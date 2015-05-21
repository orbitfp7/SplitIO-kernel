#if 1 /* patchouli vrio-blk-module */
/*
 * vRIO-block server in host kernel.
 */
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/vhost.h>
#include <linux/virtio_blk.h>
#include <linux/mutex.h>
#include <linux/file.h>
#include <linux/kthread.h>
#include <linux/blkdev.h>
#include <linux/llist.h>

//#define TRACE_LEVEL 3
#include <linux/vrio/trace.h>
#include <linux/vrio/generic.h>
#include <linux/vrio/utils.h>
#include <linux/vrio/vrio.h>

TRACE_ALL;

#include <linux/vrio/cqueue.h>
#include <linux/vrio/lmempool.h>

#define SECTOR_SHIFT  9
#define SECTOR_SIZE   (1 << SECTOR_SHIFT)
#define SECTOR_MASK   (~(SECTOR_SIZE-1))

static int debug_drop_response = 0;
module_param(debug_drop_response, int, S_IWUSR | S_IRUGO);

static int debug_recv_zero_copy = 1;
module_param(debug_recv_zero_copy, int, S_IWUSR | S_IRUGO);

static int debug_send_zero_copy = 1;
module_param(debug_send_zero_copy, int, S_IWUSR | S_IRUGO);

static int debug_batch_responses = 0;
module_param(debug_batch_responses, int, S_IWUSR | S_IRUGO);

static int debug_batch_max_size = 131072;
module_param(debug_batch_max_size, int, S_IWUSR | S_IRUGO);

static int num_outstanding_reqs = 128;
module_param(num_outstanding_reqs, int, S_IRUGO);

static DEFINE_IDA(vhost_blk_index_ida);

struct list_head devices_list;

#define NR_INLINE 1024

enum {
    VHOST_BLK_VQ_REQ = 0,
    VHOST_BLK_VQ_MAX = 1,
};

struct vhost_blk_req {
    struct bio *inline_bio[NR_INLINE];

    struct llist_node llnode;

    struct vhost_blk *blk;
    struct gsocket *gsocket;

    struct giovec *giovec;
    struct iovec iov[UIO_MAXIOV];
    int iov_nr;

    struct vrio_header *vhdr;

    char *in_buff;
    char *out_buff;
    char __in_buff[4096 * (256 + 4)];

    struct bio **bio;
    atomic_t bio_nr;

    /* Used to coalesce blk responses */
    struct iovec c_iov[UIO_MAXIOV];
    int    iov_len;
    int    response_size;
#if TRACE_DEBUG
    int    iov_pages;
#endif
    struct iovec a_iov[UIO_MAXIOV];
    int    a_iov_len;

    struct llist_node *c_llnode;
    struct skb_frag_destructor destroy;

    struct iovec status[1];

    sector_t sector;
    int write;
    u16 head;
    long len;
};

struct vhost_device {
    struct list_head link;

    uint device_uid;
    void *priv;

    struct file *file;
};

struct vhost_blk {
    /* this member must be first */
    struct giocore giocore;
    struct vhost_device *vdev;
    struct lmempool lmempool;
    struct llist_head llhead;
//    atomic_t host_work_posted;
    struct gwork_struct host_kick_work;
    u16 reqs_nr;
    int index;

#if TRACE_DEBUG
    int stat_total_reqs;
    atomic_t stat_outstanding_reqs;
    int stat_max_outstanding_reqs;
    int stat_max_batched_responses;
    int stat_max_response_size;
#endif
};

#if TRACE_DEBUG
#define ns_to_us(x) (x >> 10)

static inline u64 get_us_clock(void)
{
    return ns_to_us(sched_clock());
}
#endif

static __always_inline int iov_num_pages(struct iovec *iov)
{
    return (PAGE_ALIGN((unsigned long)iov->iov_base + iov->iov_len) -
           ((unsigned long)iov->iov_base & PAGE_MASK)) >> PAGE_SHIFT;
}

static __always_inline int vhost_blk_set_status(struct vhost_blk_req *req, u8 status)
{
    int ret;
    ret = memcpy_toiovecend(req->status, &status, 0, sizeof(status));

    if (ret) {
        etrace("Failed to write status");
        return -EFAULT;
    }

    return 0;
}

static __always_inline struct vhost_blk_req *vhost_alloc_req(struct vhost_blk *blk) {
    struct vhost_blk_req *req;

    req = lmempool_alloc(&blk->lmempool);
    if (!req) {
        etrace("mempool_alloc failed");
        return NULL;
    }

    req->iov_len = 0;
    req->response_size = 0;
#if TRACE_DEBUG
    req->iov_pages = 0;
#endif

#if TRACE_DEBUG
    blk->stat_total_reqs++;
    atomic_inc(&blk->stat_outstanding_reqs);
    blk->stat_max_outstanding_reqs = max(blk->stat_max_outstanding_reqs, 
                                         atomic_read(&blk->stat_outstanding_reqs));
#endif

    req->blk = blk;
    return req;
}
       
static __always_inline void vhost_free_req(struct vhost_blk_req *req) {
    struct vhost_blk *blk = req->blk;
    trace("vhost_free_req 1");
    if (req->giovec)
        gfree_packet(req->gsocket, req->giovec);
    trace("vhost_free_req 2");
    lmempool_free(&blk->lmempool, req);
    trace("vhost_free_req 3");

#if TRACE_DEBUG
    atomic_dec(&blk->stat_outstanding_reqs);
#endif
}

static __always_inline void vhost_add_buf(struct vhost_blk_req *req) {
    struct iovec iov[2];
    int iov_len = 2;
    int ret;

    ntrace("vhost_add_buf");
    req->vhdr->out_len = req->vhdr->in_len;
    req->vhdr->in_len = 0;
    trace("vhost_add_buf %d", req->vhdr->out_len);

    iov[0].iov_base = req->vhdr;
    iov[0].iov_len = sizeof(struct vrio_header);

    iov[1].iov_base = req->in_buff;
    iov[1].iov_len = req->vhdr->out_len;
    
    ret = gsend_iov(req->gsocket, iov, iov_len);
    trace("gsend_iov: %d", ret);
    atrace(ret <= 0);
}

static __always_inline void vrio_add_used_and_signal(struct vhost_blk_req *req) {
    trace("vrio_add_used_and_signal");
    vhost_add_buf(req);
    trace("vrio_add_used_and_signal 2");
    vhost_free_req(req);
    trace("vrio_add_used_and_signal 3");
}

static __always_inline void vrio_discard_req(struct vhost_blk_req *req) {
    vhost_free_req(req);
}

static void vhost_blk_req_done(struct bio *bio, int err)
{
    struct vhost_blk_req *req = bio->bi_private;
    struct vhost_blk *blk = req->blk;    
    bool ret;

    if (err)
        req->len = err;

    if (atomic_dec_and_test(&req->bio_nr)) {
        llist_add(&req->llnode, &blk->llhead);

        ret = queue_gwork(req->gsocket, &blk->host_kick_work);
        atrace(ret == false);
    }

    bio_put(bio);
}

static __always_inline struct page *vaddr_to_page(void *vaddr) 
{
    if (is_vmalloc_addr(vaddr)) {
        trace("is_vmalloc_addr: %lp", vaddr);
        return vmalloc_to_page(vaddr);
    } else if (virt_addr_valid(vaddr)) {
        trace("virt_addr_valid: %lp", vaddr);
        return virt_to_page(vaddr);
    } else {
        etrace("Unknown address type (%lp)", vaddr);
        return NULL;
    }
}

static int vhost_blk_bio_make(struct vhost_blk_req *req,
                  struct block_device *bdev)
{
    int pages_nr_total, i, j; //, ret;
    struct iovec *iov = req->iov;
    int iov_nr = req->iov_nr;
//    struct page **pages, 
    struct page *page;
    struct bio *bio = NULL;
    int bio_nr = 0;
//    void *buf;

    trace("vhost_blk_bio_make");

    pages_nr_total = 0;
    for (i = 0; i < iov_nr; i++)
        pages_nr_total += iov_num_pages(&iov[i]);
//    ntrace("pages_nr_total: %d", pages_nr_total);

    req->bio = req->inline_bio;

    if (unlikely(req->write == WRITE_FLUSH)) {
        trace("WRITE_FLUSH");
//        req->use_inline = true;
//        req->pl = NULL;
//        req->bio = req->inline_bio;

        bio = bio_alloc(GFP_KERNEL, 1);
        if (!bio) {
            etrace("bio_alloc failed");
            return -ENOMEM;
        }

        bio->bi_sector  = req->sector;
        bio->bi_bdev    = bdev;
        bio->bi_private = req;
        bio->bi_end_io  = vhost_blk_req_done;
        req->bio[bio_nr++] = bio;

        goto out;
    }

    atrace(pages_nr_total > NR_INLINE, goto fail);
/*
    if (pages_nr_total > NR_INLINE) {
        int pl_len, page_len, bio_len;

        req->use_inline = false;
        pl_len = iov_nr * sizeof(req->pl[0]);
        page_len = pages_nr_total * sizeof(struct page *);
        bio_len = pages_nr_total * sizeof(struct bio *);

        buf = kmalloc(pl_len + page_len + bio_len, GFP_KERNEL);
        if (!buf)
            return -ENOMEM;

        req->pl = buf;
        pages = buf + pl_len;
        req->bio = buf + pl_len + page_len;
    } else {
        req->use_inline = true;
        req->pl = req->inline_pl;
        pages = req->inline_page;
        req->bio = req->inline_bio;
    }
*/
//        req->use_inline = true;
//        req->pl = req->inline_pl;
//        pages = req->inline_page;
        

    for (req->iov_nr = i = 0; i < iov_nr; i++) {
        unsigned long iov_base, iov_len;
        int pages_nr = iov_num_pages(&iov[i]);
        trace("pages_nr: %d", pages_nr);
//        struct req_page_list *pl;

        iov_base = (unsigned long)iov[i].iov_base;
        iov_len  = (unsigned long)iov[i].iov_len;

        trace("iov_size: %d", iov_len);
        trace("iov_base(%d/%p): %.*b", i, iov_base, iov_len, iov_base);

        /* TODO: Limit the total number of pages pinned */
//        ret = get_user_pages_fast(iov_base, pages_nr,
//                      !req->write, pages);
        /* No pages were pinned */
//        if (ret < 0)
//            goto fail;

        req->iov_nr++;
//        pl = &req->pl[i];
//        pl->pages_nr = ret;
//        pl->pages = pages;

        /* Less pages pinned than wanted */
//        if (ret != pages_nr)
//            goto fail;

        for (j = 0; j < pages_nr; j++) {
            unsigned int off, len;
            //page = pages[j];
//            page = vmalloc_to_page((void *)iov_base);
//            atrace(page == NULL, goto fail);

            off = iov_base & ~PAGE_MASK;
            len = PAGE_SIZE - off;
            if (len > iov_len)
                len = iov_len;

            page = vaddr_to_page((void *)((ulong)iov_base & PAGE_MASK));
            atrace(page == NULL, goto fail);

            trace("j: %d, pages_nr: %d, off: %d, len: %d, iov_len: %d", j, pages_nr, off, len, iov_len);

            while (!bio || bio_add_page(bio, page, len, off) <= 0) {
                bio = bio_alloc(GFP_KERNEL, pages_nr_total);
                if (!bio)
                    goto fail;
                bio->bi_sector  = req->sector;
                bio->bi_bdev    = bdev;
                bio->bi_private = req;
                bio->bi_end_io  = vhost_blk_req_done;
                req->bio[bio_nr++] = bio;
            }

            req->sector += len >> 9;
            iov_base    += len;
            iov_len     -= len;
        }

//        pages += pages_nr;
    }

out:
//1    ntrace("bio_nr: %d, pages_nr_total: %d", bio_nr, pages_nr_total);
    trace("vhost_blk_bio_make succ");
    atomic_set(&req->bio_nr, bio_nr);
    return 0;

fail:
    trace("vhost_blk_bio_make fail");
    for (i = 0; i < bio_nr; i++)
        bio_put(req->bio[i]);
//    vhost_blk_req_unmap(req);
    return -ENOMEM;
}

#if 1

static __always_inline int vhost_bio_add_page(struct       vhost_blk_req *req,
                                              struct       block_device *bdev,
                                              unsigned int nr,         
                                              void         *bpage,
                                              unsigned int len,
                                              unsigned int off,
                                              int          bio_nr)
{
    sector_t sector;
    struct page *page;
    struct bio *bio;

    page = vaddr_to_page(bpage);
    atrace(page == NULL, return -EFAULT);

    sector = req->sector;
    req->sector += len >> SECTOR_SHIFT;

    if (!bio_nr || bio_add_page(req->bio[bio_nr-1], page, len, off) <= 0) {
        bio = bio_alloc(GFP_KERNEL, nr);
        if (!bio)
            return -ENOMEM;

        bio->bi_sector  = sector;
        bio->bi_bdev    = bdev;
        bio->bi_private = req;
        bio->bi_end_io  = vhost_blk_req_done;
        req->bio[bio_nr++] = bio;
        if (bio_add_page(bio, page, len, off) <= 0)
            return -ENOMEM;

        return 1;
    }

    return 0;
}

static int vhost_blk_bio_make_aligned(struct vhost_blk_req *req,
                                      struct block_device *bdev,
                                      struct iovec *iov,
                                      size_t iov_len,
                                      size_t out_len,
                                      size_t in_len)
{
    size_t off, plen, alen;
    char *aligned_buffer;
    int pages_nr_total;
    int bio_nr = 0, ret, i;
#if TRACE_DEBUG
    int number_of_copied_bytes = 0;
    int org_out_len = out_len;
    int real_pages_nr_total = 0;
#endif

    trace("iov_len: %d, SECTOR_SIZE: %d", iov_len, SECTOR_SIZE);
    req->bio = req->inline_bio;
    pages_nr_total = ((out_len + in_len + PAGE_SIZE) >> PAGE_SHIFT);
    pages_nr_total = (pages_nr_total << 1) + (pages_nr_total >> 1);

    aligned_buffer = req->out_buff;
    trace("aligned_buffer: %lp", aligned_buffer);
    atrace(out_len & ~SECTOR_MASK, goto fail);

    if (unlikely(req->write == WRITE_FLUSH)) {
        struct bio *bio = bio_alloc(GFP_KERNEL, 1);
        trace("WRITE_FLUSH");

        if (!bio) {
            etrace("bio_alloc failed");
            return -ENOMEM;
        }

        bio->bi_sector  = req->sector;
        bio->bi_bdev    = bdev;
        bio->bi_private = req;
        bio->bi_end_io  = vhost_blk_req_done;
        req->bio[bio_nr++] = bio;

        goto out;
    }

    while (out_len) {
            if (unlikely(iov->iov_len == 0)) {
                --iov_len;
                ++iov;
                continue;
            }
            
            off = (ulong)iov->iov_base & ~PAGE_MASK;
            plen = PAGE_SIZE - off;
            if (plen > iov->iov_len)
                plen = iov->iov_len;
            alen = plen & SECTOR_MASK;
            trace("off: %d, plen: %d, alen: %d", off, plen, alen);
            trace("iov->iov_len: %d", iov->iov_len);

            if (alen) {
                ret = vhost_bio_add_page(req, bdev, pages_nr_total, iov->iov_base, alen, off, bio_nr);
                atrace(ret < 0, etrace("pages_nr_total: %d, bio_nr: %d", pages_nr_total, bio_nr); goto fail);
                bio_nr += ret;
#if TRACE_DEBUG
                real_pages_nr_total++;
#endif                
                out_len -= alen;
                iov->iov_base += alen;
                iov->iov_len -= alen;
            } 
  
            if (plen & ~SECTOR_MASK) {
                ret = memcpy_fromiovecend_skip(aligned_buffer, iov, iov_len, SECTOR_SIZE);
                atrace(ret != 0, return false);

                off = (ulong)aligned_buffer & ~PAGE_MASK;
                ret = vhost_bio_add_page(req, bdev, pages_nr_total, aligned_buffer, SECTOR_SIZE, off, bio_nr);
                atrace(ret < 0, etrace("pages_nr_total: %d, bio_nr: %d", pages_nr_total, bio_nr); goto fail);
                bio_nr += ret;
#if TRACE_DEBUG
                real_pages_nr_total++;
#endif                
                out_len -= SECTOR_SIZE;
                aligned_buffer += SECTOR_SIZE;

#if TRACE_DEBUG
                number_of_copied_bytes += SECTOR_SIZE;
#endif                
            }
    }

    atrace(in_len & ~SECTOR_MASK, goto fail);

    aligned_buffer = req->in_buff;
    trace("req->in_buff: %lp", aligned_buffer);
    while (in_len) {
        off = (ulong)aligned_buffer & ~PAGE_MASK;
        plen = PAGE_SIZE - off;
        if (plen > in_len)
            plen = in_len;

        ret = vhost_bio_add_page(req, bdev, pages_nr_total, aligned_buffer, plen, off, bio_nr);
        atrace(ret < 0, etrace("pages_nr_total: %d, bio_nr: %d", pages_nr_total, bio_nr); goto fail);
        bio_nr += ret;
#if TRACE_DEBUG
        real_pages_nr_total++;
#endif                

        in_len -= plen;
        aligned_buffer += plen;
    }

out:
    trace("vhost_blk_bio_make_aligned succ");
    atomic_set(&req->bio_nr, bio_nr);
    return 0;

fail:
    trace("vhost_blk_bio_make_aligned fail");
    for (i = 0; i < bio_nr; i++)
        bio_put(req->bio[i]);
    return -ENOMEM;
}
#endif

static __always_inline void vhost_blk_bio_send(struct vhost_blk_req *req)
{
    struct blk_plug plug;
    int i, bio_nr;

    bio_nr = atomic_read(&req->bio_nr);
    blk_start_plug(&plug);
    for (i = 0; i < bio_nr; i++)
        submit_bio(req->write, req->bio[i]);
    blk_finish_plug(&plug);
}

static int vhost_blk_req_submit(struct vhost_blk_req *req, struct file *file)
{
    struct inode *inode = file->f_mapping->host;
    struct block_device *bdev = inode->i_bdev;
    int ret;

    if (debug_recv_zero_copy) {
        ret = vhost_blk_bio_make_aligned(req, bdev, req->giovec->iov, req->giovec->iov_len,
                                         req->vhdr->out_len, req->vhdr->in_len-1);
        if (ret < 0)
            return ret;
    } else {
        ret = vhost_blk_bio_make(req, bdev);
        if (ret < 0)
            return ret;
    }

    vhost_blk_bio_send(req);
/*
    spin_lock(&req->blk->flush_lock);
    req->during_flush = req->blk->during_flush;
    atomic_inc(&req->blk->req_inflight[req->during_flush]);
    spin_unlock(&req->blk->flush_lock);
*/
    return ret;
}

static int vhost_blk_req_handle(struct vhost_blk_req *req, 
                                struct virtio_blk_outhdr *hdr,
                                struct file *file)
{
    int ret;
    u8 status;
    
    trace("vhost_blk_req_handle");    
    req->sector	= hdr->sector;
    trace("req->sector: %lu", req->sector);

    switch (hdr->type) {
    case VIRTIO_BLK_T_OUT:
        trace("VIRTIO_BLK_T_OUT");
        req->write = WRITE;
        ret = vhost_blk_req_submit(req, file);
        break;
    case VIRTIO_BLK_T_IN:
        trace("VIRTIO_BLK_T_IN");
        req->write = READ;
        ret = vhost_blk_req_submit(req, file);
        break;
    case VIRTIO_BLK_T_FLUSH:
        trace("VIRTIO_BLK_T_FLUSH");
        req->write = WRITE_FLUSH;
        ret = vhost_blk_req_submit(req, file);
        break;
/*    
    case VIRTIO_BLK_T_GET_ID:
        ntrace("VIRTIO_BLK_T_GET_ID");
        ret = snprintf(id, VIRTIO_BLK_ID_BYTES,
                   "vhost-blk%d", blk->index);
        if (ret < 0)
            break;
        len = ret;
        ret = memcpy_toiovecend(req->iov, id, 0, len);
        status = ret < 0 ? VIRTIO_BLK_S_IOERR : VIRTIO_BLK_S_OK;
        ret = vhost_blk_set_status(req, status);
        if (ret)
            break;

        //transmit_packet_(req);
        free_request(req);

        //vrio_add_used_and_signal(&blk->dev, vq);
        //--vhost_add_used_and_signal(&blk->dev, vq, head, len);
        break;
*/
  
    default:
        etrace("Unsupported request type %d", hdr->type);
        status = VIRTIO_BLK_S_UNSUPP;
        ret = vhost_blk_set_status(req, status);
        if (ret) 
            break;
        
        vrio_add_used_and_signal(req);
        break;
    }

    return ret;
}

/* Guest kick us for I/O submit */
static void vhost_blk_handle_guest_kick(struct gsocket *gsocket, struct vhost_blk *blk, 
                                        struct vrio_header *vhdr, struct giovec* giovec)
{
    struct virtio_blk_outhdr hdr;
    int ret, len;
    struct file *f;
    struct vhost_blk_req *req;
    u8 status;
    char *data;

    trace("vhost_blk_handle_guest_kick");

    f = blk->vdev->file; 
    if (!f) {
        etrace("file is NULL");
        return;
    }

    req = vhost_alloc_req(blk);
    if (!req) {
        etrace("vhost_alloc_req failed");
        return; 
    }
    
    req->gsocket = gsocket;
    req->giovec = giovec;
    req->vhdr = vhdr;

    ret = memcpy_fromiovecend_skip((unsigned char *)&hdr, giovec->iov, giovec->iov_len, sizeof(hdr));
    if (unlikely(ret)) {
        etrace("Failed to get block header!");
        vrio_discard_req(req);
        return;
    }
    
    vhdr->out_len -= sizeof(hdr);
    req->len = vhdr->out_len + vhdr->in_len - sizeof(status);

    req->out_buff = (void *)((ulong)(req->__in_buff + 2 * PAGE_SIZE) & PAGE_MASK);
    req->in_buff = req->out_buff + (vhdr->out_len & PAGE_MASK) + PAGE_SIZE /* * 2 */ + SECTOR_SIZE;

    if (debug_recv_zero_copy) {
        req->status[0].iov_len = 1;
        req->status[0].iov_base = req->in_buff + vhdr->in_len - sizeof(status);
    } else {
        data = (char *)((ulong)(req->__in_buff + 2*PAGE_SIZE) & PAGE_MASK);
        req->a_iov_len = 0;

        len = vhdr->out_len;
        if (len > 0) {
            ret = memcpy_fromiovecend_skip((unsigned char *)data, giovec->iov, giovec->iov_len, len);
            if (ret) {
                etrace("Failed to copy out data!");
                vrio_discard_req(req);
                return;
            }
        
            req->a_iov[0].iov_base = data;
            req->a_iov[0].iov_len  = len;
            req->a_iov_len = 1;

            data = (char *)((ulong)(data + len + PAGE_SIZE) & PAGE_MASK);
        } 
      
        req->in_buff = data;
        req->a_iov[req->a_iov_len].iov_base = data;
        req->a_iov[req->a_iov_len].iov_len  = vhdr->in_len; 
        req->a_iov_len++;

        trace("req->len: %d", req->len);
        req->iov_nr = move_iovec(req->a_iov, req->iov, req->len, req->a_iov_len);
        trace("req->iov_nr: %d", req->iov_nr);
        move_iovec(req->a_iov, req->status, sizeof(status), req->a_iov_len);

    }

    if (vhost_blk_req_handle(req, &hdr, f) < 0) {
        etrace("vhost_blk_req_handle failed");
        vrio_discard_req(req);
    }
}

static __always_inline void free_batch_req(struct vhost_blk_req *batch_req);

struct skb_frag_data {
    struct vhost_blk_req *req;
};

int destroy_skb_frag(struct skb_frag_destructor *destructor) {
    struct skb_frag_data *data = (struct skb_frag_data *)destructor->data;

    trace("destroy_skb_frag");
    free_batch_req(data->req);
    return 0;
}

static __always_inline void zerocopy_tx(struct vhost_blk_req *batch_req, struct iovec *iov, size_t iov_len)
{            
    struct skb_frag_data *data;
    struct skb_frag_destructor *destroy = &batch_req->destroy;
    int ret;

    init_frag_destructor(destroy, destroy_skb_frag);
    data = FRAG_DESTROY_DATA(destroy, struct skb_frag_data *);
    data->req = batch_req;

    // atrace(batch_req->response_size > 63 * 1024);            
    // atrace(batch_req->iov_pages > MAX_SKB_FRAGS);

    //1
    trace("response_size: %d, iov_len: %d, iov_pages: %d", 
        batch_req->response_size, batch_req->iov_len, batch_req->iov_pages);

    if (debug_send_zero_copy) {
        ret = zgsend_iov(batch_req->gsocket, iov, iov_len, destroy);
        atrace(ret <= 0);
    } else {
        ret = gsend_iov(batch_req->gsocket, iov, iov_len);
        atrace(ret <= 0);
        destroy->destructor(destroy);
    }


//    if (!__zerocopy_tx(batch_req, batch_req->c_iov, batch_req->iov_len, batch_req->response_size)) {    
//        trace("response batch fits into inline data");        
//        free_batch_req(batch_req);            
//    }

    //    return __zerocopy_tx(struct vhost_blk_req *req, struct iovec *iov, size_t iov_len, size_t len);
}

static __always_inline void free_batch_req(struct vhost_blk_req *batch_req) 
{
    struct llist_node *llnode;
    struct vhost_blk_req *req;

    trace("free_batch_req");

    llnode = batch_req->c_llnode;
    while (llnode) {
        req = llist_entry(llnode, struct vhost_blk_req, llnode);
        llnode = llist_next(llnode);
  
        vrio_discard_req(req);
    }
}

static __always_inline int __map_blk_response(struct vhost_blk_req *new_req, struct iovec *iov) {
    struct vrio_header *vhdr;

#if TRACE_DEBUG
    if (debug_drop_response > 0) {
        debug_drop_response--;
        return 0;
    }
#endif

    vhdr = (struct vrio_header *)(new_req->in_buff - sizeof(struct vrio_header));
    vhdr->out_len = new_req->vhdr->in_len;
    vhdr->in_len = 0;

    trace("map_blk_response %d", vhdr->out_len);

    vhdr->host_priv  = new_req->vhdr->host_priv;
    vhdr->guest_priv = new_req->vhdr->guest_priv;
    vhdr->id         = new_req->vhdr->id;

//    iov[0].iov_base = req->vhdr;
//    iov[0].iov_len = sizeof(struct vrio_header);

//    iov[1].iov_base = req->in_buff;
//    iov[1].iov_len = req->vhdr->out_len;

    iov[0].iov_base = vhdr;
    iov[0].iov_len = vhdr->out_len + sizeof(struct vrio_header);

    return 1;
}

#if TRACE_DEBUG
static __always_inline int iov_pages(struct iovec *iov, int iov_len) {
    int i, pages = 0;

    for (i=0; i<iov_len; i++) {
        pages += iov_num_pages(&iov[i]);
    }

    return pages;
}
#endif

static __always_inline bool map_blk_response(struct vhost_blk_req *batch_req, struct vhost_blk_req *new_req) {
    struct iovec *iov = batch_req->c_iov + batch_req->iov_len;
    int iov_len, response_size;
#if TRACE_DEBUG
    int _iov_pages;
#endif

    iov_len = __map_blk_response(new_req, iov);    
#if TRACE_DEBUG
    _iov_pages = iov_pages(iov, iov_len);
/*
    if (batch_req->iov_pages + _iov_pages > MAX_SKB_FRAGS) {
        trace("map response failed on MAX_SKB_FRAGS: %d, %d", batch_req->iov_pages, _iov_pages);
        return false;
    }
*/    
#endif
    if (batch_req->iov_len + iov_len > UIO_MAXIOV - 100) {
        trace("map response failed on UIO_MAXIOV: %d, %d", batch_req->iov_len, iov_len);
        return false;
    }

    response_size = iov_length(iov, iov_len);
    if (batch_req->response_size + response_size > debug_batch_max_size) {
        trace("map response failed on size: %d, %d, %d", batch_req->response_size, response_size, debug_batch_max_size);
        return false;
    }
    
#if TRACE_DEBUG
    batch_req->iov_pages += _iov_pages;
#endif
    batch_req->response_size += response_size;
    batch_req->iov_len += iov_len;
    return true;
}

#if 1
/* Host kick us for I/O completion */
static void vhost_blk_handle_host_kick(struct gwork_struct *gwork)
{
    struct vhost_blk_req *req, *batch_req;
    struct llist_node *llnode, *prev_llnode = NULL, *batch_llnode;
    struct vhost_blk *blk;
    int ret;
#if TRACE_DEBUG
    int batched_responses = 0;
#endif
    u8 status;

    trace("vhost_blk_handle_host_kick");
    blk = container_of(gwork, struct vhost_blk, host_kick_work);
    llnode = llist_del_all(&blk->llhead);
    
    if (llnode == NULL)
        return;

    batch_llnode = llnode;
    batch_req = llist_entry(batch_llnode, struct vhost_blk_req, llnode);
    batch_req->c_llnode = batch_llnode;
    
    trace("llnode: %p", llnode);
    while (llnode) {
        req = llist_entry(llnode, struct vhost_blk_req, llnode);

        status = req->len >= 0 ?  VIRTIO_BLK_S_OK : VIRTIO_BLK_S_IOERR;
        trace("status: %d (OK: %d) (%d)", status, VIRTIO_BLK_S_OK, req->len);
        ret = vhost_blk_set_status(req, status);
        /* this should never happen */
        if (unlikely(ret)) {
            etrace("vhost_blk_set_status failed");
            vrio_discard_req(req);
            continue;
        }

        if (debug_batch_responses) {
            if (map_blk_response(batch_req, req)) {
#if TRACE_DEBUG
                batched_responses++;
#endif
            } else {
                trace("map_blk_response failed to add new response, sending existing response");
                atrace(prev_llnode == NULL);
                prev_llnode->next = NULL;
                batch_llnode = llnode;

                zerocopy_tx(batch_req, batch_req->c_iov, batch_req->iov_len);

                batch_req = llist_entry(batch_llnode, struct vhost_blk_req, llnode);
                batch_req->c_llnode = batch_llnode;
                map_blk_response(batch_req, batch_req);

#if TRACE_DEBUG    
                //1
                trace("batch size: %d", batched_responses);

                blk->stat_max_batched_responses = max(blk->stat_max_batched_responses, 
                    batched_responses);
                blk->stat_max_response_size = max(blk->stat_max_response_size, 
                    batch_req->response_size);

                batched_responses = 0;
#endif
            }

            prev_llnode = llnode;
            llnode = llist_next(llnode);
        } else {
            batch_req = req;
            batch_req->c_llnode = llnode;
            map_blk_response(batch_req, req);

            llnode = llist_next(llnode);
            batch_req->c_llnode->next = NULL;

#if TRACE_DEBUG          
            // batch_req->response_size = iov_length(batch_req->c_iov, batch_req->iov_len);
            blk->stat_max_response_size = max(blk->stat_max_response_size,         
                batch_req->response_size);    
#endif

            zerocopy_tx(batch_req, batch_req->c_iov, batch_req->iov_len);            
        }
    }

    if (debug_batch_responses) {
        zerocopy_tx(batch_req, batch_req->c_iov, batch_req->iov_len);

#if TRACE_DEBUG    
        //1
        trace("batch size: %d", batched_responses);

        blk->stat_max_batched_responses = max(blk->stat_max_batched_responses, 
                                              batched_responses);
        blk->stat_max_response_size = max(blk->stat_max_response_size, 
                                          batch_req->response_size);
#endif
    }
}
#endif

static int vhost_blk_setup(struct vhost_blk *blk)
{
    if (init_lmempool(&blk->lmempool, num_outstanding_reqs, sizeof(struct vhost_blk_req)) == false) {
        etrace("init_mempool failed");
        return -ENOMEM;
    }

    return 0;
}

static int vhost_blk_open(struct vhost_device *vdev) 
{
    struct vhost_blk *blk;
    int ret;

    vdev->priv = blk = kzalloc(sizeof(*blk), GFP_KERNEL);
    if (!blk) {
        etrace("kzalloc failed");
        ret = -ENOMEM;
        goto out;
    }

    ret = ida_simple_get(&vhost_blk_index_ida, 0, 0, GFP_KERNEL);
    if (ret < 0) {
        etrace("ida_simple_get failed");
        goto out_dev;
    }
    blk->index = ret;
    blk->vdev = vdev;

    init_gwork_func(&blk->host_kick_work, vhost_blk_handle_host_kick);
    set_cq_flag(&blk->host_kick_work.clink, CQ_FLAG_NO_MARK);
    
//    atomic_set(&blk->host_work_posted, 0);
/*
    blk->vq.handle_kick = vhost_blk_handle_guest_kick;
    atomic_set(&blk->req_inflight[0], 0);
    atomic_set(&blk->req_inflight[1], 0);
    blk->during_flush = 0;
    spin_lock_init(&blk->flush_lock);
    init_waitqueue_head(&blk->flush_wait);
*/
    return 0;

out_dev:
    kfree(blk);
out:
    return ret;
}

static int vhost_blk_release(struct vhost_device *vdev)
{
    struct vhost_blk *blk = vdev->priv;

    ida_simple_remove(&vhost_blk_index_ida, blk->index);
//    vhost_blk_flush(blk);
    if (vdev->file) {
        file_close(vdev->file);
        vdev->file = NULL;
    }

    done_lmempool(&blk->lmempool);
    kfree(blk);
    return 0;
}

static long vhost_blk_set_backend(struct vhost_blk *blk, struct file* file) 
{
    struct inode *inode;
    int ret;

    if (IS_ERR(file)) {
        ret = PTR_ERR(file);
        goto fail;
    }

    /* Only raw block device is supported for now */
    inode = file->f_mapping->host;
    if (!S_ISBLK(inode->i_mode)) {
        ret = -EFAULT;
        goto fail;
    }

    blk->vdev->file = file;
    return 0;

fail:
    return ret;
}

static struct vhost_device *__vhost_blk_open(struct ioctl_create *create) {
    int res;
    struct vhost_device *vdev;

    vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);

    res = vhost_blk_open(vdev);
    trace("vhost_blk_open: %d", res);
    if (res != 0) {
        etrace("vhost_blk_open failed");
        goto free_vdev;
    }

    list_add(&vdev->link, &devices_list);
    return vdev;

free_vdev:
    kfree(vdev);   
    return NULL;
}

static void __vhost_blk_release(struct vhost_device *vdev) {
    trace("__vhost_blk_release");
    list_del(&vdev->link);            
    vhost_blk_release(vdev);
    kfree(vdev);
}

static int __vhost_blk_create(struct ioctl_create *create) {
    struct vhost_device *vdev;
    struct vhost_blk *vblk;
    struct file* file;
    int res;

    trace("opening device_path: %s", create->device_path);
    file = file_open(create->device_path, O_RDWR | O_DIRECT , 777); // 0644);
    if (!file) {
        etrace("file_open failed");
        res = -EFAULT;
        goto out;
    }

    vdev = __vhost_blk_open(create);
    if (!vdev) {
        etrace("vhost_blk_open");
        res = -EFAULT;
        goto out_file;
    }

    vblk = (struct vhost_blk *)vdev->priv;

    res = vhost_blk_setup(vblk);
    if (res) {
        etrace("vhost_blk_setup: %d", res);
        goto out_blk;
    }
    
    res = vhost_blk_set_backend(vblk, file); 
    if (res) {
        etrace("vhost_blk_set_backend: %d", res);
        goto out_blk;
    }

    create->host_priv = (ulong)vblk;
    return 0;

out_blk:
    __vhost_blk_release(vdev);
out_file:
    file_close(file);
out:
    return res;
}

static void remove_blk_device_by_index(int index) {
    struct vhost_device *vdev;

    trace("device_id: %d", index);
    list_entry_at_index(index, vdev, &devices_list, link);
    if (vdev == NULL) {
        etrace("vhost device with id %d is no where to be found", index);
        return;
    }

    __vhost_blk_release(vdev);
}

static void remove_blk_device_by_uid(uint device_uid) {
    struct vhost_device *vdev;

    list_for_each_entry(vdev, &devices_list, link) { 
        if (vdev->device_uid == device_uid) {
            __vhost_blk_release(vdev);
            return;
        }
    }
}

static void remove_all_blk_devices(void) {
    struct vhost_device *vdev, *n;

    list_for_each_entry_safe(vdev, n, &devices_list, link) { 
        __vhost_blk_release(vdev);
    }
}

#if TRACE_ENABLED
int llist_size(struct llist_head *head) {
    int i=0;
    struct llist_node *pos, *_head = (struct llist_node *)head;

    llist_for_each(pos, _head) {
        i++;
    }
    i--;

    return i;
}
void sanity_check(void) {
    struct vhost_device *vdev;
    struct vhost_blk *blk;
    mtrace("sanity_check");

    list_for_each_entry(vdev, &devices_list, link) { 
        blk = vdev->priv;
#if TRACE_DEBUG
        mtrace("stat_total_reqs: %d", blk->stat_total_reqs);
        mtrace("stat_outstanding_reqs: %d", atomic_read(&blk->stat_outstanding_reqs));
        mtrace("stat_max_outstanding_reqs: %d", blk->stat_max_outstanding_reqs);
        mtrace("stat_max_batched_responses: %d", blk->stat_max_batched_responses);
        mtrace("stat_max_response_size: %d", blk->stat_max_response_size);
#endif
        mtrace("lmempool->free_list: %d", llist_size(&blk->lmempool.free_list));
    }
}
#endif

long ioctl(struct ioctl_param *local_param) {
    long res = 0;

    switch (local_param->cmd) {
        case VRIO_IOCTL_CREATE_BLK: {        
            mtrace("ioctl VRIO_IOCTL_CREATE_BLK");
            res = __vhost_blk_create(&local_param->x.create);
            break;
        }

        case VRIO_IOCTL_REMOVE_DEV: {        
            mtrace("ioctl VRIO_IOCTL_REMOVE_DEV");
            if (local_param->x.remove.device_id == -1) 
                remove_all_blk_devices();
            else 
                remove_blk_device_by_index(local_param->x.remove.device_id);
            break;
        }
        case VRIO_IOCTL_SANITY_CHECK: {
            mtrace("ioctl VRIO_IOCTL_SANITY_CHECK");
#if TRACE_ENABLED
            sanity_check();
#endif
            break;
        }
        
        default: {
            etrace("ioctl: no such command");            
            break;
        }
    }

    return res;
}

void handler(ulong param1, ulong param2) {
    struct vrio_header *vhdr;
    struct vhost_blk *vblk;
    struct gsocket *gsocket = (struct gsocket *)param1;
    struct giovec *giovec = (struct giovec *)param2;

#if TRACE_DEBUG
    static int times = 0;
    int len = iov_length(giovec->iov, giovec->iov_len);
    trace("handler (times: %d, total_size: %d)", times, len);
    times++;
#endif

    atrace(giovec->iov[0].iov_len < VRIO_HEADER_SIZE, return);

    vhdr = (struct vrio_header *)giovec->iov[0].iov_base;
    vblk = (struct vhost_blk *)vhdr->host_priv;

    giovec->iov[0].iov_base += VRIO_HEADER_SIZE;
    giovec->iov[0].iov_len -= VRIO_HEADER_SIZE;

    trace("vhdr->out_len: %d, vhdr->in_len: %d", vhdr->out_len, vhdr->in_len);
    vhost_blk_handle_guest_kick(gsocket ,vblk, vhdr, giovec);
}

static struct vdev vdev_blk = {
    .name = "blk",
    .handler = handler,
    .ioctl = ioctl,
    .run_from_softirq_context = false,
};

static int vhost_blk_init(void)
{
    bool res;
    
    mtrace("module hblk up");
    INIT_LIST_HEAD(&devices_list);

    res = vhost_register(&vdev_blk);
    trace("vhost_register: %d", res);
    if (!res) {
        etrace("vhost_register failed");
        return -EPERM;
    }

    return 0;
}

static void vhost_blk_exit(void)
{
    mtrace("module hblk down");
    remove_all_blk_devices();
    vhost_unregister(&vdev_blk);
}

module_init(vhost_blk_init);
module_exit(vhost_blk_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Asias He");
MODULE_AUTHOR("Yossi Kuperman");
MODULE_DESCRIPTION("Host kernel accelerator for vRIO-block");
#endif
