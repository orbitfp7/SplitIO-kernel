// on block remove: close all open requests? is it possible

#if 1 /* patchouli vrio-blk-module */
#include <linux/kthread.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/virtio.h>
#include <linux/virtio_blk.h>
#include <linux/scatterlist.h>
#include <linux/string_helpers.h>
#include <scsi/scsi_cmnd.h>
#include <linux/idr.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>

//  #define TRACE_LEVEL 4

#include <linux/vrio/trace.h>
#include <linux/vrio/generic.h>
#include <linux/vrio/utils.h>
#include <linux/vrio/vrio.h>

TRACE_ALL;

#include <linux/vrio/cqueue.h>
//#include <linux/vrio/lmempool.h>
#include <linux/vrio/cmempool.h>

#define PART_BITS 4

#define REQUEST_TIMEOUT 1

#if REQUEST_TIMEOUT

#define MAX_REQ_RETRIES 4
#define MONOTONIC_UP_TIMEOUT 1
#define MIN_REQ_TIMEOUT 2e5
//#define MAX_REQ_TIMEOUT 5e6 // 5 seconds

#if TRACE_DEBUG
static int debug_drop_response = 0;
module_param(debug_drop_response, int, S_IWUSR | S_IRUGO);
#endif

static int debug_retries = 0;
module_param(debug_retries, int, S_IWUSR | S_IRUGO);
#endif

static bool use_bio = 0;
module_param(use_bio, bool, S_IRUGO);

static int num_outstanding_reqs = 128;
module_param(num_outstanding_reqs, int, S_IRUGO);

/* timeout is in micro-seconds resolution */
static int initial_request_timeout = 2e5; // 1e6; // 5e4; // 1e4;
module_param(initial_request_timeout, int, S_IWUSR | S_IRUGO);

static int major;
static DEFINE_IDA(vd_index_ida);

struct list_head devices_list;

struct virtblk_req;

struct vrio_blk {
    struct vrio_device *vdev;
    wait_queue_head_t queue_wait;

    /* The disk structure for the kernel. */
    struct gendisk *disk;
    /* Lock used by the queue */
    spinlock_t lock;
    struct cmempool cmempool;
    /* Ida index - used to track minor number allocations. */
    int index;

    unsigned int sg_elems;

#if REQUEST_TIMEOUT
#if TRACE_DEBUG
    atomic_t total_req_retries;
    int max_retries;
#endif    
    atomic_t read_req_timeout;
    atomic_t write_req_timeout;
    atomic_t request_id;
#endif 

#if TRACE_DEBUG
    int stat_total_reqs;
    atomic_t stat_outstanding_reqs;
    int stat_max_outstanding_reqs;
#endif
};

struct virtblk_req
{
    struct request *req;
    struct bio *bio;
    struct virtio_blk_outhdr out_hdr;
    struct virtio_scsi_inhdr in_hdr;
    struct vrio_blk *vblk;
    int flags;
    u8 status;

    struct gwork_struct bio_send_data_work;
    struct gwork_struct bio_send_flush_work;
    struct gwork_struct add_req_work;
#if REQUEST_TIMEOUT
    struct gwork_struct add_buf_work;
    struct gwork_struct drop_request_work;
#endif

    struct vrio_header vhdr;
    struct skb_frag_destructor destroy;

    struct cqueue_struct clink;

#if REQUEST_TIMEOUT
    int retries;
    atomic_t id;
    u64 issue_time;
    int timeout;
    struct hrtimer timer;
#endif

    unsigned int in, out;
    struct iovec iov[UIO_MAXIOV];
    /* Scatterlist: can be too big for stack. */
    struct scatterlist sg[];
};

enum {
    VBLK_IS_FLUSH		= 1,
    VBLK_REQ_FLUSH		= 2,
    VBLK_REQ_DATA		= 4,
    VBLK_REQ_FUA		= 8,
};

static void virtblk_bio_send_data_work(struct gwork_struct *gwork);
static void virtblk_bio_send_flush_work(struct gwork_struct *gwork);
static void virtblk_add_req_work(struct gwork_struct *gwork);
#if REQUEST_TIMEOUT
static void virtblk_add_buf_work(struct gwork_struct *gwork);
static void virtblk_drop_request_work(struct gwork_struct *gwork);
#endif

static __always_inline int virtblk_result(struct virtblk_req *vbr)
{
    switch (vbr->status) {
    case VIRTIO_BLK_S_OK:
        return 0;
    case VIRTIO_BLK_S_UNSUPP:
        return -ENOTTY;
    default:
        return -EIO;
    }
}

static __always_inline int vbr_read_dir(struct virtblk_req *vbr) {    
    return (vbr->out_hdr.type & (VIRTIO_BLK_T_OUT | VIRTIO_BLK_T_FLUSH)) == 0;
}

static __always_inline int vbr_flush_req(struct virtblk_req *vbr) {
    return (vbr->out_hdr.type == VIRTIO_BLK_T_FLUSH);
}

static __always_inline struct virtblk_req *virtblk_alloc_req(struct vrio_blk *vblk) {
    struct virtblk_req *vbr;

    vbr = cmempool_alloc(&vblk->cmempool);
    if (!vbr) {
#if TRACE_DEBUG
        trace("mempool_alloc failed, max_outstanding_reqs: %d", vblk->stat_max_outstanding_reqs);
#else
        trace("mempool_alloc failed");
#endif
        return NULL;
    }

#if TRACE_DEBUG
    vblk->stat_total_reqs++;
    atomic_inc(&vblk->stat_outstanding_reqs);
    vblk->stat_max_outstanding_reqs = max(vblk->stat_max_outstanding_reqs, 
                                          atomic_read(&vblk->stat_outstanding_reqs));
#endif
#if REQUEST_TIMEOUT
    vbr->retries = 0;
#endif    

    init_gwork_func(&vbr->bio_send_data_work, virtblk_bio_send_data_work);
    init_gwork_func(&vbr->bio_send_flush_work, virtblk_bio_send_flush_work);
    init_gwork_func(&vbr->add_req_work, virtblk_add_req_work);
#if REQUEST_TIMEOUT
    init_gwork_func(&vbr->add_buf_work, virtblk_add_buf_work);
    init_gwork_func(&vbr->drop_request_work, virtblk_drop_request_work);
#endif

    init_cqueue_elm(&vbr->clink);

    sg_init_table(vbr->sg, vblk->sg_elems);
    vbr->vblk = vblk;
    return vbr;
}

static __always_inline void virtblk_free_req(struct virtblk_req *vbr) {
    struct vrio_blk *vblk = vbr->vblk;

    cmempool_free(&vblk->cmempool, vbr);    
#if TRACE_DEBUG
    atomic_dec(&vblk->stat_outstanding_reqs);
#endif
}

struct skb_frag_data {
    struct gsocket *gsocket;
    struct giovec *giovec;
};

int destroy_skb_frag(struct skb_frag_destructor *destructor) {
    trace("destroy_skb_frag");
    return 0;
}

#if REQUEST_TIMEOUT
#define ns_to_us(x) ((x) >> 10)
#define us_to_ns(x) ((x) << 10)

static inline u64 get_us_clock(void)
{
    return ns_to_us(sched_clock());
}

static __always_inline int get_next_req_id(struct vrio_blk *vblk) {
    int id;
    id = atomic_inc_return(&vblk->request_id);

    /* We don't allow id to be zero */
    if (unlikely(!id))
        id = atomic_inc_return(&vblk->request_id);

    return id;
}

static __always_inline void setup_req_timer(struct vrio_blk *vblk, struct virtblk_req *vbr);
static __always_inline int get_vblk_timeout(struct virtblk_req *vbr);
#endif

static __always_inline int virtblk_add_buf(struct virtblk_req *vbr) {
    struct skb_frag_destructor *destroy = &vbr->destroy;
    struct vrio_blk *vblk = vbr->vblk;
//    struct vrio_header vhdr;
    int iov_len = 1, i, err;
    trace("virtblk_add_buf: in: %d, out: %d", vbr->in, vbr->out);

    init_frag_destructor(destroy, destroy_skb_frag);

    vbr->vhdr.host_priv = vblk->vdev->host_priv;
    vbr->vhdr.guest_priv = (ulong)vbr;
    vbr->vhdr.out_len = 0;
    vbr->vhdr.in_len = 0;

#if REQUEST_TIMEOUT
    vbr->issue_time = get_us_clock();
    vbr->vhdr.id = atomic_read(&vbr->id);
    trace("virtblk_add_buf: id: %d (blkid)", vbr->vhdr.id);
#endif

    vbr->iov[0].iov_base = &vbr->vhdr;
    vbr->iov[0].iov_len = sizeof(struct vrio_header);

    for (i=0; i<vbr->out + vbr->in ; ++i) {
        if (i < vbr->out) {
            vbr->vhdr.out_len += vbr->sg[i].length;
            vbr->iov[iov_len].iov_base = sg_virt(&vbr->sg[i]);
            vbr->iov[iov_len].iov_len = vbr->sg[i].length;
            trace("- iov_base(%d/%d/%lp): %.*b", i, vbr->sg[i].length, vbr->iov[iov_len].iov_base, vbr->iov[iov_len].iov_len, vbr->iov[iov_len].iov_base);
            iov_len++;
        } else {
            vbr->vhdr.in_len += vbr->sg[i].length;
            trace("- in iov_base(%d/%d/%lp)" , i, vbr->sg[i].length, sg_virt(&vbr->sg[i]));
        }         
    }        

    err = zgsend_iov(vblk->vdev->gsocket, vbr->iov, iov_len, destroy);
    trace("zgsend_iov: %d", err);
    atrace(err <= 0);
    return err;
}

static __always_inline void virtblk_add_req(struct virtblk_req *vbr)
{
    struct vrio_blk *vblk = vbr->vblk;

#if REQUEST_TIMEOUT
    vbr->timeout = get_vblk_timeout(vbr);
    atomic_set(&vbr->id, get_next_req_id(vblk));
    setup_req_timer(vblk, vbr);
#endif

    virtblk_add_buf(vbr);
}

#if REQUEST_TIMEOUT
static void virtblk_add_buf_work(struct gwork_struct *gwork) {
    struct virtblk_req *vbr = container_of(gwork, struct virtblk_req, add_buf_work);
    trace("virtblk_add_buf_work");

    virtblk_add_buf(vbr);
}

static __always_inline void adjust_req_timeout(struct virtblk_req *vbr) {
    struct vrio_blk *vblk = vbr->vblk;

    vbr->timeout = vbr->timeout << 1;
//    if (vbr->timeout > MAX_REQ_TIMEOUT)
//        vbr->timeout = MAX_REQ_TIMEOUT;

    if (vbr_read_dir(vbr)) {
        if (vbr->timeout > atomic_read(&vblk->read_req_timeout))
            atomic_set(&vblk->read_req_timeout, vbr->timeout);
        else 
            vbr->timeout = atomic_read(&vblk->read_req_timeout);
//        timeout = atomic_read(&vblk->read_req_timeout) * 2;
//        atomic_set(&vblk->read_req_timeout, min(timeout, MAX_REQ_TIMEOUT));
    }
    else {
        if (vbr->timeout > atomic_read(&vblk->write_req_timeout))
            atomic_set(&vblk->write_req_timeout, vbr->timeout);
        else
            vbr->timeout = atomic_read(&vblk->write_req_timeout);
//        timeout = atomic_read(&vblk->write_req_timeout) * 2;
//        atomic_set(&vblk->write_req_timeout, min(timeout, MAX_REQ_TIMEOUT));
    }
}

static __always_inline u64 calc_req_timeout(int req_timeout, int req_duration) {
//    if (unlikely(!req_timeout))
//        return req_duration;

    return (initial_request_timeout * 0.2) + (req_timeout * 0.8);
/*
    u64 new_timeout = (req_timeout * 0.9) + (req_duration * 0.1);
    if (new_timeout < MIN_REQ_TIMEOUT)
        new_timeout = MIN_REQ_TIMEOUT;

    return new_timeout;
*/
}

static __always_inline void update_req_timeout(struct virtblk_req *vbr, int req_duration) {
#if MONOTONIC_UP_TIMEOUT
    return;
#else
    struct vrio_blk *vblk = vbr->vblk;

    if (vbr_read_dir(vbr)) {
        atomic_set(&vblk->read_req_timeout, 
            calc_req_timeout(atomic_read(&vblk->read_req_timeout), req_duration));
    } else {
        atomic_set(&vblk->write_req_timeout, 
            calc_req_timeout(atomic_read(&vblk->write_req_timeout), req_duration));
    }    
#endif
}

static __always_inline int get_vblk_timeout(struct virtblk_req *vbr) {
    struct vrio_blk *vblk = vbr->vblk;
 
    if (vbr_flush_req(vbr))
        return atomic_read(&vblk->write_req_timeout) << 2;

    if (vbr_read_dir(vbr)) {
        return atomic_read(&vblk->read_req_timeout);
    } else {
        return atomic_read(&vblk->write_req_timeout);
    }
}

static __always_inline int get_req_timeout(struct virtblk_req *vbr) {
#if MONOTONIC_UP_TIMEOUT
    return vbr->timeout;
#else
    return (vbr->timeout); // << 1);
#endif
}

static __always_inline enum hrtimer_restart timer_callback(struct hrtimer *timer)
{
    struct virtblk_req *vbr = container_of(timer, struct virtblk_req, timer);
    struct vrio_blk *vblk = vbr->vblk;
    ktime_t interval;
    u64 actual_interval;
    int id, new_id;
    int ret;

    actual_interval = get_us_clock() - vbr->issue_time;
    trace("timer_callback try: %d, timeout us (%d), actual duration: (%d)", 
           vbr->retries, get_req_timeout(vbr), actual_interval);

    /* In some cases the timer expires prematurely */
    if (actual_interval * 1.1 < get_req_timeout(vbr)) {
        ntrace("timer expired prematured, forwarding (req_timeout: %lu, actual: %lu, delta: %lu)", 
            get_req_timeout(vbr), actual_interval, get_req_timeout(vbr) - actual_interval);
        atrace((get_req_timeout(vbr) - actual_interval) < 1e4);
//        interval = ktime_set(0, 
//            min_t(u64, us_to_ns(get_req_timeout(vbr) - actual_interval), us_to_ns(10000)));
        interval = ktime_set(0, us_to_ns(get_req_timeout(vbr) - actual_interval));
        hrtimer_forward_now(timer, interval);

        return HRTIMER_RESTART;
    }

    new_id = get_next_req_id(vblk);
    if (!(id = atomic_read(&vbr->id)) || (atomic_cmpxchg(&vbr->id, id, new_id) != id)) {
        trace("request is handled concurrently, leaving the timer");
        return HRTIMER_NORESTART;
    }

    debug_retries++;

    vbr->retries++;    
#if TRACE_DEBUG
    atomic_inc(&vblk->total_req_retries);
    vblk->max_retries = max(vblk->max_retries, vbr->retries);
#endif    

    if (vbr->retries > MAX_REQ_RETRIES) {
        ret = queue_gwork(vblk->vdev->gsocket, &vbr->drop_request_work);        
        atrace(ret == false);
        return HRTIMER_NORESTART;        
    }

    ntrace("resending request (try: %d, req: %lp), timeout us (%d), actual duration: (%d)", 
           vbr->retries, vbr ,get_req_timeout(vbr), actual_interval);
//    adjust_req_timeout(vbr);
    ntrace("new timeout us (%d)", get_req_timeout(vbr));

    interval = ktime_set(0, us_to_ns(get_req_timeout(vbr)));
    hrtimer_forward_now(timer, interval);

    ret = queue_gwork(vblk->vdev->gsocket, &vbr->add_buf_work);
    atrace(ret == false);

    return HRTIMER_RESTART;
}

static __always_inline void setup_req_timer(struct vrio_blk *vblk, struct virtblk_req *vbr) {
    ktime_t ktime = ktime_set(0, us_to_ns(get_req_timeout(vbr)));
    int err;
    
    trace("setup_req_timer (timeout us: %d)", get_req_timeout(vbr));
    hrtimer_init(&vbr->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    vbr->timer.function = &timer_callback;
    err = hrtimer_start(&vbr->timer, ktime, HRTIMER_MODE_REL);
    atrace(err != 0);
}

static __always_inline void teardown_req_timer(struct virtblk_req *vbr) {
    int ret;
    
    ret = hrtimer_cancel(&vbr->timer);
    trace("hrtimer_cancel: %d", ret);
}
#endif

static int virtblk_bio_send_flush(struct virtblk_req *vbr)
{
    unsigned int out = 0, in = 0;

    trace("virtblk_bio_send_flush");
    vbr->flags |= VBLK_IS_FLUSH;
    vbr->out_hdr.type = VIRTIO_BLK_T_FLUSH;
    vbr->out_hdr.sector = 0;
    vbr->out_hdr.ioprio = 0;
    sg_set_buf(&vbr->sg[out++], &vbr->out_hdr, sizeof(vbr->out_hdr));
    sg_set_buf(&vbr->sg[out + in++], &vbr->status, sizeof(vbr->status));

    vbr->out = out;
    vbr->in = in;

    virtblk_add_req(vbr);
    return 0;
}

static int virtblk_bio_send_data(struct virtblk_req *vbr)
{
    struct vrio_blk *vblk = vbr->vblk;
    unsigned int num, out = 0, in = 0;
    struct bio *bio = vbr->bio;

    trace("virtblk_bio_send_data");
    vbr->flags &= ~VBLK_IS_FLUSH;
    vbr->out_hdr.type = 0;
    vbr->out_hdr.sector = bio->bi_sector;
    vbr->out_hdr.ioprio = bio_prio(bio);

    sg_set_buf(&vbr->sg[out++], &vbr->out_hdr, sizeof(vbr->out_hdr));

    num = blk_bio_map_sg(vblk->disk->queue, bio, vbr->sg + out);

    sg_set_buf(&vbr->sg[num + out + in++], &vbr->status,
           sizeof(vbr->status));

    if (num) {
        if (bio->bi_rw & REQ_WRITE) {
            vbr->out_hdr.type |= VIRTIO_BLK_T_OUT;
            out += num;
        } else {
            vbr->out_hdr.type |= VIRTIO_BLK_T_IN;
            in += num;
        }
    }

    vbr->out = out;
    vbr->in = in;
    virtblk_add_req(vbr);
    return 0;
}

static void virtblk_bio_send_data_work(struct gwork_struct *gwork)
{
    struct virtblk_req *vbr = container_of(gwork, struct virtblk_req, bio_send_data_work);
    virtblk_bio_send_data(vbr);
}

static void virtblk_bio_send_flush_work(struct gwork_struct *gwork)
{
    struct virtblk_req *vbr = container_of(gwork, struct virtblk_req, bio_send_flush_work);
    virtblk_bio_send_flush(vbr);
}

static void __virtblk_done(struct virtblk_req *vbr);

#if REQUEST_TIMEOUT
static void drop_request(struct virtblk_req *vbr) 
{
    etrace("request is being dropped (retries: %d) (blkid: %d)", vbr->retries, vbr->vhdr.id);
    vbr->status = VIRTIO_BLK_S_IOERR;
    vbr->flags = 0;
    __virtblk_done(vbr);

#if 0
    spin_lock_irqsave(&vblk->disk->queue->queue_lock, flags);
    
    if (vbr->bio) {
        trace("vbr->bio != NULL");
        bio_endio(vbr->bio, virtblk_result(vbr));
        virtblk_free_req(vbr);

        /* In case queue is stopped waiting for more buffers. */        
        wake_up(&vblk->queue_wait);
    } else {
        trace("calling virtblk_request_done");
        virtblk_request_done(vbr);    

        /* In case queue is stopped waiting for more buffers. */        
        blk_start_queue(vblk->disk->queue);
    }

//    spin_unlock_irqrestore(&vblk->lock, flags);
    spin_unlock_irqrestore(&vblk->disk->queue->queue_lock, flags);
#endif
}

static void virtblk_drop_request_work(struct gwork_struct *gwork) {
    struct virtblk_req *vbr = container_of(gwork, struct virtblk_req, drop_request_work);
    trace("virtblk_drop_request_work");

    drop_request(vbr);
}
#endif

#if 0
static void virtblk_bio_send_data_work(struct work_struct *work)
{
    struct virtblk_req *vbr;

    vbr = container_of(work, struct virtblk_req, work);
    virtblk_bio_send_data(vbr);
}

static void virtblk_bio_send_flush_work(struct work_struct *work)
{
    struct virtblk_req *vbr;

    vbr = container_of(work, struct virtblk_req, work);
    virtblk_bio_send_flush(vbr);
}
#endif

static __always_inline void virtblk_request_done(struct virtblk_req *vbr)
{
    struct request *req = vbr->req;
    int error = virtblk_result(vbr);
    trace("virtblk_result: %d (OK: %d) (status: %d)", error, VIRTIO_BLK_S_OK, vbr->status);    
    trace("req->cmd_type: %d, (REQ_BLK_PC: %d, RET_SPECIAL: %d)", req->cmd_type, REQ_TYPE_BLOCK_PC, REQ_TYPE_SPECIAL);

    if (req->cmd_type == REQ_TYPE_BLOCK_PC) {
        etrace("not supported yet REQ_TYPE_BLOCK_PC");
        req->resid_len = vbr->in_hdr.residual;
        req->sense_len = vbr->in_hdr.sense_len;
        req->errors = vbr->in_hdr.errors;
    } else if (req->cmd_type == REQ_TYPE_SPECIAL) {
        etrace("not supported yet REQ_TYPE_SPECIAL");
        req->errors = (error != 0);
    }

    __blk_end_request_all(req, error);
    virtblk_free_req(vbr);
}

static __always_inline void virtblk_bio_flush_done(struct virtblk_req *vbr)
{
    struct vrio_blk *vblk = vbr->vblk;
    bool ret;

    trace("virtblk_bio_flush_done");
    if (vbr->flags & VBLK_REQ_DATA) {
        trace("vbr->flags & VBLK_REQ_DATA"); //ntrace
        /* Send out the actual write data */
        //ret = generic_work_queue(vblk->vdev->gsocket, virtblk_bio_send_data_work, (ulong)vbr, 0);
        ret = queue_gwork(vblk->vdev->gsocket, &vbr->bio_send_data_work);
        atrace(ret == false);
//        virtblk_bio_send_data(vbr);
    } else {
        bio_endio(vbr->bio, virtblk_result(vbr));
        virtblk_free_req(vbr);
    }
}

static __always_inline void virtblk_bio_data_done(struct virtblk_req *vbr)
{
    struct vrio_blk *vblk = vbr->vblk;
    bool ret;

    trace("virtblk_bio_data_done");
    if (unlikely(vbr->flags & VBLK_REQ_FUA)) {
        trace("unlikely(vbr->flags & VBLK_REQ_FUA)"); //ntrace
        /* Send out a flush before end the bio */
        vbr->flags &= ~VBLK_REQ_DATA;
        //ret = generic_work_queue(vblk->vdev->gsocket, virtblk_bio_send_flush_work, (ulong)vbr, 0);
        ret = queue_gwork(vblk->vdev->gsocket, &vbr->bio_send_flush_work);
        atrace(ret == false);
//        virtblk_bio_send_flush(vbr);
    } else {
        bio_endio(vbr->bio, virtblk_result(vbr));
        virtblk_free_req(vbr);
    }
}

static __always_inline void virtblk_bio_done(struct virtblk_req *vbr)
{
    if (unlikely(vbr->flags & VBLK_IS_FLUSH))
        virtblk_bio_flush_done(vbr);
    else
        virtblk_bio_data_done(vbr);
}

static __always_inline void __virtblk_req_apply(struct bio_vec *bvec, struct giovec *giovec) {
    unsigned char *bvec_addr;
    struct scatterlist sg;
    int ret;

    trace("__virtblk_req_apply");
    sg_set_page(&sg, bvec->bv_page, bvec->bv_len, bvec->bv_offset);
    bvec_addr = sg_virt(&sg);

    ret = memcpy_fromiovecend_skip(bvec_addr, giovec->iov, giovec->iov_len, bvec->bv_len);
    atrace(ret != 0, return);

    trace("iov_size: %d", bvec->bv_len);
    trace("iov_base(): %.*b", bvec->bv_len, bvec_addr);
}
                      
static void virtblk_req_apply(struct virtblk_req *vbr, struct giovec *giovec) {
    struct bio_vec *bvec; 
    struct req_iterator iter;

    struct iovec *iov = giovec->iov;
    size_t iov_len = giovec->iov_len;
    int i = 0; 
    int ret;

    trace("virtblk_req_apply");
    if (likely(vbr_read_dir(vbr))) {
        if (vbr->bio) {
            trace("apply vbr->bio");
            bio_for_each_segment(bvec, vbr->bio, i) {
                trace("i: %d", i);
                __virtblk_req_apply(bvec, giovec);
            }
        }
        else  {
            trace("apply vbr->req");
            rq_for_each_segment(bvec, vbr->req, iter) {
                trace("i: %d", i);
                __virtblk_req_apply(bvec, giovec);
            }
        }
    }

    ret = memcpy_fromiovecend_skip((unsigned char *)&vbr->status, iov, iov_len, sizeof(vbr->status));
    atrace(ret != 0, return);
    trace("status: %d.", vbr->status);
}

static void __virtblk_done(struct virtblk_req *vbr)
{
    struct vrio_blk *vblk = vbr->vblk;
    unsigned long flags;
    trace("virtblk_done");

    spin_lock_irqsave(&vblk->lock, flags);
//    spin_lock_irqsave(vblk->disk->queue->queue_lock, flags);
    
    if (vbr->bio) {
        trace("vbr->bio != NULL");
        virtblk_bio_done(vbr);

        /* In case queue is stopped waiting for more buffers. */        
        wake_up(&vblk->queue_wait);
    } else {
        trace("calling virtblk_request_done");
        virtblk_request_done(vbr);    

        /* In case queue is stopped waiting for more buffers. */        
        blk_start_queue(vblk->disk->queue);
    }

    spin_unlock_irqrestore(&vblk->lock, flags);
//    spin_unlock_irqrestore(vblk->disk->queue->queue_lock, flags);
}

static void virtblk_done(struct virtblk_req *vbr, int response_id, struct giovec *giovec)
{
#if REQUEST_TIMEOUT
    int req_duration;
    trace("virtblk_done vbr->id: %d, vhdr.id: %d", atomic_read(&vbr->id), response_id);

    if (atomic_cmpxchg(&vbr->id, response_id, 0) == response_id) {
        teardown_req_timer(vbr);
    
        req_duration = (get_us_clock() - vbr->issue_time);
        update_req_timeout(vbr, req_duration);
        trace("request duration: %d us", req_duration);

        virtblk_req_apply(vbr, giovec);
        __virtblk_done(vbr);
    } else {
        ntrace("Old response arrived, dropped (response_id: %d)", response_id);
    }

#else
    virtblk_req_apply(vbr, giovec);
    __virtblk_done(vbr);
#endif
}

static void virtblk_add_req_work(struct gwork_struct *gwork) {
    struct virtblk_req *vbr = container_of(gwork, struct virtblk_req, add_req_work);
    trace("virtblk_add_req_work");

    virtblk_add_req(vbr);
/*    if (virtblk_add_req(vbr, vbr->out, vbr->in) <= 0)  {
        etrace("virtblk_add_buf failed");
        virtblk_free_req(vbr);
        return;
    }*/
}

static bool do_req(struct request_queue *q, struct vrio_blk *vblk,
           struct request *req)
{
    unsigned long num, out = 0, in = 0;
    struct virtblk_req *vbr;
    bool ret;
    trace("do_req");

    vbr = virtblk_alloc_req(vblk); 
    if (!vbr) {
        trace("virtblk_alloc_req failed");
        /* When another request finishes we'll try again. */
        return false;
    }

    vbr->req = req;
    vbr->bio = NULL;
    if (req->cmd_flags & REQ_FLUSH) {
        trace("req->cmd_flags & REQ_FLUSH (VIRTIO_BLK_T_FLUSH)");
        vbr->out_hdr.type = VIRTIO_BLK_T_FLUSH;
        vbr->out_hdr.sector = 0;
        vbr->out_hdr.ioprio = req_get_ioprio(vbr->req);
    } else {
        switch (req->cmd_type) {
        case REQ_TYPE_FS:
            trace("REQ_TYPE_FS");
            vbr->out_hdr.type = 0;
            vbr->out_hdr.sector = blk_rq_pos(vbr->req);
            vbr->out_hdr.ioprio = req_get_ioprio(vbr->req);
            break;
        case REQ_TYPE_BLOCK_PC:
            etrace("REQ_TYPE_BLOCK_PC not supported");
            virtblk_free_req(vbr);
/*
            vbr->out_hdr.type = VIRTIO_BLK_T_SCSI_CMD;
            vbr->out_hdr.sector = 0;
            vbr->out_hdr.ioprio = req_get_ioprio(vbr->req);
*/
            return false;
            break;
/*
        case REQ_TYPE_SPECIAL:
            trace("REQ_TYPE_SPECIAL");
            vbr->out_hdr.type = VIRTIO_BLK_T_GET_ID;
            vbr->out_hdr.sector = 0;
            vbr->out_hdr.ioprio = req_get_ioprio(vbr->req);
            break;
*/        default:
            /* We don't put anything else in the queue. */
            etrace("Unknown request %d (REQ_TYPE_SPECIAL: %d)", req->cmd_type, REQ_TYPE_SPECIAL);
            BUG();
        }
    }

    sg_set_buf(&vbr->sg[out++], &vbr->out_hdr, sizeof(vbr->out_hdr));

    /*
     * If this is a packet command we need a couple of additional headers.
     * Behind the normal outhdr we put a segment with the scsi command
     * block, and before the normal inhdr we put the sense data and the
     * inhdr with additional status information before the normal inhdr.
     */
/*
    if (vbr->req->cmd_type == REQ_TYPE_BLOCK_PC)
        sg_set_buf(&vblk->sg[out++], vbr->req->cmd, vbr->req->cmd_len);
*/
    num = blk_rq_map_sg(q, vbr->req, vbr->sg + out);
/*
    if (vbr->req->cmd_type == REQ_TYPE_BLOCK_PC) {
        sg_set_buf(&vbr->sg[num + out + in++], vbr->req->sense, SCSI_SENSE_BUFFERSIZE);
        sg_set_buf(&vbr->sg[num + out + in++], &vbr->in_hdr,
               sizeof(vbr->in_hdr));
    }
*/
    sg_set_buf(&vbr->sg[num + out + in++], &vbr->status,
           sizeof(vbr->status));

    if (num) {
        if (rq_data_dir(vbr->req) == WRITE) {
            trace("rq_data_dir(vbr->req) == WRITE, type |= VIRTIO_BLK_T_OUT");
            vbr->out_hdr.type |= VIRTIO_BLK_T_OUT;
            out += num;
        } else {
            trace("rq_data_dir(vbr->req) != WRITE, type |= VIRTIO_BLK_T_IN");
            vbr->out_hdr.type |= VIRTIO_BLK_T_IN;
            in += num;
        }
    }

    vbr->in = in;
    vbr->out = out;
    ret = queue_gwork(vblk->vdev->gsocket, &vbr->add_req_work);     
    atrace(ret == false);

    return true;
}
#if 1
static void virtblk_request(struct request_queue *q) {
    struct vrio_blk *vblk = q->queuedata;
    struct request *req;

    trace("virtblk_request");
    while ((req = blk_peek_request(q)) != NULL) {
#if TRACE_DEBUG
        BUG_ON(req->nr_phys_segments + 2 > vblk->sg_elems);
#endif
        /* If this request fails, stop queue and wait for something to
           finish to restart it. */
        if (!do_req(q, vblk, req)) {
            trace("do_req failed");
            blk_stop_queue(q);
            break;
        }

        blk_start_request(req);
    }
    trace("virtblk_request done");
}
#endif

static __always_inline struct virtblk_req *virtblk_alloc_req_wait(struct vrio_blk *vblk) {
    struct virtblk_req *vbr;
    DEFINE_WAIT(wait);
    trace("virtblk_alloc_req_wait");

    for (;;) {
        prepare_to_wait_exclusive(&vblk->queue_wait, &wait,
                      TASK_UNINTERRUPTIBLE);

        vbr = virtblk_alloc_req(vblk);
        if (vbr)
            break;
        
        trace("waiting on wait_queue for available vbr");
        io_schedule();
    }

    finish_wait(&vblk->queue_wait, &wait);
    return vbr;
}

static void virtblk_make_request(struct request_queue *q, struct bio *bio)
{
    struct vrio_blk *vblk = q->queuedata;
    struct virtblk_req *vbr;

#if TRACE_DEBUG
    BUG_ON(bio->bi_phys_segments + 2 > vblk->sg_elems);
#endif
        
    trace("virtblk_make_request");
    vbr = virtblk_alloc_req_wait(vblk);
    if (!vbr) {
        etrace("virtblk_alloc_req_wait failed");
        bio_endio(bio, -ENOMEM);
        return;
    }

    trace("virtblk_make_request: %p", bio);
    vbr->bio = bio;
    vbr->flags = 0;
    if (bio->bi_rw & REQ_FLUSH)
        vbr->flags |= VBLK_REQ_FLUSH;
    if (bio->bi_rw & REQ_FUA)
        vbr->flags |= VBLK_REQ_FUA;
    if (bio->bi_size)
        vbr->flags |= VBLK_REQ_DATA;

    if (unlikely(vbr->flags & VBLK_REQ_FLUSH))
        virtblk_bio_send_flush(vbr);
    else
        virtblk_bio_send_data(vbr);
}

/* return id (s/n) string for *disk to *id_str
 */
static int virtblk_get_id(struct gendisk *disk, char *id_str)
{
    struct vrio_blk *vblk = disk->private_data;
    struct request *req;
    struct bio *bio;
    int err;

    bio = bio_map_kern(vblk->disk->queue, id_str, VIRTIO_BLK_ID_BYTES,
               GFP_KERNEL);
    if (IS_ERR(bio))
        return PTR_ERR(bio);

    req = blk_make_request(vblk->disk->queue, bio, GFP_KERNEL);
    if (IS_ERR(req)) {
        bio_put(bio);
        return PTR_ERR(req);
    }

    req->cmd_type = REQ_TYPE_SPECIAL;
    err = blk_execute_rq(vblk->disk->queue, vblk->disk, req, false);
    blk_put_request(req);

    return err;
}

static int virtblk_ioctl(struct block_device *bdev, fmode_t mode,
                 unsigned int cmd, unsigned long data)
{
    struct gendisk *disk = bdev->bd_disk;
    struct vrio_blk *vblk = disk->private_data;
    trace("virtblk_ioctl");
    /*
     * Only allow the generic SCSI ioctls if the host can support it.
     */
    if (!vrio_has_feature(vblk->vdev, VIRTIO_BLK_F_SCSI))
        return -ENOTTY;

    trace("VIRTIO_BLK_F_SCSI");

    return scsi_cmd_blk_ioctl(bdev, mode, cmd,
                  (void __user *)data);
}

/* We provide getgeo only to please some old bootloader/partitioning tools */
static int virtblk_getgeo(struct block_device *bd, struct hd_geometry *geo)
{
    struct vrio_blk *vblk = bd->bd_disk->private_data;
    struct vrio_blk_geometry vgeo;
    int err;

    /* see if the host passed in geometry config */
    err = vrio_config_val(vblk->vdev, VIRTIO_BLK_F_GEOMETRY,
                offsetof(struct vrio_blk_config, geometry),
                &vgeo);

    if (!err) {
        geo->heads = vgeo.heads;
        geo->sectors = vgeo.sectors;
        geo->cylinders = vgeo.cylinders;
    } else {
        /* some standard values, similar to sd */
        geo->heads = 1 << 6;
        geo->sectors = 1 << 5;
        geo->cylinders = get_capacity(bd->bd_disk) >> 11;
    }
    return 0;
}

static const struct block_device_operations virtblk_fops = {
//    .owner  = THIS_MODULE,
    .ioctl  = virtblk_ioctl,
    .getgeo = virtblk_getgeo,
};

static int index_to_minor(int index)
{
    return index << PART_BITS;
}

static int minor_to_index(int minor)
{
    return minor >> PART_BITS;
}

static ssize_t virtblk_serial_show(struct device *dev,
                struct device_attribute *attr, char *buf)
{
    struct gendisk *disk = dev_to_disk(dev);
    struct vrio_blk *vblk = disk->private_data;
    int err;

    err = snprintf(buf, VIRTIO_BLK_ID_BYTES,
                   "vhost-blk%d", vblk->index);

    return err;

#if 0
    struct gendisk *disk = dev_to_disk(dev);
    int err;

    /* sysfs gives us a PAGE_SIZE buffer */
    BUILD_BUG_ON(PAGE_SIZE < VIRTIO_BLK_ID_BYTES);

    buf[VIRTIO_BLK_ID_BYTES] = '\0';
    err = virtblk_get_id(disk, buf);
    if (!err)
        return strlen(buf);

    if (err == -EIO) /* Unsupported? Make it empty. */
        return 0;

    return err;
#endif
}
DEVICE_ATTR(serial, S_IRUGO, virtblk_serial_show, NULL);
// DEVICE_ATTR(serial, S_IRUGO, NULL, NULL);

/*
 * Legacy naming scheme used for virtio devices.  We are stuck with it for
 * virtio blk but don't ever use it for any new driver.
 */
static int virtblk_name_format(char *prefix, int index, char *buf, int buflen)
{
    const int base = 'z' - 'a' + 1;
    char *begin = buf + strlen(prefix);
    char *end = buf + buflen;
    char *p;
    int unit;

    p = end - 1;
    *p = '\0';
    unit = base;
    do {
        if (p == begin)
            return -EINVAL;
        *--p = 'a' + (index % unit);
        index = (index / unit) - 1;
    } while (index >= 0);

    memmove(begin, p, end - p);
    memcpy(buf, prefix, strlen(prefix));

    return 0;
}

static int virtblk_get_cache_mode(struct vrio_device *vdev)
{
    u8 writeback;
    int err;

    err = vrio_config_val(vdev, VIRTIO_BLK_F_CONFIG_WCE, 
                offsetof(struct vrio_blk_config, wce), 
                &writeback);
    
    trace("virtblk_get_cache_mode: err %d", err);
    if (err)
        writeback = vrio_has_feature(vdev, VIRTIO_BLK_F_WCE);

    trace("virtblk_get_cache_mode: writeback %d", writeback);
    return writeback;
}

static void virtblk_update_cache_mode(struct vrio_device *vdev)
{
    u8 writeback = virtblk_get_cache_mode(vdev);
    struct vrio_blk *vblk = vdev->priv;

    if (writeback)
        blk_queue_flush(vblk->disk->queue, REQ_FLUSH);
    else
        blk_queue_flush(vblk->disk->queue, 0);

    revalidate_disk(vblk->disk);
}

static const char *const virtblk_cache_types[] = {
    "write through", "write back"
};

static ssize_t
virtblk_cache_type_store(struct device *dev, struct device_attribute *attr,
             const char *buf, size_t count)
{
    struct gendisk *disk = dev_to_disk(dev);
    struct vrio_blk *vblk = disk->private_data;
    struct vrio_device *vdev = vblk->vdev;
    int i;
    u8 writeback;

    trace("virtblk_cache_type_store");

    BUG_ON(!vrio_has_feature(vblk->vdev, VIRTIO_BLK_F_CONFIG_WCE));
    for (i = ARRAY_SIZE(virtblk_cache_types); --i >= 0; )
        if (sysfs_streq(buf, virtblk_cache_types[i]))
            break;

    if (i < 0)
        return -EINVAL;

    writeback = i;    
    vrio_set_config_val(vdev,
              offsetof(struct vrio_blk_config, wce),
              &writeback, sizeof(writeback));

    virtblk_update_cache_mode(vdev);
    return count;
}

static ssize_t
virtblk_cache_type_show(struct device *dev, struct device_attribute *attr,
             char *buf)
{    
    struct gendisk *disk = dev_to_disk(dev);
    struct vrio_blk *vblk = disk->private_data;
    u8 writeback = virtblk_get_cache_mode(vblk->vdev);
    trace("virtblk_cache_type_show");

    BUG_ON(writeback >= ARRAY_SIZE(virtblk_cache_types));
    return snprintf(buf, 40, "%s\n", virtblk_cache_types[writeback]);
}

static const struct device_attribute dev_attr_cache_type_ro =
    __ATTR(cache_type, S_IRUGO,
           virtblk_cache_type_show, NULL);

static const struct device_attribute dev_attr_cache_type_rw =
    __ATTR(cache_type, S_IRUGO|S_IWUSR,
           virtblk_cache_type_show, virtblk_cache_type_store);

static int create_blk_device(struct vrio_device *vdev)
{
    char device_name[DISK_NAME_LEN];
    struct vrio_blk *vblk;
    struct request_queue *queue;
    int err, index;
    int pool_size;
  
    u64 cap;
    u32 blk_size, sg_elems;

    err = ida_simple_get(&vd_index_ida, 0, minor_to_index(1 << MINORBITS),
                 GFP_KERNEL);
    if (err < 0)
        goto out;
    index = err;
    /* We need to know how many segments before we allocate. */
    err = vrio_config_val(vdev, VIRTIO_BLK_F_SEG_MAX,
                offsetof(struct vrio_blk_config, seg_max),
                &sg_elems);

    /* We need at least one SG element, whatever they say. */
    if (err || !sg_elems)
        sg_elems = 1;
    sg_elems += 2;
    //sg_elems = 4;
    trace("sg_elems: %d, %d", sg_elems, err);
    vdev->priv = vblk = kzalloc(sizeof(*vblk), GFP_KERNEL);
    if (!vblk) {
        err = -ENOMEM;
        goto out_free_index;
    }

#if REQUEST_TIMEOUT
    atomic_set(&vblk->read_req_timeout, initial_request_timeout);
    atomic_set(&vblk->write_req_timeout, initial_request_timeout);
#endif    
    
    init_waitqueue_head(&vblk->queue_wait);
    vblk->vdev = vdev;
    vblk->sg_elems = sg_elems;

    pool_size = sizeof(struct virtblk_req) + sizeof(struct scatterlist) * sg_elems;
    if (init_cmempool(&vblk->cmempool, num_outstanding_reqs, pool_size) == false) {
        etrace("init_mempool failed");
        err = -ENOMEM;
        goto out_cqueue;
    }

    /* FIXME: How many partitions?  How long is a piece of string? */
    vblk->disk = alloc_disk(1 << PART_BITS);
    if (!vblk->disk) {
        err = -ENOMEM;
        goto out_mempool;
    }

    spin_lock_init(&vblk->lock);
    queue = vblk->disk->queue = blk_init_queue(virtblk_request, &vblk->lock);
    if (!queue) {
        err = -ENOMEM;
        goto out_put_disk;
    }

    trace("use_bio: %d", use_bio);
    if (use_bio)
        blk_queue_make_request(queue, virtblk_make_request);

    queue->queuedata = vblk;

#if REQUEST_TIMEOUT    
    atomic_set(&vblk->request_id, 0);
#endif

    if (vrio_config_val_len(vdev, VIRTIO_BLK_F_DEV_NAME, 
        offsetof(struct vrio_blk_config, device_name), device_name, DISK_NAME_LEN)) 
        virtblk_name_format("vrd", index, vblk->disk->disk_name, DISK_NAME_LEN);
    else
        strncpy(vblk->disk->disk_name, device_name, DISK_NAME_LEN);

    vblk->disk->major = major;
    vblk->disk->first_minor = index_to_minor(index);
    vblk->disk->private_data = vblk;
    vblk->disk->fops = &virtblk_fops;
    vblk->index = index;

    /* configure queue flush support */
    virtblk_update_cache_mode(vdev);

    /* If disk is read-only in the host, the guest should obey */
    if (vrio_has_feature(vdev, VIRTIO_BLK_F_RO)) {
        trace("disk is readonly");
        set_disk_ro(vblk->disk, 1);
    }

    /* Host must always specify the capacity. */
    __vrio_config_val(vdev, offsetof(struct vrio_blk_config, capacity), &cap);
    atrace(cap == 0, etrace("cap == 0"); return -1);
    trace("disk capacity: %lu, %lu", cap, cap/512);
    set_capacity(vblk->disk, cap / 512);

    /* We can handle whatever the host told us to handle. */
    blk_queue_max_segments(queue, vblk->sg_elems-2);

    /* No need to bounce any requests */
    blk_queue_bounce_limit(queue, BLK_BOUNCE_ANY);

    /* No real sector limit. */
    blk_queue_max_hw_sectors(queue, -1U);

#if 0
    /* Host can optionally specify maximum segment size and number of
     * segments. */
    err = virtio_config_val(vdev, VIRTIO_BLK_F_SIZE_MAX,
                offsetof(struct virtio_blk_config, size_max),
                &v);
    if (!err)
        blk_queue_max_segment_size(q, v);
    else
        blk_queue_max_segment_size(q, -1U);
#endif

    blk_queue_max_segment_size(queue, -1U);
    trace("blk_queue_max_segment_size: %d", -1);

//    blk_queue_max_segment_size(queue, 61000); // -1U);
#if 0
    /* Host can optionally specify the block size of the device */
    err = virtio_config_val(vdev, VIRTIO_BLK_F_BLK_SIZE,
                offsetof(struct virtio_blk_config, blk_size),
                &blk_size);
    if (!err)
        blk_queue_logical_block_size(q, blk_size);
    else
        blk_size = queue_logical_block_size(q);
#endif

    err = vrio_config_val(vdev, VIRTIO_BLK_F_BLK_SIZE, 
                offsetof(struct vrio_blk_config, blk_size), 
                &blk_size);
    if (!err) {
        blk_queue_logical_block_size(queue, blk_size);
    } else {
        blk_size = queue_logical_block_size(queue);
    }

    trace("blk_size: %d (err: %d)", blk_size, err);
#if 0
    /* Use topology information if available */
    err = virtio_config_val(vdev, VIRTIO_BLK_F_TOPOLOGY,
            offsetof(struct virtio_blk_config, physical_block_exp),
            &physical_block_exp);
    if (!err && physical_block_exp)
        blk_queue_physical_block_size(q,
                blk_size * (1 << physical_block_exp));

    err = virtio_config_val(vdev, VIRTIO_BLK_F_TOPOLOGY,
            offsetof(struct virtio_blk_config, alignment_offset),
            &alignment_offset);
    if (!err && alignment_offset)
        blk_queue_alignment_offset(q, blk_size * alignment_offset);

    err = virtio_config_val(vdev, VIRTIO_BLK_F_TOPOLOGY,
            offsetof(struct virtio_blk_config, min_io_size),
            &min_io_size);
    if (!err && min_io_size)
        blk_queue_io_min(q, blk_size * min_io_size);

    err = virtio_config_val(vdev, VIRTIO_BLK_F_TOPOLOGY,
            offsetof(struct virtio_blk_config, opt_io_size),
            &opt_io_size);
    if (!err && opt_io_size)
        blk_queue_io_opt(q, blk_size * opt_io_size);
#endif
    trace("adding disk");
    add_disk(vblk->disk);

    err = device_create_file(disk_to_dev(vblk->disk), &dev_attr_serial);
    if (err)
        goto out_del_disk;

    if (vrio_has_feature(vdev, VIRTIO_BLK_F_CONFIG_WCE)) {
        err = device_create_file(disk_to_dev(vblk->disk),
                     &dev_attr_cache_type_rw);
        trace("device_create_file VIRTIO_BLK_F_CONFIG_WCE err: %d", err);
    }
    else {
        err = device_create_file(disk_to_dev(vblk->disk),
                     &dev_attr_cache_type_ro);
        trace("device_create_file NO VIRTIO_BLK_F_CONFIG_WCE err: %d", err);
    }
    if (err)
        goto out_del_disk;

    return 0;

out_del_disk:
    del_gendisk(vblk->disk);
    blk_cleanup_queue(queue);
out_put_disk:
    put_disk(vblk->disk);
out_mempool:
    done_cmempool(&vblk->cmempool);
out_cqueue:
//    free_cqueue(vblk->pending_requests);


//    mempool_destroy(vblk->pool);
/*out_free_vq:
    vdev->config->del_vqs(vdev);
out_free_vblk:
    kfree(vblk);
*/
out_free_index:
    ida_simple_remove(&vd_index_ida, index);
out:
    return err;
}

static void remove_blk_device(struct vrio_device *vdev)
{
    struct vrio_blk *vblk = vdev->priv;
    int index = vblk->index;
    int refc;

    del_gendisk(vblk->disk);
    blk_cleanup_queue(vblk->disk->queue);

    refc = atomic_read(&disk_to_dev(vblk->disk)->kobj.kref.refcount);
    put_disk(vblk->disk);
    done_cmempool(&vblk->cmempool);
//    free_cqueue(vblk->pending_requests);

    kfree(vblk);

    /* Only free device id if we don't have any users */
    if (refc == 1)
        ida_simple_remove(&vd_index_ida, index);
}


static const struct virtio_device_id id_table[] = {
    { VIRTIO_ID_BLOCK, VIRTIO_DEV_ANY_ID },
    { 0 },
};
/*
static unsigned int features[] = {
    VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_GEOMETRY,
    VIRTIO_BLK_F_RO, VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_SCSI,
    VIRTIO_BLK_F_WCE, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_CONFIG_WCE
};
*/
static int __create_blk_device(struct ioctl_param *param) { 
    struct ioctl_create *create = &param->x.create;
    int res;

    struct vrio_device *vdev;
    vdev = kmalloc(sizeof(*vdev), GFP_KERNEL);

    vdev->ioctl_param = *param;
 //   vdev->placeholder.vrio_blk_config = create->config.vrio_blk;
    vdev->config = &vdev->ioctl_param.x.create.config.vrio_blk; // &vdev->placeholder.vrio_blk_config;
    vdev->features = create->config.vrio_blk.features;

    vdev->gsocket = (struct gsocket *)create->gsocket;
    atrace(vdev->gsocket == NULL, return -EFAULT);
    vdev->host_priv = create->host_priv;
    atrace((void *)vdev->host_priv == NULL);

    res = create_blk_device(vdev);
    trace("create_blk_device: %d", res);
    if (res != 0) {
        etrace("create_blk_device failed");
        goto free_vdev;
    }

    list_add(&vdev->link, &devices_list);
    return 0;

free_vdev:
    kfree(vdev);   
    return res;
}

int create_blk_device_thread(void *data) { 
    struct ioctl_param *param = data;
    trace("blk_thread");
    __create_blk_device(param);
    kfree(param);
    return 0;
}

static void __remove_blk_device(struct vrio_device *vdev) {
    mtrace("Destroying virtual block device frontend: %s", vdev->ioctl_param.x.create.device_path);
    list_del(&vdev->link);            
    remove_blk_device(vdev);
    gfree_gsocket(vdev->gsocket);
    kfree(vdev);    

//    module_put(THIS_MODULE);
}

static struct vrio_device *get_blk_device_by_backend(char *device_path) {
    struct vrio_device *vdev;

    list_for_each_entry(vdev, &devices_list, link) { 
       if (!strncmp(vdev->ioctl_param.x.create.device_path, 
                    device_path,
                    sizeof(vdev->ioctl_param.x.create.device_path)))
            return vdev;
     }

     return NULL;
}

static void remove_blk_device_by_backend(char *device_path) {
    struct vrio_device *vdev;

    vdev = get_blk_device_by_backend(device_path);
    if (vdev)
        __remove_blk_device(vdev);        
}

/*
static void remove_blk_device_by_index(int index) {
    struct vrio_device *vdev;

    trace("device_id: %d", index);
    list_entry_at_index(index, vdev, &devices_list, link);
    if (vdev == NULL) {
        etrace("blk device with id %d is no where to be found", index);
        return;
    }

    __remove_blk_device(vdev);
}

static void remove_blk_device_by_uid(uint device_uid) {
    struct vrio_device *vdev;

    list_for_each_entry(vdev, &devices_list, link) { 
        if (vdev->device_uid == device_uid) {
            __remove_blk_device(vdev);
            return;
        }
    }
}
*/
static void remove_all_blk_devices(void) {
    struct vrio_device *vdev, *n;

    trace("remove_all_blk_devices");
    list_for_each_entry_safe(vdev, n, &devices_list, link) { 
        trace("calling __remove_blk_device: %p", vdev);
        __remove_blk_device(vdev);
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
    struct vrio_device *vdev;
    struct vrio_blk *vblk;
    mtrace("sanity_check");

    list_for_each_entry(vdev, &devices_list, link) { 
        vblk = vdev->priv;
#if TRACE_DEBUG
        mtrace("stat_total_reqs: %d", vblk->stat_total_reqs);
        mtrace("stat_outstanding_reqs: %d", atomic_read(&vblk->stat_outstanding_reqs));
        mtrace("stat_max_outstanding_reqs: %d", vblk->stat_max_outstanding_reqs);
#if REQUEST_TIMEOUT
        mtrace("total_req_retries: %d", atomic_read(&vblk->total_req_retries));
        mtrace("req_retries: %d", vblk->max_retries);
#endif        
#endif
        mtrace("cmempool->free_list: %d", cmempool_size(&vblk->cmempool)); // llist_size(&vblk->lmempool.free_list));
    }
}
#endif

long ioctl(struct ioctl_param *local_param) {

    switch (local_param->cmd) {
        case VRIO_IOCTL_CREATE_BLK: {                                            
            struct ioctl_param *param;
            
            mtrace("ioctl VRIO_IOCTL_CREATE_BLK");
            param = (struct ioctl_param *)kmalloc(sizeof(struct ioctl_param), GFP_KERNEL);
            *param = *local_param;
            kthread_run(create_blk_device_thread, param, "blk-create");
            break;
        }
        case VRIO_IOCTL_REMOVE_DEV: {
            mtrace("ioctl VRIO_IOCTL_REMOVE_DEV");
            remove_blk_device_by_backend(local_param->x.create.device_path);
//            remove_blk_device_by_uid(local_param->x.remove.device_uid);
//            remove_blk_device_by_index(local_param->x.remove.device_id);
/*
            if (local_param->x.remove.device_id == -1) 
                remove_all_blk_devices();
            else 
                remove_blk_device_by_index(local_param->x.remove.device_id);                
*/            
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

    return 0;
}

void handler(ulong param1, ulong param2) {
    struct gsocket *gsocket = (struct gsocket *)param1;
    struct giovec *giovec = (struct giovec *)param2;
    struct vrio_header vhdr;
    struct virtblk_req *vbr;
    int len, ret;
    int i = 0;
        
#if TRACE_DEBUG
    static int times = 0;
    len = iov_length(giovec->iov, giovec->iov_len);
    trace("handler (times: %d, total_size: %d)", times, len);
    times++;
#endif
 
#if TRACE_DEBUG
    for (i=0; i<giovec->iov_len; i++) {
        trace("iov[%d]: %d, %.*b", i, giovec->iov[i].iov_len, giovec->iov[i].iov_len, giovec->iov[i].iov_base);
    }    
#endif
    i=0;
    len = iov_length(giovec->iov, giovec->iov_len);
    atrace(len <= VRIO_HEADER_SIZE);
    while (len > 0) {
        trace("len: %d", len);
        ret = memcpy_fromiovecend_skip((unsigned char *)&vhdr, giovec->iov, giovec->iov_len, VRIO_HEADER_SIZE);
        atrace(ret != 0, goto done);
        trace("vhdr.id: %d (blkid), VRIO_HEADER_SIZE + vhdr.out_len: %d", vhdr.id, VRIO_HEADER_SIZE + vhdr.out_len);
        len -= (VRIO_HEADER_SIZE + vhdr.out_len);
        atrace(len < 0, goto done);
        atrace(vhdr.guest_priv == 0, goto done);

        vbr = (struct virtblk_req *)vhdr.guest_priv;

#if REQUEST_TIMEOUT
#if TRACE_DEBUG
    if (debug_drop_response > 0) {
        debug_drop_response--;
        iovec_pop_len(giovec->iov, giovec->iov_len, vhdr.out_len);
        continue;
    }
#endif
#endif
        virtblk_done(vbr, vhdr.id, giovec);
        ++i;
    }

done:
    trace("batch count: %d", i);
    gfree_packet(gsocket, giovec);    
}

static struct vdev vdev_blk = {
    .name = "blk",
    .handler = handler,
    .ioctl = ioctl,
    .run_from_softirq_context = true,
};

static int __init init(void)
{
    int error;
    bool res;
    
    mtrace("module gblk up (use_bio: %d)", use_bio);
    INIT_LIST_HEAD(&devices_list);

    res = vdev_register(&vdev_blk);
    trace("vdev_register: %d", res);
    if (!res) {
        etrace("vdev_register failed");
        return -EPERM;
    }
    major = register_blkdev(0, "vrio-blk");
    if (major < 0) {
        error = major;
        goto out_vdev_unregister;
    }

    return 0;
out_vdev_unregister:
    vdev_unregister(&vdev_blk);
    return error;
}

static void __exit fini(void)
{
    mtrace("module gblk down");
    
    remove_all_blk_devices();
    unregister_blkdev(major, "vrio-blk");
    vdev_unregister(&vdev_blk);
}
module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("vRIO gblock driver");
MODULE_LICENSE("GPL");
#endif
