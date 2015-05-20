#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/vhost.h>
#include <linux/virtio_blk.h>
#include <linux/mutex.h>
#include <linux/file.h>
#include <linux/kthread.h>
#include <linux/blkdev.h>
#include <linux/llist.h>

#define TRACE_LEVEL 3
#include <linux/vrio/trace.h>
#include <linux/vrio/generic.h>
#include <linux/vrio/utils.h>
#include <linux/vrio/vrio.h>
#include <linux/vrio/sdev.h>

TRACE_ALL;

#include <linux/vrio/cqueue.h>
#include <linux/vrio/lmempool.h>

#define MAX_OUTSTANDING_REQ (64 * 16)

static int iov_segs = 4;
module_param(iov_segs, int, S_IWUSR | S_IRUGO);

long seed = 0;

struct lmempool lmempool;

atomic64_t total_rx_bytes;
atomic64_t total_tx_bytes;
atomic64_t total_rx_requests;
atomic64_t total_tx_requests;

static void init_stats(void);

long ioctl(struct ioctl_param *local_param) {
    long res = 0;

    switch (local_param->cmd) {
        case VRIO_IOCTL_CREATE_SDEV: {        
            mtrace("ioctl VRIO_IOCTL_CREATE_SDEV");
            break;
        }

        case VRIO_IOCTL_REQUEST_SDEV: {
            mtrace("ioctl VRIO_IOCTL_REQUEST_SDEV");
            break;
        }

        case VRIO_IOCTL_SANITY_CHECK: {
            mtrace("ioctl VRIO_IOCTL_SANITY_CHECK");
            mtrace("total_tx_requests: %lu", atomic64_read(&total_tx_requests));
            mtrace("total_rx_requests: %lu", atomic64_read(&total_rx_requests));
            mtrace("total_tx_bytes (MB): %lu", atomic64_read(&total_tx_bytes)/(1024*1024));
            mtrace("total_rx_bytes (MB): %lu", atomic64_read(&total_rx_bytes)/(1024*1024));
            mtrace("total_tx_bits (Mb): %lu", atomic64_read(&total_tx_bytes)*8/(1024*1024));
            mtrace("total_rx_bits (Mb): %lu", atomic64_read(&total_rx_bytes)*8/(1024*1024));
            init_stats();
            break;
        }
        
        default: {
            etrace("ioctl: no such command");            
            break;
        }
    }

    return res;
}

struct skb_frag_data {
    struct sdev_req *req;
};

int destroy_skb_frag(struct skb_frag_destructor *destructor) {
    struct skb_frag_data *data = (struct skb_frag_data *)destructor->data;

    trace("destroy_skb_frag, lmempool_free");
    lmempool_free(&lmempool, data->req);    

    return 0;
}

void handler(ulong param1, ulong param2) {
    struct sdev_header *shdr;
    struct sdev_req *req;
    struct gsocket *gsocket = (struct gsocket *)param1;
    struct giovec *giovec = (struct giovec *)param2;
    int err;

    struct skb_frag_destructor *destroy;
    struct skb_frag_data *data;

    atrace(giovec->iov[0].iov_len < SDEV_HEADER_SIZE, return);

    shdr = (struct sdev_header *)giovec->iov[0].iov_base;
    giovec->iov[0].iov_base += SDEV_HEADER_SIZE;
    giovec->iov[0].iov_len -= SDEV_HEADER_SIZE;

    if ((shdr->flags & SDEV_FLAGS_CHECKSUM) && 
        !is_sdev_checksum_valid(giovec->iov, giovec->iov_len, shdr->checksum)) {
        etrace("sdev checksum mismatch");
        gfree_packet(gsocket, giovec);
        return;
    }

    atomic64_inc(&total_rx_requests);
    atomic64_add(iov_length(giovec->iov, giovec->iov_len), &total_rx_bytes);

    trace("request size: %d (flags: %d)", shdr->size, shdr->flags);
    req = lmempool_alloc(&lmempool);
    if (!req) {
        etrace("lmempool_alloc failed");
        gfree_packet(gsocket, giovec);    
        return;
    }

    destroy = (struct skb_frag_destructor *)req->__destroy;
    init_frag_destructor(destroy, destroy_skb_frag);
    data = FRAG_DESTROY_DATA(destroy, struct skb_frag_data *);
    data->req = req;

    if (shdr->operation == SDEV_OPERATION_WRITE) {
        trace("received a write operation");
        if (shdr->flags & SDEV_FLAGS_ACK_ON_WRITE) {
            trace("sending ack");
            req->shdr.private = shdr->private;
            req->shdr.operation = SDEV_OPERATION_ACK;
            req->shdr.size = 0;
            req->shdr.flags = 0;
            map_request_iov(req, 0, iov_segs);
            err = gsend_iov(gsocket, req->iov, req->nr_iov);
            atrace(err < 0);
            lmempool_free(&lmempool, req);    

            atomic64_inc(&total_tx_requests);
        }
    }

    if (shdr->operation == SDEV_OPERATION_READ) {    
        trace("received a read operation");    
        req->shdr = *shdr;

        init_buffer(req->buffer, shdr->size, seed++);
        map_request_iov(req, shdr->size, iov_segs);
        if (shdr->flags & SDEV_FLAGS_CHECKSUM) {
            req->shdr.checksum = calc_sdev_checksum_buff(req->buffer, shdr->size);
            trace("checksum: %X", req->shdr.checksum);
        }

        atomic64_inc(&total_tx_requests);
        atomic64_add(iov_length(req->iov, req->nr_iov), &total_tx_bytes);

        if (shdr->flags & SDEV_FLAGS_READ_ZCOPY) {
            trace("sending read request, send-zero-copy (size: %d) (req: %lp)", shdr->size, req);
            err = zgsend_iov(gsocket, req->iov, req->nr_iov, destroy);
            atrace(err < 0);
        } else {
            trace("sending read request (size: %d) (req: %lp)", shdr->size, req);
            err = gsend_iov(gsocket, req->iov, req->nr_iov);
            atrace(err < 0);            
            lmempool_free(&lmempool, req);    
        }
    }

    gfree_packet(gsocket, giovec);    
}

static void init_stats(void)
{
    atomic64_set(&total_rx_bytes, 0);
    atomic64_set(&total_tx_bytes, 0);
    atomic64_set(&total_rx_requests, 0);
    atomic64_set(&total_tx_requests, 0);
}

static void initialize(void)
{
    if (init_lmempool(&lmempool, MAX_OUTSTANDING_REQ, sizeof(struct sdev_req)) == false) {
        etrace("init_mempool failed");
        return;
    }

    init_stats();
}

static void free_all(void)
{
    done_lmempool(&lmempool);
}

static struct vdev vdev_sdev = {
    .name = "sdev",
    .handler = handler,
    .ioctl = ioctl,
    .run_from_softirq_context = false,
};

static int vhost_sdev_init(void)
{
    bool res;
    
    mtrace("module hsdev up");

    res = vhost_register(&vdev_sdev);
    trace("vhost_register: %d", res);
    if (!res) {
        etrace("vhost_register failed");
        return -EPERM;
    }

    initialize();
    return 0;
}

static void vhost_sdev_exit(void)
{
    mtrace("module hsdev down");
    free_all();    
    vhost_unregister(&vdev_sdev);
}

module_init(vhost_sdev_init);
module_exit(vhost_sdev_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Yossi Kuperman");
