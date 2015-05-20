#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_net.h>
#include <linux/scatterlist.h>
#include <linux/if_vlan.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/tcp.h>
#include <linux/jiffies.h>

#define TRACE_LEVEL 3

#include <linux/vrio/trace.h>
#include <linux/vrio/generic.h>
#include <linux/vrio/utils.h>
#include <linux/vrio/vrio.h>
#include <linux/vrio/sdev.h>

#include <linux/vrio/l2socket.h>

TRACE_ALL;

#include <linux/vrio/lmempool.h>
#include <linux/vrio/cqueue.h>

#define MAX_OUTSTANDING_REQ 64

long seed = 0;

struct lmempool lmempool;

struct gsocket *gsocket = NULL;

atomic_t outstanding_req;

struct skb_frag_data {
    struct sdev_req *req;
};

struct sdev_req *alloc_req(void) 
{
    struct sdev_req *req;

    req = lmempool_alloc(&lmempool);
    if (req)
        atomic_inc(&outstanding_req);

    return req;
}

void free_req(struct sdev_req *req) 
{
    lmempool_free(&lmempool, req);        
    atomic_dec(&outstanding_req);
}

int destroy_skb_frag(struct skb_frag_destructor *destructor) {
    struct skb_frag_data *data = (struct skb_frag_data *)destructor->data;

    if (!(data->req->shdr.flags & SDEV_FLAGS_ACK_ON_WRITE)) {
        trace("destroy_skb_frag, lmempool_free");
        free_req(data->req);    
    }

    return 0;
}

void do_request(int operation, int size, int flags, int iov_segs) 
{
    struct skb_frag_destructor *destroy;
    struct skb_frag_data *data;
    struct sdev_req *req;
    int err;

    req = alloc_req();
    if (!req) {
        etrace("lmempool_alloc failed");
        return;
    }

    req->shdr.operation = operation;
    req->shdr.size = size;
    req->shdr.flags = flags;
    req->shdr.private = (ulong)req;
    req->shdr.checksum = 0;

    destroy = (struct skb_frag_destructor *)req->__destroy;
    init_frag_destructor(destroy, destroy_skb_frag);
    data = FRAG_DESTROY_DATA(destroy, struct skb_frag_data *);
    data->req = req;
 
    if (operation == SDEV_OPERATION_READ) {
        trace("sending read request");
        map_request_iov(req, 0, iov_segs);
        err = gsend_iov(gsocket, req->iov, req->nr_iov);
        atrace(err < 0);            
        free_req(req);    
    }
                     
    if (operation == SDEV_OPERATION_WRITE) {
        init_buffer(req->buffer, size, seed++);
        map_request_iov(req, size, iov_segs);
        if (flags & SDEV_FLAGS_CHECKSUM) {
            req->shdr.checksum = calc_sdev_checksum_buff(req->buffer, size);
            trace("checksum: %X", req->shdr.checksum);
        }

        if (flags & SDEV_FLAGS_WRITE_ZCOPY) {
            trace("sending write request, send-zero-copy (size: %d) (req: %lp)", size, req);
            err = zgsend_iov(gsocket, req->iov, req->nr_iov, destroy);
            atrace(err < 0);
        } else {
            trace("sending write request (size: %d) (req: %lp)", size, req);
            err = gsend_iov(gsocket, req->iov, req->nr_iov);
            atrace(err < 0);            
            free_req(req);
        }
   }
}

int do_request_thread(void *data) { 
    struct ioctl_param *local_param = data;
    unsigned long je = jiffies_to_msecs(jiffies) + local_param->x.sdev.duration * 1000;
    int nr_requests = 0;
    mtrace("do_request_thread start (duration: %ds)", local_param->x.sdev.duration);
    while (jiffies_to_msecs(jiffies) <= je) {
        do_request(local_param->x.sdev.operation, 
                   local_param->x.sdev.size,
                   local_param->x.sdev.flags,
                   local_param->x.sdev.nr_iov);

        usleep_range(local_param->x.sdev.udelay, local_param->x.sdev.udelay+10);

//        if (unlikely(need_resched()))
//            schedule();
        nr_requests++;
    }

    mtrace("done (reqs: %d) (operation: %d, size: %d, flags: %d, nr_iov: %d, duration: %ds)", 
                   nr_requests,
                   local_param->x.sdev.operation, 
                   local_param->x.sdev.size,
                   local_param->x.sdev.flags,
                   local_param->x.sdev.nr_iov,
                   local_param->x.sdev.duration);
    kfree(local_param);
    return 0;
}

long ioctl(struct ioctl_param *local_param) {
    struct ioctl_param *lparam;
    
    switch (local_param->cmd) {
        case VRIO_IOCTL_CREATE_SDEV: { 
            mtrace("ioctl VRIO_IOCTL_CREATE_SDEV");

            if (gsocket)
                gfree_gsocket(gsocket);

            gsocket = (struct gsocket *)local_param->x.create.gsocket;
            break;
        }
        case VRIO_IOCTL_REQUEST_SDEV: { 
            trace("ioctl VRIO_IOCTL_REQUEST_SDEV");
            if (!gsocket) {
                etrace("No device initialized");
                break;
            }

            lparam = (struct ioctl_param *)kmalloc(sizeof(struct ioctl_param), GFP_KERNEL);
            *lparam = *local_param;
            kthread_run(do_request_thread, lparam, "do-req");
            break;
        } 
        case VRIO_IOCTL_SANITY_CHECK: {
            mtrace("ioctl VRIO_IOCTL_SANITY_CHECK");
            mtrace("outstanding_req: %d", atomic_read(&outstanding_req));
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
    struct sdev_header *shdr;
    struct sdev_req *req;
    struct gsocket *gsocket = (struct gsocket *)param1;
    struct giovec *giovec = (struct giovec *)param2;
    int res, i;

    atrace(giovec->iov[0].iov_len < SDEV_HEADER_SIZE, return);

    shdr = (struct sdev_header *)giovec->iov[0].iov_base;
    req = (struct sdev_req *)shdr->private;
    giovec->iov[0].iov_base += SDEV_HEADER_SIZE;
    giovec->iov[0].iov_len -= SDEV_HEADER_SIZE;
    
    if ((shdr->flags & SDEV_FLAGS_CHECKSUM) && 
        !is_sdev_checksum_valid(giovec->iov, giovec->iov_len, shdr->checksum)) {
        etrace("sdev checksum mismatch");
        gfree_packet(gsocket, giovec);
        return;
    }

    trace("request size: %d", shdr->size);
    if (shdr->operation == SDEV_OPERATION_ACK) {
        trace("received ack operation (req: %lp)", req);
        free_req(req);    
    }
    if (shdr->operation == SDEV_OPERATION_READ) {
        trace("received read operation");        
    }

    gfree_packet(gsocket, giovec);
}

static void initialize(void)
{
    if (init_lmempool(&lmempool, MAX_OUTSTANDING_REQ, sizeof(struct sdev_req)) == false) {
        etrace("init_mempool failed");
        return;
    }

    atomic_set(&outstanding_req, 0);
}

static void free_all(void)
{
    done_lmempool(&lmempool);

    gfree_gsocket(gsocket);
}

static struct vdev vdev_sdev = {
    .name = "sdev",
    .handler = handler,
    .ioctl = ioctl,
    .run_from_softirq_context = true,
};

static int __init init(void)
{
    bool res;
    
    mtrace("module gsdev up");

    res = vdev_register(&vdev_sdev);
    trace("vdev_register: %d", res);
    if (!res) {
        etrace("vdev_register failed");
        return -EPERM;
    }

    initialize();

    return 0;
}

static void __exit fini(void)
{
    mtrace("module gsdev down");
    
    free_all();
    vdev_unregister(&vdev_sdev);
}

module_init(init);
module_exit(fini);

MODULE_DESCRIPTION("vRIO gsdev driver");
MODULE_LICENSE("GPL");
