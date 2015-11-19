#if 1 /* patchouli vrio-generic-module */
#ifndef __GENERIC_H
#define __GENERIC_H

#include "generic_common.h"
#include <linux/vrio/cqueue.h>

/* only for optimization */
#include <linux/vrio/eth.h>

#define MAX_ETH_COUNT 32
#define MAX_IO_CORES 32

struct l2socket;
struct gsocket;
struct gwork_struct;

typedef void (*gwork_handler)(ulong param1, ulong param2);
typedef void (*gwork_func_t)(struct gwork_struct *gwork);

struct giovec {
    size_t iov_len;
    struct iovec *iov;
    
    unsigned char data[64];
};

struct vdev {
    struct list_head link;
        
    char name[32];
    gwork_handler handler;
    long (*ioctl) (struct ioctl_param *ioctl_param); 
    bool run_from_softirq_context;

    struct device *fs_dev;
    struct l2socket *l2sockets[MAX_ETH_COUNT];
    int l2sockets_nr;
};

struct giocore {
    int affinity_core_id;            
    atomic_t iopackets;
};

struct gwork_struct {    
    struct cqueue_struct clink;
    gwork_func_t func;
};

static inline void init_gwork_func(struct gwork_struct *gwork, gwork_func_t func) {
    init_cqueue_elm(&gwork->clink);
    gwork->func = func;
}

bool vhost_register(struct vdev *vdev);
void vhost_unregister(struct vdev *vdev);

bool vdev_register(struct vdev *vdev);
void vdev_unregister(struct vdev *vdev);


static __always_inline int gsend_iov(struct gsocket *gsocket, struct iovec *iov, size_t iov_len) {
    return send_iov((struct bsocket *)gsocket, iov, iov_len);
}

static __always_inline int gsend_buff(struct gsocket *gsocket, char *buff, size_t length) {
    return send_buff((struct bsocket *)gsocket, buff, length);
}

static __always_inline int gsend_skb(struct gsocket *gsocket, struct sk_buff *skb) {
    return send_skb((struct bsocket *)gsocket, skb);
}

static __always_inline void gsend_raw_skb(struct gsocket *gsocket, struct sk_buff *skb) {
    send_raw_skb((struct bsocket *)gsocket, skb);
}

static __always_inline void gfree_packet(struct gsocket *gsocket, struct giovec* giovec) {
    free_packet((struct bsocket *)gsocket, (struct biovec *)giovec);
}

static __always_inline void gfree_gsocket(struct gsocket *gsocket) {
    kfree(gsocket);
}

static __always_inline struct sk_buff *gdetach_skb(struct giovec *giovec) {
    return detach_skb((struct biovec *)giovec);
}

static __always_inline struct sk_buff *giovec_to_skb(struct net_device *dev,
                              struct iovec *iov,
                              size_t iov_len,
                              struct skb_frag_destructor *destroy) {
    return iovec_to_skb(dev, iov, iov_len, destroy);
}

static __always_inline int zgsend_iov(struct gsocket *gsocket, struct iovec *iov, size_t iov_len, struct skb_frag_destructor *destroy) {
    return zbsend_iov((struct bsocket *)gsocket, iov, iov_len, destroy);
}

bool queue_gwork(struct gsocket *gsocket, struct gwork_struct *gwork);

void fs_device_file_create(struct device *fs_dev, struct dev_ext_attribute *attr);
void fs_device_file_remove(struct device *fs_dev, struct dev_ext_attribute *attr);


// For debug only
void trace_gsocket(struct gsocket *gsocket);

#endif /* ___GENERIC_H */
#endif
