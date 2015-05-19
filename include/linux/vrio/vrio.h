#if 1 /* patchouli vrio */
#ifndef _VRIO_H
#define _VRIO_H

#include "vrio_common.h"

#define VRIO_HEADER_SIZE  (sizeof(struct vrio_header))
#define VRIO_HEADER_DEBUG 0

struct vrio_device {    
    struct list_head link;

    ulong features;
    uint device_uid;

    void *config;
    void *priv;

    struct gsocket *gsocket;
    ulong host_priv;

    union {
        struct vrio_blk_config vrio_blk_config;
        struct vrio_net_config vrio_net_config;
    } placeholder;
};

struct vrio_header {
    ulong host_priv;
    ulong guest_priv;
    int id;
    int out_len;
    int in_len;
#if VRIO_HEADER_DEBUG
    ulong checksum;
#endif
};

#if VRIO_HEADER_DEBUG
static ulong calc_vrio_checksum(struct iovec *iov, int iov_len) {
    int i, j;
    char *ptr;
    int index = 0;    
    ulong checksum = 0;

    for(i=0; i<iov_len; i++) {
        for (j=0; j<iov[i].iov_len; j++) {
            checksum += ((uchar *)iov[i].iov_base)[j] * (index++);
        }
    }

    return checksum;
}

static ulong calc_vrio_checksum_skb(struct sk_buff *skb) {
    struct scatterlist sg[MAX_SKB_FRAGS + 2];
    struct iovec iov[64];
    int num, i;
        
    num = skb_to_sgvec(skb, sg, 0, skb->len);
    for (i=0; i<num; i++) {
        iov[i].iov_base = sg_virt(&sg[i]);
        iov[i].iov_len = sg[i].length;        
    }

    return calc_vrio_checksum(iov, num);
}

static bool is_vrio_checksum_valid(struct iovec *iov, int iov_len) {
    struct vrio_header *vhdr;
    ulong checksum;

    vhdr = (struct vrio_header *)iov[0].iov_base;
    checksum = vhdr->checksum;
    vhdr->checksum = 0;
    return (checksum == calc_vrio_checksum(iov, iov_len));
}
#endif

static inline bool vrio_has_feature(struct vrio_device *vdev, ulong feature) {
    return (bool)test_bit(feature, &vdev->features);
}

#define vrio_config_val(vdev, feature, offset, v) \
        vrio_config_buf((vdev), (feature), (offset), (v), sizeof(*v))

#define vrio_config_val_len(vdev, feature, offset, v, len) \
        vrio_config_buf((vdev), (feature), (offset), (v), (len))

#define __vrio_config_val(vdev, offset, v) \
        vrio_config_buf((vdev), 0, (offset), (v), sizeof(*v))

static __maybe_unused int vrio_config_buf(struct vrio_device *vdev, ulong feature, uint offset, 
                     void *buf, uint len) {
                         
    if (feature != 0 && !vrio_has_feature(vdev, feature)) {
        return -ENOENT;
    }

    memcpy(buf, vdev->config + offset, len);
    return 0;
}

static __maybe_unused void vrio_set_config_val(struct vrio_device *vdev, uint offset, 
                     void *buf, uint len) {
                         
    memcpy(vdev->config + offset, buf, len);
}

#define list_entry_at_index(i, pos, head, member)    \
        {   int __index = i;                         \
            list_for_each_entry(pos, head, member) { \
                __index--;                           \
                if (__index == 0) break;             \
            }                                        \
            if (__index)                             \
                pos = NULL;                          \
        }

#endif /* _VRIO_H */
#endif
