#if 1 /* patchouli vrio-generic-module */
#ifndef _GENERIC_H
#define _GENERIC_H

#include "vrio_common.h"

#define IOCTL_CHECKSUM 0

struct ioctl_create {
    char device_path[256];
    ulong gsocket;
    ulong host_priv;
    unsigned char host_port;

    ulong guest_priv;
    unsigned char guest_port;

    union {
        struct vrio_blk_config vrio_blk;
        struct vrio_net_config vrio_net;
    } config;
};

struct ioctl_remove {
    int device_id;
    uint device_uid;
};

struct ioctl_poll {
    int nr_iocores;
    int iocores[32];
};

struct ioctl_iocore {
    int nr_iocores;
    int iocores[32];
};

struct ioctl_sdev {
    int size;
    int operation;
    int flags;
    int duration;
    int udelay;
    int nr_iov;
};

struct ioctl_param {    
    char device_name[32];
    char interface_name[32];
    char guest_mac_address[6];
    uint cmd;

    union {
        struct ioctl_create create;
        struct ioctl_remove remove;        
        struct ioctl_poll   poll;
        struct ioctl_iocore iocore;

        struct ioctl_sdev sdev;
    } x;

#if IOCTL_CHECKSUM
    ulong checksum;
#endif
};

#if IOCTL_CHECKSUM
__maybe_unused static ulong calc_checksum(struct ioctl_param *param) {
    int i;
    ulong checksum = 0;
    ulong *ptr = (ulong *)param;

    param->checksum = 0;
    for (i=0; i<sizeof(struct ioctl_param) / sizeof(ulong); i++) {
          checksum += *ptr;
    }
    
    return checksum;
}
#endif

#define GENERIC_MAGIC           'g'

#define GENERIC_IOCTL_CREATE    _IOWR(GENERIC_MAGIC, 1, int)
#define GENERIC_IOCTL_REMOVE    _IOWR(GENERIC_MAGIC, 2, int)
#define GENERIC_IOCTL_POLL      _IOWR(GENERIC_MAGIC, 3, int)
#define GENERIC_IOCTL_IOCORE    _IOWR(GENERIC_MAGIC, 4, int)
#define GENERIC_IOCTL_CHANNEL   _IOWR(GENERIC_MAGIC, 5, int)
#define GENERIC_IOCTL_GENERIC   _IOWR(GENERIC_MAGIC, 6, int)
#define GENERIC_SANITY_CHECK    _IOWR(GENERIC_MAGIC, 7, int)

#define VRIO_IOCTL_CREATE_BLK   1
#define VRIO_IOCTL_CREATE_NET   2
#define VRIO_IOCTL_REMOVE_DEV   3
#define VRIO_IOCTL_HOST         4

#define VRIO_IOCTL_CREATE_SDEV  5
#define VRIO_IOCTL_REQUEST_SDEV 6

#define VRIO_IOCTL_SANITY_CHECK 7


#endif /* _GENERIC_H */
#endif
