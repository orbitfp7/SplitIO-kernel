#if 1 /* patchouli vrio */
#ifndef _VRIO_COMMON_H
#define _VRIO_COMMON_H

#ifndef __KERNEL__
#define BIT_WORD(nr)      ((nr) / BITS_PER_LONG)
#define BITS_PER_BYTE     8
#define BITS_PER_LONG     (sizeof(long) * BITS_PER_BYTE)
#define BIT_MASK(nr)      (1UL << ((nr) % BITS_PER_LONG))
 
/* TODO: Not atomic as it should be:
  * we don't use this for anything important. */
static inline void clear_bit(int nr, volatile unsigned long *addr) {
    unsigned long mask = BIT_MASK(nr);        
    unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);        
    *p &= ~mask;
}

static inline int test_bit(int nr, const volatile unsigned long *addr) {
    return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
}

struct list_head {
    struct list_head *next, *prev;
};
#endif

/* The feature bitmap for virtio blk */
#define VIRTIO_BLK_F_BARRIER    0       /* Does host support barriers? */
#define VIRTIO_BLK_F_SIZE_MAX   1       /* Indicates maximum segment size */
#define VIRTIO_BLK_F_SEG_MAX    2       /* Indicates maximum # of segments */
#define VIRTIO_BLK_F_GEOMETRY   4       /* Legacy geometry available  */
#define VIRTIO_BLK_F_RO         5       /* Disk is read-only */
#define VIRTIO_BLK_F_BLK_SIZE   6       /* Block size of disk is available*/
#define VIRTIO_BLK_F_SCSI       7       /* Supports scsi command passthru */
#define VIRTIO_BLK_F_WCE        9       /* Writeback mode enabled after reset */
#define VIRTIO_BLK_F_TOPOLOGY   10      /* Topology information is available */
#define VIRTIO_BLK_F_CONFIG_WCE 11      /* Writeback mode available in config */

/* The feature bitmap for virtio net */
#define VIRTIO_NET_F_CSUM	0	/* Host handles pkts w/ partial csum */
#define VIRTIO_NET_F_GUEST_CSUM	1	/* Guest handles pkts w/ partial csum */
#define VIRTIO_NET_F_MAC	5	/* Host has given MAC address. */
#define VIRTIO_NET_F_GSO	6	/* Host handles pkts w/ any GSO type */
#define VIRTIO_NET_F_GUEST_TSO4	7	/* Guest can handle TSOv4 in. */
#define VIRTIO_NET_F_GUEST_TSO6	8	/* Guest can handle TSOv6 in. */
#define VIRTIO_NET_F_GUEST_ECN	9	/* Guest can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_GUEST_UFO	10	/* Guest can handle UFO in. */
#define VIRTIO_NET_F_HOST_TSO4	11	/* Host can handle TSOv4 in. */
#define VIRTIO_NET_F_HOST_TSO6	12	/* Host can handle TSOv6 in. */
#define VIRTIO_NET_F_HOST_ECN	13	/* Host can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_HOST_UFO	14	/* Host can handle UFO in. */
#define VIRTIO_NET_F_MRG_RXBUF	15	/* Host can merge receive buffers. */
#define VIRTIO_NET_F_STATUS	16	/* virtio_net_config.status available */
#define VIRTIO_NET_F_CTRL_VQ	17	/* Control channel available */
#define VIRTIO_NET_F_CTRL_RX	18	/* Control channel RX mode support */
#define VIRTIO_NET_F_CTRL_VLAN	19	/* Control channel VLAN filtering */
#define VIRTIO_NET_F_CTRL_RX_EXTRA 20	/* Extra RX mode control support */
#define VIRTIO_NET_F_GUEST_ANNOUNCE 21	/* Guest can announce device on the
                     * network */
#define VIRTIO_NET_F_MQ	22	/* Device supports Receive Flow
                     * Steering */
#define VIRTIO_NET_F_CTRL_MAC_ADDR 23	/* Set MAC address */

#define VIRTIO_NET_S_LINK_UP	1	/* Link is up */
#define VIRTIO_NET_S_ANNOUNCE	2	/* Announcement is needed */

struct vrio_blk_config {
    ulong features;
    uint64_t capacity;
    uint32_t blk_size;
    uint32_t seg_max;

    struct vrio_blk_geometry {
        uint16_t cylinders;                 
        uint8_t heads;                 
        uint8_t sectors;
    } geometry;

    uint8_t wce;
};

struct vrio_net_config {    
    ulong features;
    /* The config defining mac address (if VIRTIO_NET_F_MAC) */
    __u8 mac[6];
    /* See VIRTIO_NET_F_STATUS and VIRTIO_NET_S_* above */
    __u16 status;
};

#endif /* _VRIO_COMMON_H */
#endif
