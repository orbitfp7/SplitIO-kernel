#if 1 /* patchouli vrio-net-module */
/* A network driver using virtio.
 *
 * Copyright 2007 Rusty Russell <rusty@rustcorp.com.au> IBM Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
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

#include <linux/vrio/trace.h>
#include <linux/vrio/generic.h>
#include <linux/vrio/utils.h>
#include <linux/vrio/vrio.h>

#include <linux/vrio/l2socket.h>

TRACE_ALL;

#include <linux/vrio/cqueue.h>

//static int skb_queue_size = 1024;

static int XMIT_WEIGHT = 0x40000; // 0x20000; 
module_param(XMIT_WEIGHT, int, S_IRUGO);

static int napi_weight = 128;
module_param(napi_weight, int, 0444);

static bool csum = true, gso = true;
module_param(csum, bool, 0444);
module_param(gso, bool, 0444);

#if TRACE_DEBUG
int is_using_rdtsc = 0;
module_param(is_using_rdtsc, int, S_IWUSR | S_IRUGO);

long rx_work_cycles = 0;
module_param(rx_work_cycles, long, S_IWUSR | S_IRUGO);
#endif

/* FIXME: MTU in config. */
#define MAX_PACKET_LEN (ETH_HLEN + VLAN_HLEN + ETH_DATA_LEN)
#define GOOD_COPY_LEN  L2_GNET_GOOD_COPY

#define VIRTNET_SEND_COMMAND_SG_MAX    2

#define VRIONET_DRIVER_NAME    "vRIO"
#define VRIONET_DRIVER_VERSION "1.0.0"

struct list_head devices_list;

struct virtnet_stats {
    struct u64_stats_sync tx_syncp;
    struct u64_stats_sync rx_syncp;
    u64 tx_bytes;
    u64 tx_packets;

    u64 rx_bytes;
    u64 rx_packets;
};

struct vrionet_info {
    int MAGIC;
    struct vrio_device *vdev;
    struct net_device *dev;
    unsigned int status;

    struct gwork_struct tx_work;
    struct sk_buff_head tx_packet_queue;

    int netif_flag;

    /* Max # of queue pairs supported by the device */
    u16 max_queue_pairs;

    /* # of queue pairs currently used by the driver */
    u16 curr_queue_pairs;

    /* I like... big packets and I cannot lie! */
    bool big_packets;

    /* Host will merge rx buffers for big packets (shake it! shake it!) */
    bool mergeable_rx_bufs;

    /* Active statistics */
    struct virtnet_stats __percpu *stats;

    /* TX: fragments + linear part + virtio header */
    struct scatterlist sg[MAX_SKB_FRAGS + 2];
    struct iovec iov[MAX_SKB_FRAGS + 2 + 1];
};

static __always_inline int skb_from_vnet_hdr(struct sk_buff *skb, struct virtio_net_hdr *vnet_hdr)
{
    unsigned short gso_type = 0;
    if (vnet_hdr->gso_type != VIRTIO_NET_HDR_GSO_NONE) {
        switch (vnet_hdr->gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {
        case VIRTIO_NET_HDR_GSO_TCPV4:
            trace("VIRTIO_NET_HDR_GSO_TCPV4");
            gso_type = SKB_GSO_TCPV4;
            break;
        case VIRTIO_NET_HDR_GSO_TCPV6:
            trace("VIRTIO_NET_HDR_GSO_TCPV6");
            gso_type = SKB_GSO_TCPV6;
            break;
        case VIRTIO_NET_HDR_GSO_UDP:
            trace("VIRTIO_NET_HDR_GSO_UDP");
            gso_type = SKB_GSO_UDP;
            break;
        default:
            return -EINVAL;
        }

        if (vnet_hdr->gso_type & VIRTIO_NET_HDR_GSO_ECN)
            gso_type |= SKB_GSO_TCP_ECN;

        if (vnet_hdr->gso_size == 0)
            return -EINVAL;
    }
     
    trace("csum_start: %d, csum_offset: %d, skb->len: %d, skb_headroom(skb): %d, skb_headlen(skb): %d", 
                vnet_hdr->csum_start, vnet_hdr->csum_offset, skb->len, skb_headroom(skb), skb_headlen(skb));
    if (vnet_hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
        if (!skb_partial_csum_set(skb, vnet_hdr->csum_start,
                      vnet_hdr->csum_offset)) {
            etrace("skb_partial_csum_set failed: csum_start: %d, csum_offset: %d", 
                vnet_hdr->csum_start, vnet_hdr->csum_offset);
            return -EINVAL;
        }
    } else if (vnet_hdr->flags & VIRTIO_NET_HDR_F_DATA_VALID) {
        skb->ip_summed = CHECKSUM_UNNECESSARY;
        trace("CHECKSUM_UNNECESSARY");
    }


    if (vnet_hdr->gso_type != VIRTIO_NET_HDR_GSO_NONE) {
        skb_shinfo(skb)->gso_size = vnet_hdr->gso_size;
        skb_shinfo(skb)->gso_type = gso_type;

        /* Header must be checked, and gso_segs computed. */
        skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
        skb_shinfo(skb)->gso_segs = 0;
    }

    trace("skb_shinfo(skb)->gso_size: %d", skb_shinfo(skb)->gso_size);
    return 0;
}

static __always_inline struct virtio_net_hdr *skb_vnet_hdr(struct sk_buff *skb)
{
    return (struct virtio_net_hdr *)skb->cb;
}

struct skb_frag_data {
    struct gsocket *gsocket;
    struct giovec *giovec;
};

int destroy_skb_frag(struct skb_frag_destructor *destructor) {
    struct skb_frag_data *data = (struct skb_frag_data *)destructor->data;
    trace("destroy_skb_frag");

    gfree_packet(data->gsocket, data->giovec);
    return 0;
}

enum {
    VHOST_NET_TX_FREE_MEM = 0,
    VHOST_NET_TX_ZEROCOPY = 1,
};

static int receive_buf(struct vrionet_info *vi, struct giovec *giovec, unsigned int len)
{
    struct net_device *dev = vi->dev;
    struct virtnet_stats *stats = this_cpu_ptr(vi->stats);
    struct sk_buff *skb = NULL;
    struct virtio_net_hdr hdr;
    int res = VHOST_NET_TX_FREE_MEM;
    int ret;

#if TRACE_DEBUG
    long s_cycles;
        
    if (is_using_rdtsc)
        s_cycles = get_cycles();
#endif

    if (unlikely(len < sizeof(struct virtio_net_hdr) + ETH_HLEN)) {
        etrace("%s: short packet %i", dev->name, len);
        dev->stats.rx_length_errors++;
        return res; 
    }

#if L2_RECEIVE_SKB
    trace("L2_RECEIVE_SKB");
    skb = gdetach_skb(giovec);
    if (likely(skb)) {
        trace("gdetach_skb returned skb");

//        mtrace("skb_headlen: %d", skb_headlen(skb));
        memcpy((unchar *)&hdr, skb->data, sizeof(struct virtio_net_hdr));
        skb_pull(skb, sizeof(struct virtio_net_hdr));
        if (skb_headlen(skb) < 54) /* 14 + 20 + 20 */
            __pskb_pull_tail(skb, 54 - skb_headlen(skb));

        skb->dev = vi->dev;
    }
#endif

    if (unlikely(!skb)) {
        struct skb_frag_data *data;
        struct skb_frag_destructor *destroy = (struct skb_frag_destructor *)giovec->data;
        
        init_frag_destructor(destroy, destroy_skb_frag);
        data = FRAG_DESTROY_DATA(destroy, struct skb_frag_data *);
        data->gsocket = vi->vdev->gsocket;
        data->giovec = giovec;

        ret = memcpy_fromiovecend_skip((unchar *)&hdr, giovec->iov, giovec->iov_len, sizeof(struct virtio_net_hdr));
        atrace(ret != 0, goto out_err);
        skb = giovec_to_skb(vi->dev, giovec->iov, giovec->iov_len, destroy);
        res = VHOST_NET_TX_ZEROCOPY;

//        skb = giovec_to_skb(vi, giovec, len);
        if (unlikely(!skb)) {
out_err:
            etrace("giovec_to_skb returns NULL");
            dev->stats.rx_dropped++;
            return res;
        }

//        if (skb_shinfo(skb)->nr_frags) {
//            res = VHOST_NET_TX_ZEROCOPY;
//        }
    }
//    hdr = skb_vnet_hdr(skb);

    u64_stats_update_begin(&stats->rx_syncp);
    stats->rx_bytes += skb->len;
    stats->rx_packets++;
    u64_stats_update_end(&stats->rx_syncp);

    if (skb_from_vnet_hdr(skb, &hdr))
        goto frame_err;

    skb->protocol = eth_type_trans(skb, dev);
    trace("Receiving skb proto 0x%04x len %i type %i",
         ntohs(skb->protocol), skb->len, skb->pkt_type);

#if TRACE_DEBUG
    if (is_using_rdtsc)
        rx_work_cycles = get_cycles() - s_cycles;
#endif

    netif_receive_skb(skb);
    return res;

frame_err:
    dev->stats.rx_frame_errors++;
    dev_kfree_skb(skb);
    return res;
}

static int virtnet_open(struct net_device *dev)
{
    trace("virtnet_open");

    return 0;
}

static __always_inline int virtnet_add_buf(struct vrionet_info *vi, unsigned int out) {
    struct vrio_header vhdr;
    int iov_len = 1;
    int i;
    int ret;
    trace("virtnet_add_buf");
    trace("out: %d", out);

    vhdr.host_priv = vi->vdev->host_priv;
    vhdr.guest_priv = (ulong)vi;
    vhdr.out_len = vhdr.in_len = 0;

    vi->iov[0].iov_base = &vhdr;
    vi->iov[0].iov_len = sizeof(struct vrio_header);

    for (i=0; i<out ; ++i) {
        vhdr.out_len += vi->sg[i].length;
        vi->iov[iov_len].iov_base = sg_virt(&vi->sg[i]);
        vi->iov[iov_len].iov_len = vi->sg[i].length;
        trace("- iov_base(%d/%d/%lp): %.*b", i, vi->sg[i].length, vi->iov[iov_len].iov_base, vi->iov[iov_len].iov_len, vi->iov[iov_len].iov_base);
        iov_len++;
    }        

#if VRIO_HEADER_DEBUG
    vhdr.checksum = 0;
    vhdr.checksum = calc_vrio_checksum(vi->iov, iov_len);
#endif

    ret = gsend_iov(vi->vdev->gsocket, vi->iov, iov_len);    
    trace("gsend_iov: %d", ret);
    //mtrace("tx_psize: %d", ret);
    //atrace(ret <= 0, etrace("ret: %d", ret));
    return ret;
}

static __always_inline void skb_to_vnet_hdr(struct sk_buff *skb, struct virtio_net_hdr *hdr)
{
    if (skb->ip_summed == CHECKSUM_PARTIAL) {
        trace("CHECKSUM_PARTIAL");
        hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
        hdr->csum_start = skb_checksum_start_offset(skb);
        hdr->csum_offset = skb->csum_offset;
        trace("hdr->hdr.csum_start: %d", hdr->csum_start);
        trace("hdr->hdr.csum_offset: %d", hdr->csum_offset);
    } else {
        trace("! CHECKSUM_PARTIAL");
        hdr->flags = 0;
        hdr->csum_offset = hdr->csum_start = 0;
    }

    if (skb_is_gso(skb)) {
        trace("skb_is_gso(skb), skb_shinfo(skb)->gso_size: %d, skb_headlen(skb): %d", skb_shinfo(skb)->gso_size, skb_headlen(skb));
        hdr->hdr_len = skb_headlen(skb);
        hdr->gso_size = skb_shinfo(skb)->gso_size;
        if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4)
            hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
        else if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV6)
            hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
        else if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP)
            hdr->gso_type = VIRTIO_NET_HDR_GSO_UDP;
        else
            BUG();
        if (skb_shinfo(skb)->gso_type & SKB_GSO_TCP_ECN)
            hdr->gso_type |= VIRTIO_NET_HDR_GSO_ECN;
    } else {
        trace("VIRTIO_NET_HDR_GSO_NONE");
        hdr->gso_type = VIRTIO_NET_HDR_GSO_NONE;
        hdr->gso_size = hdr->hdr_len = 0;
    }
}

static __always_inline int xmit_skb(struct vrionet_info *vi, struct sk_buff *skb)
{
    struct virtio_net_hdr *hdr = skb_vnet_hdr(skb);
#if TRACE_DEBUG
    const unsigned char *dest = ((struct ethhdr *)skb->data)->h_dest;
#endif    
    unsigned num_sg;

    trace("%s: xmit %p %pM", vi->dev->name, skb, dest);

    //skb_to_vnet_hdr(skb, &hdr->hdr);
    //hdr->mhdr.num_buffers = 0;

    /* Encode metadata header at front. */
//    if (vi->mergeable_rx_bufs)
//        sg_set_buf(vi->sg, &hdr->mhdr, sizeof hdr->mhdr);
//    else
    sg_set_buf(vi->sg, hdr, sizeof(struct virtio_net_hdr));

    num_sg = skb_to_sgvec(skb, vi->sg + 1, 0, skb->len) + 1;
    return virtnet_add_buf(vi, num_sg);
}

void print_skb(struct sk_buff *skb);

static __always_inline void start_xmit_skb(struct sk_buff *skb, struct net_device *dev)
{
    struct vrionet_info *vi = netdev_priv(dev);
    struct virtnet_stats *stats = this_cpu_ptr(vi->stats);
    int err;

    trace("start_xmit_skb");
    trace("skb->len: %d, skb->data_len: %d", skb->len, skb->data_len);

    trace("skb->protocol: %d, eth_hdr(skb)->h_proto: %d", skb->protocol, eth_hdr(skb)->h_proto);

    /* Try to transmit */
   err = xmit_skb(vi, skb);

    /* This should not happen! */
    if (unlikely(err <= 0)) {
        dev->stats.tx_fifo_errors++;
        if (err != -EAGAIN)
            etrace("Unexpected TXQ (%d) queue failure: %d", 0, err);
        dev->stats.tx_dropped++;
        kfree_skb(skb);
        return;
    }

    u64_stats_update_begin(&stats->tx_syncp);
    stats->tx_bytes += skb->len;
    stats->tx_packets++;
    u64_stats_update_end(&stats->tx_syncp);

    kfree_skb(skb);
    return;
}

#if L2_SEND_SKB_DIRECTLY
static netdev_tx_t start_xmit(struct sk_buff *skb, struct net_device *dev) 
{
    struct vrionet_info *vi = netdev_priv(dev);
    struct virtnet_stats *stats = this_cpu_ptr(vi->stats);
    struct virtio_net_hdr hdr; 
    struct vrio_header *vhdr;
    int err;
        
    trace("start_xmit");

    trace("skb_headroom(skb): %d", skb_headroom(skb));
    if (skb_headroom(skb) < sizeof(struct virtio_net_hdr)) {
        etrace("freeing skb, skb_headroom lacks header space");
        kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    /* Don't wait up for transmitted skbs to be freed. */
    skb_orphan(skb);
    nf_reset(skb);

    skb_to_vnet_hdr(skb, &hdr);
    
//    skb = dup_skb(skb);
/*          
    if (skb_shinfo(skb)->nr_frags) {
        trace("skb->len: %d", skb->len);
        trace("original skb data(%d/%d): %.*b", skb_headlen(skb), skb_shinfo(skb)->nr_frags, skb_headlen(skb), skb->data);
        cskb = ypskb_copy(skb, GFP_ATOMIC);
        kfree_skb(skb);
        trace("cskb->len: %d", cskb->len);
        trace("copy skb data(%d/%d): %.*b", skb_headlen(cskb), skb_shinfo(cskb)->nr_frags, skb_headlen(cskb), cskb->data);

        skb = cskb;
    }
*/

    trace("%s: xmit %p %pM", vi->dev->name, skb, ((struct ethhdr *)skb->data)->h_dest);
    memcpy(skb_push(skb, sizeof(struct virtio_net_hdr)), 
           &hdr, 
           sizeof(struct virtio_net_hdr));

    vhdr = (struct vrio_header *)skb_push(skb, sizeof(struct vrio_header));
    vhdr->host_priv = vi->vdev->host_priv;
    vhdr->guest_priv = (ulong)vi;
    vhdr->out_len = skb->len - sizeof(struct vrio_header);
    vhdr->in_len = 0;

#if VRIO_HEADER_DEBUG
    vhdr->checksum = 0;
    vhdr->checksum = calc_vrio_checksum_skb(skb);
#endif

    err = gsend_skb(vi->vdev->gsocket, skb);

    /* This should not happen! */
    if (unlikely(err <= 0)) {
        dev->stats.tx_fifo_errors++;
        etrace("Unexpected TXQ (%d) queue failure: %d", 0, err);
        dev->stats.tx_dropped++;
        return NETDEV_TX_OK;
    }

    u64_stats_update_begin(&stats->tx_syncp);
    stats->tx_bytes += skb->len;
    stats->tx_packets++;
    u64_stats_update_end(&stats->tx_syncp);

    return NETDEV_TX_OK;
}
#else

static netdev_tx_t start_xmit(struct sk_buff *skb, struct net_device *dev) 
{
    struct vrionet_info *vi = netdev_priv(dev);
    bool ret;

    trace("start_xmit");

    /* Don't wait up for transmitted skbs to be freed. */
    skb_orphan(skb);
    nf_reset(skb);

    skb_to_vnet_hdr(skb, skb_vnet_hdr(skb));

    start_xmit_skb(skb, dev);
    return NETDEV_TX_OK;
}
#endif

static int virtnet_set_mac_address(struct net_device *dev, void *p)
{
    trace("virtnet_set_mac_address");
    return -EINVAL;
}

static struct rtnl_link_stats64 *virtnet_stats(struct net_device *dev,
                           struct rtnl_link_stats64 *tot)
{
    struct vrionet_info *vi = netdev_priv(dev);
    int cpu;
    unsigned int start;
//    trace("virtnet_stats");

    for_each_possible_cpu(cpu) {
        struct virtnet_stats *stats = per_cpu_ptr(vi->stats, cpu);
        u64 tpackets, tbytes, rpackets, rbytes;

        do {
            start = u64_stats_fetch_begin_bh(&stats->tx_syncp);
            tpackets = stats->tx_packets;
            tbytes   = stats->tx_bytes;
        } while (u64_stats_fetch_retry_bh(&stats->tx_syncp, start));

        do {
            start = u64_stats_fetch_begin_bh(&stats->rx_syncp);
            rpackets = stats->rx_packets;
            rbytes   = stats->rx_bytes;
        } while (u64_stats_fetch_retry_bh(&stats->rx_syncp, start));

        tot->rx_packets += rpackets;
        tot->tx_packets += tpackets;
        tot->rx_bytes   += rbytes;
        tot->tx_bytes   += tbytes;
    }

    tot->tx_dropped = dev->stats.tx_dropped;
    tot->tx_fifo_errors = dev->stats.tx_fifo_errors;
    tot->rx_dropped = dev->stats.rx_dropped;
    tot->rx_length_errors = dev->stats.rx_length_errors;
    tot->rx_frame_errors = dev->stats.rx_frame_errors;

    return tot;
}

static int virtnet_close(struct net_device *dev)
{
    trace("virtnet_close");
    return 0;
}

static void virtnet_set_rx_mode(struct net_device *dev)
{
    trace("virtnet_set_rx_mode");
}

static int virtnet_vlan_rx_add_vid(struct net_device *dev, __be16 proto, u16 vid)
{
    trace("virtnet_vlan_rx_add_vid");
    return 0;
}

static int virtnet_vlan_rx_kill_vid(struct net_device *dev, __be16 proto, u16 vid)
{
    trace("virtnet_vlan_rx_kill_vid");    
    return 0;
}

static void virtnet_get_ringparam(struct net_device *dev,
                struct ethtool_ringparam *ring)
{
    ring->rx_max_pending = 101;
    ring->tx_max_pending = 101;
    ring->rx_pending = ring->rx_max_pending;
    ring->tx_pending = ring->tx_max_pending;
}

static void virtnet_get_drvinfo(struct net_device *dev,
                struct ethtool_drvinfo *info)
{
    strlcpy(info->driver, VRIONET_DRIVER_NAME, sizeof(info->driver));
    strlcpy(info->version, VRIONET_DRIVER_VERSION, sizeof(info->version));
}

/* TODO: Eliminate OOO packets during switching */
static int virtnet_set_channels(struct net_device *dev,
                struct ethtool_channels *channels)
{
    int err = 0;
    trace("virtnet_set_channels");

    return err;
}

static void virtnet_get_channels(struct net_device *dev,
                 struct ethtool_channels *channels)
{
    struct vrionet_info *vi = netdev_priv(dev);
    trace("virtnet_get_channels");

    channels->combined_count = vi->curr_queue_pairs;
    channels->max_combined = vi->max_queue_pairs;
    channels->max_other = 0;
    channels->rx_count = 0;
    channels->tx_count = 0;
    channels->other_count = 0;
}

static const struct ethtool_ops virtnet_ethtool_ops = {
    .get_drvinfo = virtnet_get_drvinfo,
    .get_link = ethtool_op_get_link,
    .get_ringparam = virtnet_get_ringparam,
    .set_channels = virtnet_set_channels,
    .get_channels = virtnet_get_channels,
};

#define MIN_MTU 68
#define MAX_MTU 65535

static int virtnet_change_mtu(struct net_device *dev, int new_mtu)
{
    trace("virtnet_change_mtu");

    if (new_mtu < MIN_MTU || new_mtu > MAX_MTU)
        return -EINVAL;
    dev->mtu = new_mtu;
    return 0;
}

/* To avoid contending a lock hold by a vcpu who would exit to host, select the
 * txq based on the processor id.
 */
static u16 virtnet_select_queue(struct net_device *dev, struct sk_buff *skb)
{
    trace("virtnet_select_queue");
    return 0;
}

static const struct net_device_ops virtnet_netdev = {
    .ndo_open            = virtnet_open,
    .ndo_stop   	     = virtnet_close,
    .ndo_start_xmit      = start_xmit,
    .ndo_validate_addr   = eth_validate_addr,
    .ndo_set_mac_address = virtnet_set_mac_address,
    .ndo_set_rx_mode     = virtnet_set_rx_mode,
    .ndo_change_mtu	     = virtnet_change_mtu,
    .ndo_get_stats64     = virtnet_stats,
    .ndo_vlan_rx_add_vid = virtnet_vlan_rx_add_vid,
    .ndo_vlan_rx_kill_vid = virtnet_vlan_rx_kill_vid,
    .ndo_select_queue     = virtnet_select_queue,
};

static int create_net_device(struct vrio_device *vdev)
{
    int err;
    struct net_device *dev;
    struct vrionet_info *vi;
    u16 max_queue_pairs;

    max_queue_pairs = 1;
    trace("max_queue_pairs: %d", max_queue_pairs);

    /* Allocate ourselves a network device with room for our info */
    dev = alloc_etherdev_mq(sizeof(struct vrionet_info), max_queue_pairs);
    if (!dev)
        return -ENOMEM;

    /* Set up network device as normal. */
    dev->priv_flags |= IFF_UNICAST_FLT | IFF_LIVE_ADDR_CHANGE;
    dev->netdev_ops = &virtnet_netdev;
    dev->features = NETIF_F_HIGHDMA;

    SET_ETHTOOL_OPS(dev, &virtnet_ethtool_ops);
//    SET_NETDEV_DEV(dev, &vdev->dev);

    /* Do we support "hardware" checksums? */
    if (vrio_has_feature(vdev, VIRTIO_NET_F_CSUM)) {
        trace("feature: VIRTIO_NET_F_CSUM");
        /* This opens up the world of extra features. */
        dev->hw_features |= NETIF_F_HW_CSUM|NETIF_F_SG|NETIF_F_FRAGLIST;
        if (csum)
            dev->features |= NETIF_F_HW_CSUM|NETIF_F_SG|NETIF_F_FRAGLIST;

        if (vrio_has_feature(vdev, VIRTIO_NET_F_GSO)) {
            trace("feature: VIRTIO_NET_F_GSO");
            dev->hw_features |= NETIF_F_TSO | NETIF_F_UFO
                | NETIF_F_TSO_ECN | NETIF_F_TSO6;
        }
        /* Individual feature bits: what can host handle? */
        if (vrio_has_feature(vdev, VIRTIO_NET_F_HOST_TSO4)) {
            trace("feature: VIRTIO_NET_F_HOST_TSO4");
            dev->hw_features |= NETIF_F_TSO;
        }
        if (vrio_has_feature(vdev, VIRTIO_NET_F_HOST_TSO6)) {
            trace("feature: VIRTIO_NET_F_HOST_TSO6");
            dev->hw_features |= NETIF_F_TSO6;
        }
        if (vrio_has_feature(vdev, VIRTIO_NET_F_HOST_ECN)) {
            trace("feature: VIRTIO_NET_F_HOST_ECN");
            dev->hw_features |= NETIF_F_TSO_ECN;
        }
        if (vrio_has_feature(vdev, VIRTIO_NET_F_HOST_UFO)) {
            trace("feature: VIRTIO_NET_F_HOST_UFO");
            dev->hw_features |= NETIF_F_UFO;
        }

        if (gso) {
            dev->features |= dev->hw_features & (NETIF_F_ALL_TSO|NETIF_F_UFO);
        }
        /* (!csum && gso) case will be fixed by register_netdev() */
    }

    /* Configuration may specify what MAC to use.  Otherwise random. */
    if (vrio_config_val_len(vdev, VIRTIO_NET_F_MAC,
                  offsetof(struct vrio_net_config, mac),
                  dev->dev_addr, dev->addr_len) < 0) {
        trace("feature: ! VIRTIO_NET_F_MAC - random MAC");
        eth_hw_addr_random(dev);
    }

    /* Set up our device-specific information */
    vi = netdev_priv(dev);
    vi->MAGIC = 0xAABBCCDD;
    vi->dev = dev;
    vi->vdev = vdev;
    vdev->priv = vi;
    vi->stats = alloc_percpu(struct virtnet_stats);
    err = -ENOMEM;
    if (vi->stats == NULL)
        goto free;

    /* If we can receive ANY GSO packets, we must allocate large ones. */
    if (vrio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO4) ||
        vrio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO6) ||
        vrio_has_feature(vdev, VIRTIO_NET_F_GUEST_ECN)) {
        trace("feature: (VIRTIO_NET_F_GUEST_TSO4 || VIRTIO_NET_F_GUEST_TSO6 || VIRTIO_NET_F_GUEST_ECN) big_packets");
        vi->big_packets = true;
    }

    if (vrio_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF)) {
        trace("feature: VIRTIO_NET_F_MRG_RXBUF mergeable_rx_bufs");
        vi->mergeable_rx_bufs = true;
    }

    /* Use single tx/rx queue pair as default */
    vi->curr_queue_pairs = 1;
    vi->max_queue_pairs = max_queue_pairs;

    netif_set_real_num_tx_queues(dev, 1);
    netif_set_real_num_rx_queues(dev, 1);

    err = register_netdev(dev);
    if (err) {
        etrace("virtio_net: registering device failed");
        goto free_vqs;
    }

    /* Assume link up if device can't report link status,
       otherwise get link status from config. */
    if (vrio_has_feature(vi->vdev, VIRTIO_NET_F_STATUS)) {
        trace("feature: VIRTIO_NET_F_STATUS");
        netif_carrier_off(dev);
//        schedule_work(&vi->config_work);
    } else {        
        trace("feature: ! VIRTIO_NET_F_STATUS, LINK_UP");
//        etrace("device is down");
        vi->status = VIRTIO_NET_S_LINK_UP;
        netif_carrier_on(dev);
    }

    mtrace("registered device %s with %d RX and TX vq's",
         dev->name, max_queue_pairs);

    return 0;

//free_recv_bufs:
//    free_receive_bufs(vi);
//    unregister_netdev(dev);
free_vqs:
//    cancel_delayed_work_sync(&vi->refill);
//    virtnet_del_vqs(vi);
//free_index:
//    free_percpu(vi->vq_index);
//free_stats:
    free_percpu(vi->stats);
free:
    free_netdev(dev);
    return err;
};

static void remove_net_device(struct vrio_device *vdev)
{
    struct vrionet_info *vi = vdev->priv;

    unregister_netdev(vi->dev);

    free_percpu(vi->stats);
    free_netdev(vi->dev);
}

static int __create_net_device(struct ioctl_create *create) {
    int res;

    struct vrio_device *vdev;
    vdev = kmalloc(sizeof(*vdev), GFP_KERNEL);

    vdev->placeholder.vrio_net_config = create->config.vrio_net;
    vdev->config = &vdev->placeholder.vrio_net_config;
    vdev->features = create->config.vrio_net.features;

    vdev->gsocket = (struct gsocket *)create->gsocket;
    atrace(vdev->gsocket == NULL, return -EFAULT);
    vdev->host_priv = create->host_priv;
    atrace((void *)vdev->host_priv == NULL);

    res = create_net_device(vdev);
    trace("create_net_device: %d", res);
    if (res != 0) {
        etrace("create_net_device failed");
        goto free_vdev;
    }
    
    trace("guest_priv: %lp, host_priv: %lp", vdev->priv, vdev->host_priv);
    create->guest_priv = (ulong)vdev->priv;
    list_add(&vdev->link, &devices_list);
    return 0;

free_vdev:
    kfree(vdev);   
    return res;
}

static void __remove_net_device(struct vrio_device *vdev) {
    trace("__remove_net_device");
    list_del(&vdev->link);            
    remove_net_device(vdev);
    gfree_gsocket(vdev->gsocket);
    kfree(vdev);    
//    module_put(THIS_MODULE);
}

static void remove_net_device_by_index(int index) {
    struct vrio_device *vdev;

    trace("device_id: %d", index);
    list_entry_at_index(index, vdev, &devices_list, link);
    if (vdev == NULL) {
        etrace("net device with id %d is no where to be found", index);
        return;
    }

    __remove_net_device(vdev);
}

static void remove_net_device_by_uid(uint device_uid) {
    struct vrio_device *vdev;

    list_for_each_entry(vdev, &devices_list, link) { 
        if (vdev->device_uid == device_uid) {
            __remove_net_device(vdev);
            return;
        }
    }
}

static void remove_all_net_devices(void) {
    struct vrio_device *vdev, *n;

    trace("remove_all_net_devices");
    list_for_each_entry_safe(vdev, n, &devices_list, link) { 
        trace("calling __remove_net_device: %p", vdev);
        __remove_net_device(vdev);
    }
}

static struct virtio_device_id id_table[] = {
    { VIRTIO_ID_NET, VIRTIO_DEV_ANY_ID },
    { 0 },
};

#if TRACE_ENABLED
void sanity_check(void) {
    mtrace("sanity_check");
}
#endif

long ioctl(struct ioctl_param *local_param) {

    switch (local_param->cmd) {
        case VRIO_IOCTL_CREATE_NET: { 
            mtrace("ioctl VRIO_IOCTL_CREATE_NET");
            __create_net_device(&local_param->x.create);
            break;
        }
        
        case VRIO_IOCTL_REMOVE_DEV: {
            mtrace("ioctl VRIO_IOCTL_REMOVE_DEV");
            if (local_param->x.remove.device_id == -1) 
                remove_all_net_devices();
            else 
                remove_net_device_by_index(local_param->x.remove.device_id);                
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
    struct vrio_header *vhdr;
    struct vrionet_info *vi;
    struct gsocket *gsocket = (struct gsocket *)param1;
    struct giovec *giovec = (struct giovec *)param2;
    int res, i;

    atrace(giovec->iov[0].iov_len < VRIO_HEADER_SIZE, return);
#if VRIO_HEADER_DEBUG
    if (!is_vrio_checksum_valid(giovec->iov, giovec->iov_len)) {
        etrace("vrio checksum mismatch");
        gfree_packet(gsocket, giovec);
        return;
    }
#endif    
    vhdr = (struct vrio_header *)giovec->iov[0].iov_base;
    giovec->iov[0].iov_base += VRIO_HEADER_SIZE;
    giovec->iov[0].iov_len -= VRIO_HEADER_SIZE;
    
    trace("vhdr->guest_priv: %lp, vhdr->host_priv: %lp", vhdr->guest_priv, vhdr->host_priv);
    vi = (struct vrionet_info *)vhdr->guest_priv;

    atrace(vi->MAGIC != 0xAABBCCDD, gfree_packet(gsocket, giovec); return);

#if TRACE_DEBUG
    for (i=0; i<giovec->iov_len; i++) {
        trace("iov(%d/%d): %.*b", i, giovec->iov[i].iov_len, giovec->iov[i].iov_len, giovec->iov[i].iov_base);
    }
#endif
    //udelay(100);
    res = receive_buf(vi, giovec, vhdr->out_len);  
    if (unlikely(res == VHOST_NET_TX_FREE_MEM)) {     
        trace("receive_buf returned VHOST_NET_TX_FREE_MEM, freeing giovec");
        gfree_packet(gsocket, giovec);
    }
//    gfree_packet(gsocket, giovec);
}

static struct vdev vdev_net = {
    .name = "net",
    .handler = handler,
    .ioctl = ioctl,
#if L2_GNET_RUN_FROM_SOFTIRQ
    .run_from_softirq_context = true,
#else
    .run_from_softirq_context = false,
#endif
/*
#if L2_MACVTAP_DIRECT_CALLBACK
    .run_from_softirq_context = true,
#else
    .run_from_softirq_context = false,
#endif
*/
};

static int __init init(void)
{
    bool res;
    
    mtrace("module gnet up");
    INIT_LIST_HEAD(&devices_list);

    res = vdev_register(&vdev_net);
    trace("vdev_register: %d", res);
    if (!res) {
        etrace("vdev_register failed");
        return -EPERM;
    }

    return 0;
/*
out_vdev_unregister:
    vdev_unregister(&vdev_net);
    return error;
*/
}

static void __exit fini(void)
{
    mtrace("module gnet down");
    
    remove_all_net_devices();
    vdev_unregister(&vdev_net);
}

module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("vRIO gnetwork driver");
MODULE_LICENSE("GPL");
#endif
