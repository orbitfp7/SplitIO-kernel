#if 1 /* patchouli vrio-net-module */
/*
 * vRIO-net server in host kernel.
 */
#include <linux/compat.h>
#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/virtio_net.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/rcupdate.h>
#include <linux/file.h>
#include <linux/slab.h>

#include <linux/net.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <linux/if_macvlan.h>
#include <linux/if_vlan.h>

#include <net/sock.h>

#include <linux/vrio/trace.h>
#include <linux/vrio/generic.h>
#include <linux/vrio/utils.h>
#include <linux/vrio/vrio.h>

#include <linux/vrio/l2socket.h>

TRACE_ALL;

struct list_head devices_list;

static int zcopytx = 0;
module_param(zcopytx, int, 0444);
MODULE_PARM_DESC(zcopytx, "Enable Zero Copy TX;"
                          " 1 -Enable; 0 - Disable");

static int use_tap_bridge = 1;
module_param(use_tap_bridge, int, 0444);

static int VHOST_NET_WEIGHT = 0x80000; // 0x20000; 
module_param(VHOST_NET_WEIGHT, int, S_IRUGO);

#define VHOST_MAX_PEND 128

#define VHOST_GOODCOPY_LEN 256

/*
 * For transmit, used buffer len is unused; we override it to track buffer
 * status internally; used for zerocopy tx only.
 */
/* Lower device DMA failed */
#define VHOST_DMA_FAILED_LEN	3
/* Lower device DMA done */
#define VHOST_DMA_DONE_LEN	2
/* Lower device DMA in progress */
#define VHOST_DMA_IN_PROGRESS	1
/* Buffer unused */
#define VHOST_DMA_CLEAR_LEN	0

#define VHOST_DMA_IS_DONE(len) ((len) >= VHOST_DMA_DONE_LEN)

enum {
    VHOST_NET_VQ_RX = 0,
    VHOST_NET_VQ_TX = 1,
    VHOST_NET_VQ_MAX = 2,
};

enum vhost_net_poll_state {
    VHOST_NET_POLL_DISABLED = 0,
    VHOST_NET_POLL_STARTED = 1,
    VHOST_NET_POLL_STOPPED = 2,
};

struct vhost_device {
    struct list_head link;

    uint device_uid;
    void *priv;

    struct file *file;
    struct socket *sock;

    struct sk_buff *(* __recvskb)(struct socket *);
    void (* __sendskb)(struct socket *, struct sk_buff *);

    struct gsocket *gsocket;
    ulong guest_priv;
};

struct vhost_net {
    /* this member must be first */
    struct giocore giocore;
    struct vhost_device *vdev;

    /* Number of TX recently submitted.
     * Protected by tx vq lock. */
    poll_table         poll_table;
    ulong              poll_mask;
    wait_queue_t       wait_q;
    wait_queue_head_t *wqh;

    struct gwork_struct rx_work;
//    atomic_t poll_wake_posted;

    size_t vhost_hlen;
    size_t sock_hlen;

    bool zcopy;

//    unsigned tx_packets;

    char __buff[4096 * 21];
    char *buff;
    struct iovec iov[128];
};

static __always_inline bool vhost_sock_zcopy(struct socket *sock)
{
    trace("vhost_sock_zcopy: %d", sock_flag(sock->sk, SOCK_ZEROCOPY));
    return likely(zcopytx) &&
        sock_flag(sock->sk, SOCK_ZEROCOPY);
}

/* Pop first len bytes from iovec. Return number of segments used. */
static int move_iovec_hdr(struct iovec *from, struct iovec *to,
              size_t len, int iov_count)
{
    int seg = 0;
    size_t size;

    while (len && seg < iov_count) {
        size = min(from->iov_len, len);
        to->iov_base = from->iov_base;
        to->iov_len = size;
        from->iov_len -= size;
        from->iov_base += size;
        len -= size;
        ++from;
        ++to;
        ++seg;
    }
    return seg;
}

/* Copy iovec entries for len bytes from iovec. */
static void copy_iovec_hdr(const struct iovec *from, struct iovec *to,
               size_t len, int iovcount)
{
    int seg = 0;
    size_t size;

    while (len && seg < iovcount) {
        size = min(from->iov_len, len);
        to->iov_base = from->iov_base;
        to->iov_len = size;
        len -= size;
        ++from;
        ++to;
        ++seg;
    }
}

static void vhost_zerocopy_callback(struct ubuf_info *ubuf, bool success)
{
    struct gsocket *gsocket = (struct gsocket *)ubuf->ctx;
    struct giovec *giovec = (struct giovec *)ubuf->desc;

    trace("vhost_zerocopy_callback: %d", success);
    gfree_packet(gsocket, giovec);
}

enum {
    VHOST_NET_TX_FREE_MEM = 0,
    VHOST_NET_TX_ZEROCOPY = 1,
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

static bool tap_handle_tx(struct vhost_net *net, struct giovec *giovec)
{
    struct sk_buff *skb;

    skb = gdetach_skb(giovec);
    if (skb) {
//        trace("Linearizing skb: %d", skb_linearize(skb));
//        skb_pull(skb, 78);
        
        trace("gdetach_skb returned skb, preparing skb to be sent");        
        if (skb_headlen(skb) < sizeof(struct virtio_net_hdr)) {
            etrace("not enough space in linear data, skb_headlen: %d (packet dropped)", skb_headlen(skb));
            return true;
        }

        skb_pull(skb, sizeof(struct virtio_net_hdr));
        skb_from_vnet_hdr(skb, (struct virtio_net_hdr *)(skb->data - sizeof(struct virtio_net_hdr)));
/*
        trace("skb->network_header: %lp",  skb->network_header);
        trace("skb->mac_header: %lp",  skb->mac_header);
        trace("skb->protocol: %d",  skb->protocol);
*/
        skb_set_network_header(skb, ETH_HLEN);
        skb_reset_mac_header(skb);
        skb->protocol = eth_hdr(skb)->h_proto;

        trace("packet size(skb->len): %d", skb->len);
/*
        trace("skb_headlen(skb): %d", skb_headlen(skb));
        trace("skb_headroom(skb): %d", skb_headroom(skb));
        trace("skb_shinfo(skb)->gso_size: %d", skb_shinfo(skb)->gso_size);
        trace("skb_shinfo(skb)->gso_type: %d", skb_shinfo(skb)->gso_type);
        trace("skb_shinfo(skb)->gso_segs: %d", skb_shinfo(skb)->gso_segs);
*/
        //gsend_raw_skb
        trace("macvtap_handle_tx: psize: %d", skb->len);

//        if (skb->len > 60000)
//            ntrace("tx_psize: %d", skb->len);
        net->vdev->__sendskb(net->vdev->sock, skb);
        return true;
    }    

    return false;
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

static __always_inline struct skb_vnet_hdr *skb_vnet_hdr(struct sk_buff *skb)
{
    return (struct skb_vnet_hdr *)skb->cb;
}

static int zerocopy_handle_tx(struct vhost_net *net, struct giovec *giovec, size_t len)
{
    struct skb_frag_data *data;
    struct virtio_net_hdr hdr;
    struct sk_buff *skb;
    int ret;

    struct skb_frag_destructor *destroy = (struct skb_frag_destructor *)giovec->data;
    
    init_frag_destructor(destroy, destroy_skb_frag);
    data = FRAG_DESTROY_DATA(destroy, struct skb_frag_data *);
    data->gsocket = net->vdev->gsocket;
    data->giovec = giovec;
    
    ret = memcpy_fromiovecend_skip((unchar *)&hdr, giovec->iov, giovec->iov_len, sizeof(struct virtio_net_hdr));
    atrace(ret != 0, return VHOST_NET_TX_FREE_MEM);
    skb = giovec_to_skb(NULL, giovec->iov, giovec->iov_len, destroy);
    if (unlikely(!skb)) {
        etrace("giovec_to_skb failed");
        goto out;
    }

    skb_set_network_header(skb, ETH_HLEN);
    skb_reset_mac_header(skb);
    skb->protocol = eth_hdr(skb)->h_proto;

    if (skb_from_vnet_hdr(skb, (struct virtio_net_hdr *)&hdr)) 
        goto out_skb;

    if (skb->ip_summed == CHECKSUM_PARTIAL)
        skb_set_transport_header(skb, skb_checksum_start_offset(skb));
    else
        skb_set_transport_header(skb, ETH_HLEN);

    trace("skb_shinfo(skb)->nr_frags: %d", skb_shinfo(skb)->nr_frags);
    net->vdev->__sendskb(net->vdev->sock, skb);    

out:    
    return VHOST_NET_TX_ZEROCOPY;

out_skb:
    dev_kfree_skb(skb);
    return VHOST_NET_TX_ZEROCOPY;
}

static int __tap_handle_tx(struct vhost_net *net, struct giovec *giovec, size_t len)
{
    unsigned out, s;
    int err;
    size_t hdr_size;
    struct socket *sock;
    struct vhost_ubuf_ref *uninitialized_var(ubufs);
    bool zcopy_used;

    struct iovec *iov = giovec->iov;
    int iov_len = giovec->iov_len;

    struct iovec hdr[64];

    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_iov = iov,
        .msg_flags = MSG_DONTWAIT,
    };

    mm_segment_t old_fs;

    int res = VHOST_NET_TX_FREE_MEM;

    trace("handle_tx");
    out = iov_len;

    sock = net->vdev->sock;
    atrace(sock == NULL, return VHOST_NET_TX_FREE_MEM);

    hdr_size = net->vhost_hlen;

    /* Skip header. TODO: support TSO. */
    s = move_iovec_hdr(iov, hdr, hdr_size, out);
    msg.msg_iovlen = out;
    /* Sanity check */
    /*
    if (!len) {
        etrace("Unexpected header len for TX: "
            "%zd expected %zd\n",
            iov_length(hdr, s), hdr_size);
    }
    */

#if 1
    zcopy_used = net->zcopy && (len >= VHOST_GOODCOPY_LEN);
    if (zcopy_used) {
        struct ubuf_info *ubuf = 
            (struct ubuf_info *)((char *)giovec->iov[0].iov_base - sizeof(struct ubuf_info));

        ubuf->callback = vhost_zerocopy_callback;
        ubuf->ctx = net->vdev->gsocket; 
        ubuf->desc = (ulong)giovec; 
        msg.msg_control = ubuf;
        msg.msg_controllen = sizeof(ubuf);

        res = VHOST_NET_TX_ZEROCOPY;
        trace("using zero copy");
    }
#endif
    old_fs = get_fs();
    set_fs(KERNEL_DS);

    /* TODO: Check specific error and bomb out unless ENOBUFS? */
    trace("packet size: %d, iov_len: %d", len, iov_len);
//    ulong start_t = jiffies;
    err = sock->ops->sendmsg(NULL, sock, &msg, len);
    //err = macvtap_send(sock, &msg, len);

    trace("handle_tx: psize: %d / %d", err, len);
    //mtrace("iov_len: %d", iov_len);
//    ulong end_t = jiffies;

  //  trace("send time: %d (%d)", (end_t - start_t) * 1000 / HZ, (end_t - start_t));
    set_fs(old_fs);

    trace("sock->ops->sendmsg: %d (%d)", len, err);
    if (unlikely(err < 0)) {
        //if (err != -EAGAIN) // && err == -ENOBUFS) 
        if (err == -EAGAIN)
            ntrace("egress interface overloaded, packet dropped");        
        else 
            etrace("sock->ops->sendmsg: %d", err);
        //                tx_poll_start(net, sock);
        return res;
    }
    if (err != len)
        etrace("Truncated TX packet: "
        " len %d != %zd\n", err, len);

//    total_len += len;
    //        vhost_net_tx_packet(net);

    return res;
}

__always_inline static int handle_tx(struct vhost_net *net, struct giovec *giovec, size_t len)
{
    bool zcopy_used;
    zcopy_used = net->zcopy; // && (len >= VHOST_GOODCOPY_LEN);

    //if (zcopy_used) {
    if (zcopy_used) {
        trace("calling zerocopy handle tx");
        return zerocopy_handle_tx(net, giovec, len);
    } else {
        trace("calling tap handle tx");
        return __tap_handle_tx(net, giovec, len);
    }
}

static int peek_head_len(struct sock *sk)
{
    struct sk_buff *head;
    int len = 0;
    unsigned long flags;

    spin_lock_irqsave(&sk->sk_receive_queue.lock, flags);
    head = skb_peek(&sk->sk_receive_queue);
    if (likely(head)) {
        len = head->len;
        if (vlan_tx_tag_present(head))
            len += VLAN_HLEN;
    }
    spin_unlock_irqrestore(&sk->sk_receive_queue.lock, flags);
    return len;
}

static __always_inline int virtnet_add_buf(struct vhost_net *net, char *buff, int len) {
    struct vrio_header vhdr;
    struct iovec iov[2];
    int iov_len = 2;
    int ret;
    trace("virtnet_add_buf");

    vhdr.host_priv = (ulong)net; 
    vhdr.guest_priv = (ulong)net->vdev->guest_priv; 
    vhdr.out_len = len;

    iov[0].iov_base = &vhdr;
    iov[0].iov_len = sizeof(struct vrio_header);

    iov[1].iov_base = buff;
    iov[1].iov_len = len;
    
#if VRIO_HEADER_DEBUG
    vhdr.checksum = 0;
    vhdr.checksum = calc_vrio_checksum(iov, iov_len);
#endif

    ret = gsend_iov(net->vdev->gsocket, iov, iov_len);    
    trace("gsend_iov: %d", ret);
    //atrace(ret <= 0);
    return ret;
}

static __always_inline int recvmsg(struct socket *sock, struct msghdr *msg, size_t len) {
    mm_segment_t fs;
    int err;

    fs = get_fs();     /* save previous value */
    set_fs (get_ds()); /* use kernel limit */

    err = sock->ops->recvmsg(NULL, sock, msg,
            len, MSG_DONTWAIT | MSG_TRUNC);

    set_fs(fs); /* restore before returning to user space */
    return err;
}

static __always_inline int vhost_poll_start(struct vhost_net *vnet, struct file *file);
static __always_inline void vhost_poll_stop(struct vhost_net *vnet);

static int vhost_poll_wakeup(wait_queue_t *wait, unsigned mode, int sync, void *key);

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

static void tap_handle_rx(struct vhost_net *net) {
    struct virtio_net_hdr hdr; 
    struct vrio_header *vhdr;
    struct sk_buff *skb;
    size_t total_len = 0;
    int err;
    int skb_len;

    while ((skb = net->vdev->__recvskb(net->vdev->sock))) {    
        trace("macvtap_recvskb: skb->len: %d", skb->len);
        trace("skb_headroom(skb): %d", skb_headroom(skb));
        if (skb_headroom(skb) < sizeof(struct virtio_net_hdr) + sizeof(struct vrio_header)) {        
            etrace("freeing skb, skb_headroom lacks header space");
            kfree_skb(skb);
            continue;
        }

        skb_orphan(skb);
        nf_reset(skb);

        skb_to_vnet_hdr(skb, &hdr);
        memcpy(skb_push(skb, sizeof(struct virtio_net_hdr)), 
               &hdr, 
               sizeof(struct virtio_net_hdr));

        vhdr = (struct vrio_header *)skb_push(skb, sizeof(struct vrio_header));
        vhdr->host_priv = (ulong)net; 
        vhdr->guest_priv = (ulong)net->vdev->guest_priv; 
        vhdr->out_len = skb->len - sizeof(struct vrio_header);
        vhdr->in_len = 0;
#if VRIO_HEADER_DEBUG
        vhdr->checksum = 0;
        vhdr->checksum = calc_vrio_checksum_skb(skb);
#endif

        skb_len = skb->len;
        err = gsend_skb(net->vdev->gsocket, skb);
        trace("macvtap_handle_rx: psize: %d / %d", err, skb_len);
        if (unlikely(err <= 0)) {
            etrace("gsend_skb failed with: %d", err);
            break;
        }
        
        total_len += err;    
        if (unlikely(total_len >= VHOST_NET_WEIGHT)) {
            ntrace("total_len raached VHOST_NET_WEIGHT, bailing out");
            break;
        }
    }
}

static void __tap_handle_rx(struct vhost_net *net)  
{
    unsigned uninitialized_var(in);
    struct vhost_log *vq_log;
    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_control = NULL, /* FIXME: get and handle RX aux data. */
        .msg_controllen = 0,
        .msg_iov = net->iov,
        .msg_flags = MSG_DONTWAIT,
    };
    struct virtio_net_hdr_mrg_rxbuf hdr = {
        .hdr.flags = 0,
        .hdr.gso_type = VIRTIO_NET_HDR_GSO_NONE
    };
    size_t total_len = 0;
    int err, mergeable;
    size_t vhost_hlen, sock_hlen;
    size_t vhost_len, sock_len;
    struct socket *sock;

    struct iovec ihdr[4];

    trace("handle_rx");

//    vhost_poll_stop(net);
//    atomic_set(&net->poll_wake_posted, 0);

    net->iov[0].iov_base = (void *)(((ulong)net->__buff + 4096) & ~4095);
    net->iov[0].iov_len = 4096 * 20;

    trace("net->iov[0].iov_base: %lp", net->iov[0].iov_base);
    trace("net->__buff: %lp", net->__buff);

    sock = net->vdev->sock;
    atrace(sock == NULL, return);

    vhost_hlen = net->vhost_hlen;
    sock_hlen = net->sock_hlen;

    vq_log = NULL;

    mergeable = 0;
    while ((sock_len = peek_head_len(sock->sk))) {
        //        trace("rx iteration #%d", i++);
        sock_len += sock_hlen;
        vhost_len = sock_len + vhost_hlen;
        in = 1;
        /* We don't need to be notified again. */
        trace("vhost_hlen: %d (sock_hlen: %d)", vhost_hlen, sock_hlen);
        if (unlikely((vhost_hlen)))
            /* Skip header. TODO: support TSO. */
                move_iovec_hdr(net->iov, ihdr, vhost_hlen, in);
        else
            /* Copy the header for use in VIRTIO_NET_F_MRG_RXBUF:
            * needed because recvmsg can modify msg_iov. */
            copy_iovec_hdr(net->iov, ihdr, sock_hlen, in);
        msg.msg_iovlen = in;
        err = recvmsg(sock, &msg, sock_len);
        trace("handle_rx: psize: %d / %d", err, sock_len);
        trace("sock->ops->recvmsg: %d", err);
        if (err > 0) {
            trace("net->iov[0].iov_base: %lp", net->iov[0].iov_base);
            trace("net->iov[0].iov_base: %.*b", err, net->iov[0].iov_base);
        }

        /* Userspace might have consumed the packet meanwhile:
        * it's not supposed to do this usually, but might be hard
        * to prevent. Discard data we got (if any) and keep going. */
        if (unlikely(err != sock_len)) {
            etrace("Discarded rx packet: "
                " len %d, expected %zd\n", err, sock_len);
            //            return;
            //            vhost_discard_vq_desc(vq, headcount);
            continue;
        }

        if (unlikely(vhost_hlen) &&
            memcpy_toiovecend(ihdr, (unsigned char *)&hdr, 0,
            vhost_hlen)) {
                etrace("Unable to write vnet_hdr at addr %p",
                    net->iov[0].iov_base);
                //            return;      
                break;
        }

        err = virtnet_add_buf(net, net->iov[0].iov_base, sock_len);
        if (unlikely(err <= 0)) {
            if (err != -EAGAIN) 
                etrace("virtnet_add_buf failed with: %d", err);
            break;
        }
        //atrace(err <= 0);

        total_len += vhost_len;
        if (unlikely(total_len >= VHOST_NET_WEIGHT)) {
            trace("total_len raached VHOST_NET_WEIGHT, bailing out");
            break;
        }
    }

//    vhost_poll_start(net, net->vdev->file);
}

static __always_inline bool rx_more_work(struct vhost_net *net) {
    return peek_head_len(net->vdev->sock->sk) != 0;
}

static void handle_rx(struct gwork_struct *gwork) {
    struct vhost_net *net = container_of(gwork, struct vhost_net, rx_work); 
    bool ret;
#if L2_MACVTAP_RX_SKB_BRIDGE
    if (use_tap_bridge) 
        tap_handle_rx(net);
    else
        __tap_handle_rx(net);
#else
    trace("calling tap_handle_rx");
    __tap_handle_rx(net);
#endif

    unmark_cqueue_elm(&gwork->clink);
    if (rx_more_work(net)) {
        ret = queue_gwork(net->vdev->gsocket, gwork);
        atrace(ret == false);
    }
}

static struct socket *get_tap_socket(struct vhost_device *vdev)
{
    struct socket *sock;
    struct file *file = vdev->file;

    if (!file)
        return ERR_PTR(-EBADF);
    sock = tun_get_socket(file);
    if (!IS_ERR(sock)) {
        trace("Voila! it's a tap socket");
        vdev->__sendskb = tun_sendskb;
        vdev->__recvskb = tun_recvskb;        
        return sock;
    }

    sock = macvtap_get_socket(file);
    if (IS_ERR(sock))
        fput(file);
        
    trace("Voila! it's a macvtap socket");        
    vdev->__sendskb = macvtap_sendskb;
    vdev->__recvskb = macvtap_recvskb;        
    return sock;
}

static struct socket *get_socket(struct vhost_device *vdev)
{
    struct socket *sock;
    struct file *file = vdev->file;

    /* special case to disable backend */
    if (file == NULL)
        return NULL;

    sock = get_tap_socket(vdev);
    if (!IS_ERR(sock))
        return sock;
    return ERR_PTR(-ENOTSOCK);
}

static int vhost_poll_wakeup(wait_queue_t *wait, unsigned mode, int sync, void *key) 
{
    struct vhost_net *net;
    bool ret;
    trace("vhost_poll_wakeup");

    net = container_of(wait, struct vhost_net, wait_q);

    if (!((unsigned long)key & net->poll_mask)) {
        return 0;
    }

    ret = queue_gwork(net->vdev->gsocket, &net->rx_work);
    atrace(ret == false);

    //vhost_poll_stop(net);
    return 0;
}

void vhost_poll_func(struct file *file, wait_queue_head_t *wqh, struct poll_table_struct *table) {
    struct vhost_net *vnet;
    trace("vhost_poll_func");         

    vnet = container_of(table, struct vhost_net, poll_table);
    vnet->wqh = wqh;
    add_wait_queue(wqh, &vnet->wait_q);
}

void vhost_poll_init(struct vhost_net *vnet) 
{
    init_waitqueue_func_entry(&vnet->wait_q, vhost_poll_wakeup);
    init_poll_funcptr(&vnet->poll_table, vhost_poll_func);
    vnet->poll_mask = POLLIN; 
    vnet->poll_table._key = vnet->poll_mask;
}

static __always_inline void vhost_poll_stop(struct vhost_net *vnet)
{
    trace("vhost_poll_stop");
    if (vnet->wqh) {
        // __remove_wait_queue
        remove_wait_queue(vnet->wqh, &vnet->wait_q);
        vnet->wqh = NULL;
    }
}

static __always_inline int vhost_poll_start(struct vhost_net *vnet, struct file *file)
{
    unsigned long mask;
    trace("vhost_poll_start");

    if (!vnet->wqh) {
        mask = file->f_op->poll(file, &vnet->poll_table);

        if (mask) {
            vhost_poll_wakeup(&vnet->wait_q, 0, 0, (void *)mask);        
        }
    }

/*
    if (mask & POLLERR) {
        if (poll->wqh)
            remove_wait_queue(poll->wqh, &poll->wait);
        ret = -EINVAL;
    }
*/
    return 0; 
}

static long vhost_net_set_backend(struct vhost_net *net, struct file *file)
{
    struct socket *sock;
    int r;

    net->vdev->file = file;
    sock = get_socket(net->vdev);
    if (IS_ERR(sock)) {
        r = PTR_ERR(sock);
        goto err;
    }

    net->vdev->sock = sock;

    return 0;

err:
    etrace("set backend failed");
    net->vdev->file = NULL;
    net->vdev->sock = NULL;
    return r;
}

static int vhost_net_set_features(struct vhost_net *n, u64 features)
{
    size_t vhost_hlen, sock_hlen, hdr_len;

    hdr_len = (features & (1 << VIRTIO_NET_F_MRG_RXBUF)) ?
            sizeof(struct virtio_net_hdr_mrg_rxbuf) :
            sizeof(struct virtio_net_hdr);
    if (features & (1 << VHOST_NET_F_VIRTIO_NET_HDR)) {
        /* vhost provides vnet_hdr */
        vhost_hlen = hdr_len;
        sock_hlen = 0;
    } else {
        /* socket provides vnet_hdr */
        vhost_hlen = 0;
        sock_hlen = hdr_len;
    }

    n->vhost_hlen = vhost_hlen;
    n->sock_hlen = sock_hlen;

    return 0;
}

static struct file *macvtap_open(struct ioctl_create *create) {
    struct file* file = NULL;
    char dev_path[128];

    trace("opening macvtap device: %s", create->device_path);
    sprintf(dev_path, "/dev/%s",create->device_path);
    file = file_open(dev_path, O_RDWR, 777); // 0644);
    if (!file) {
        etrace("file_open failed");
        goto out;
    }

    return file;

out:
    return NULL;
}

static struct file *tap_open(struct ioctl_create *create) {
    static char *clonedev = "/dev/net/tun";
    struct file* file = NULL;
    struct ifreq ifr;

    trace("opening clone device: %s", clonedev);
    file = file_open(clonedev, O_RDWR, 777); // 0644);
    if (!file) {
        etrace("file_open failed");
        goto out;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR;
    strncpy(ifr.ifr_name, create->device_path, IFNAMSIZ);

    if (file_ioctl(file, TUNSETIFF, (ulong)&ifr) < 0) {
        etrace("file_ioctl TUNSETIFF failed");
        goto out_file;
    }

    return file;

out_file:
    file_close(file);
out:
    return NULL;
}

static struct file *vtap_open(struct ioctl_create *create) {
    struct file* file = NULL;
    struct ifreq ifr;
    u64 features;

    int hdr_len;

    if (create->device_path[0] == 'm')
        file = macvtap_open(create);
     else
        file = tap_open(create);

    if (!file) 
        goto out;

    memset(&ifr, 0, sizeof(ifr));

    features = create->config.vrio_net.features;
    hdr_len = (features & (1 << VIRTIO_NET_F_MRG_RXBUF)) ?
        sizeof(struct virtio_net_hdr_mrg_rxbuf) :
        sizeof(struct virtio_net_hdr);

    if (file_ioctl(file, TUNSETVNETHDRSZ, (ulong)&hdr_len) < 0) {
        etrace("Config tap device TUNSETVNETHDRSZ error");
        goto out_file;
    }

    return file;

out_file:
    file_close(file);
out:
    return NULL;
}

static int vhost_net_open(struct vhost_device *vdev) 
{
    struct vhost_net *net;
    int ret;

    vdev->priv = net = kzalloc(sizeof(*net), GFP_KERNEL);
    if (!net) {
        etrace("kzalloc failed");
        ret = -ENOMEM;
        goto out;
    }

    net->vdev = vdev;    
    vhost_poll_init(net);

    init_gwork_func(&net->rx_work, handle_rx);
    set_cq_flag(&net->rx_work.clink, CQ_FLAG_MANUAL_UNMARK);

//    net->tx_poll_state = VHOST_NET_POLL_DISABLED;

    return 0;
out:
    return ret;
}

static struct vhost_device *__vhost_net_open(struct ioctl_create *create) {
    int res;
    struct vhost_device *vdev;

    vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);

    res = vhost_net_open(vdev);
    trace("vhost_net_open: %d", res);
    if (res != 0) {
        etrace("vhost_net_open failed");
        goto free_vdev;
    }

    list_add(&vdev->link, &devices_list);
    return vdev;

free_vdev:
    kfree(vdev);   
    return NULL;
}

static int vhost_net_release(struct vhost_device *vdev)
{
    struct vhost_net *net = vdev->priv;

    vhost_poll_stop(net);

    if (vdev->file) {
        file_close(vdev->file);
        vdev->file = NULL;
        vdev->sock = NULL;
    }

    kfree(net);
    return 0;
}

static void __vhost_net_release(struct vhost_device *vdev) {
    trace("__vhost_net_release");
    list_del(&vdev->link);            
    vhost_net_release(vdev);
    gfree_gsocket(vdev->gsocket);
    kfree(vdev);
}

static int __vhost_net_create(struct ioctl_create *create) {
    struct vhost_device *vdev;
    struct vhost_net *vnet;
    struct file* file;
    int res;

    trace("opening device_path: %s", create->device_path);
    file = vtap_open(create);
    if (!file) {
        etrace("vtap_open failed");
        res = -EFAULT;
        goto out;
    }

    vdev = __vhost_net_open(create);
    if (!vdev) {
        etrace("__vhost_net_open");
        res = -EFAULT;
        goto out_file;
    }

    vnet = (struct vhost_net *)vdev->priv;

    res = vhost_net_set_backend(vnet, file); 
    if (res) {
        etrace("vhost_net_set_backend: %d", res);
        goto out_net;
    }

    res = vhost_net_set_features(vnet, create->config.vrio_net.features);
    if (res) {
        etrace("vhost_net_set_features: %d", res);
        goto out_net;
    }

    vnet->zcopy = vhost_sock_zcopy(vnet->vdev->sock);
    trace("TX Zero copy used: %d", vnet->zcopy);
    vhost_poll_start(vnet, vnet->vdev->file);
    create->host_priv = (ulong)vnet;
    return 0;

out_net:
    __vhost_net_release(vdev);
out_file:
    file_close(file);
out:
    return res;
}

static void remove_net_device_by_index(int index) {
    struct vhost_device *vdev;

    trace("device_id: %d", index);
    list_entry_at_index(index, vdev, &devices_list, link);
    if (vdev == NULL) {
        etrace("vhost device with id %d is no where to be found", index);
        return;
    }

    __vhost_net_release(vdev);
}

static void remove_net_device_by_uid(uint device_uid) {
    struct vhost_device *vdev;

    list_for_each_entry(vdev, &devices_list, link) { 
        if (vdev->device_uid == device_uid) {
            __vhost_net_release(vdev);
            return;
        }
    }
}

static void remove_all_net_devices(void) {
    struct vhost_device *vdev, *n;

    list_for_each_entry_safe(vdev, n, &devices_list, link) { 
        __vhost_net_release(vdev);
    }
}

#if TRACE_ENABLED
void sanity_check(void) {
    mtrace("sanity_check");
}
#endif

long ioctl(struct ioctl_param *local_param) {
    struct vhost_net *net;
    long res = 0;

    switch (local_param->cmd) {
        case VRIO_IOCTL_CREATE_NET: { 
            mtrace("ioctl VRIO_IOCTL_CREATE_NET");    
            res = __vhost_net_create(&local_param->x.create);
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

        case VRIO_IOCTL_HOST: {
            mtrace("VRIO_IOCTL_HOST (guest_priv: %lp, host_priv: %lp)", 
                local_param->x.create.guest_priv, 
                local_param->x.create.host_priv);
            net = (struct vhost_net *)local_param->x.create.host_priv;
            net->vdev->gsocket = (struct gsocket *)local_param->x.create.gsocket;
            net->vdev->guest_priv = local_param->x.create.guest_priv;
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
    struct vhost_net *net;
    struct gsocket *gsocket = (struct gsocket *)param1;
    struct giovec *giovec = (struct giovec *)param2;    
    int i, res;
#if VRIO_HEADER_DEBUG
    ulong checksum;
#endif

    atrace(giovec->iov[0].iov_len < VRIO_HEADER_SIZE, return);

    if (giovec->iov[0].iov_len < VRIO_HEADER_SIZE) {
        mtrace("*** ERROR (iov_len < VRIO_HEADER_SIZE) ***");
        gfree_packet(gsocket, giovec);
        return;
    }

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
    net = (struct vhost_net *)vhdr->host_priv;
   
#if TRACE_DEBUG
    for (i=0; i<giovec->iov_len; i++) {
        trace("iov(%d/%d): %.*b", i, giovec->iov[i].iov_len, giovec->iov[i].iov_len, giovec->iov[i].iov_base);
    }
#endif

#if L2_MACVTAP_TX_SKB_BRIDGE
    if (use_tap_bridge) {
        if (tap_handle_tx(net, giovec)) {
            trace("macvtap_handle_tx returned true, freeing giovec");
            gfree_packet(gsocket, giovec);
            return;
        }
    }
#endif

    res = handle_tx(net, giovec, vhdr->out_len);
    if (unlikely(res == VHOST_NET_TX_FREE_MEM)) {     
        trace("handle_tx returned VHOST_NET_TX_FREE_MEM, freeing giovec");
        gfree_packet(gsocket, giovec);
    }
}

static struct vdev vdev_net = {
    .name = "net",
    .handler = handler,
    .ioctl = ioctl,
    .run_from_softirq_context = false,
};

static int vhost_net_init(void)
{
    bool res;

    mtrace("module hnet up");
    INIT_LIST_HEAD(&devices_list);

    res = vhost_register(&vdev_net);
    trace("vhost_register: %d", res);
    if (!res) {
        etrace("vhost_register failed");
        return -EPERM;
    }

    return 0;
}

static void vhost_net_exit(void)
{
    mtrace("module hnet down");

    remove_all_net_devices();
    vhost_unregister(&vdev_net);
}

module_init(vhost_net_init);
module_exit(vhost_net_exit);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Michael S. Tsirkin");
MODULE_AUTHOR("Yossi Kuperman");
MODULE_DESCRIPTION("Host kernel for vRIO-net");
#endif
