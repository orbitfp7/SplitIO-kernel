#if 1 /* patchouli vrio-eth-module */
#ifndef _L2PACKET_H
#define _L2PACKET_H

#include <linux/vrio/l2socket.h>
#include <linux/vrio/cqueue.h>

#define RX_HANDLER_ATOMIC_ASSERT     1

#define MAX_PORTS                    16
#define HASH_KEY_RANGE               65536

extern int l2_packet_list_size;      
extern int large_packet_list_size;   

#define LARGE_PACKET_IOV_MAX_SIZE    8192

extern int l2_packet_size;
#define L2_PACKET_MAX_SIZE           16384
#define __L2_PACKET_MAX_SIZE         (L2_PACKET_MAX_SIZE + 4096)
#define L2_PACKET_MIN_SIZE           ETH_ZLEN
                                        
#define L2_TCP_MAX_SEGMENT_SIZE      65500
#define L2_IP_NEXT_PROTOCOL          0xFD

#define ETHHDR_SIZE                  (sizeof(struct ethhdr))
#define IPHDR_SIZE                   (sizeof(struct iphdr))
#define TCPHDR_SIZE                  (sizeof(struct tcphdr))

#if L2_FRAGMENTATION_OFFLOAD
#define L2_PACKET_HEADER_SIZE        (ETHHDR_SIZE + IPHDR_SIZE + TCPHDR_SIZE)
#else
#define L2_PACKET_HEADER_SIZE        (ETHHDR_SIZE + IPHDR_SIZE)
#endif

#define L2_PACKET_TO_ETH_HDR(l2pkt)     ((struct ethhdr *)((l2pkt)->l2_mac_header))
#define L2_PACKET_TO_IP_HDR(l2pkt)      ((struct iphdr *)((l2pkt)->l2_network_header))
#define L2_PACKET_TO_TCP_HDR(l2pkt)     ((struct tcphdr *)((l2pkt)->l2_transport_header))

#define L2_PACKET_DATA(l2pkt)           (l2pkt->l2packet + L2_PACKET_HEADER_SIZE)
#define __L2_PACKET_DATA_SIZE(l2pkt)    (l2pkt->packet_size)

struct cqueue;

struct l2packet {
    struct llist_node llink;

    struct list_head link;

    uint packet_size;
#if L2_FRAGMENTATION_OFFLOAD
    uint partial_size;
#endif

    struct sk_buff *skb;
    struct iovec iov[MAX_SKB_FRAGS];
    size_t iov_len;

    unchar *l2_mac_header;
    unchar *l2_network_header;
    unchar *l2_transport_header;
};

struct large_packet {
    struct llist_node llink;

    struct list_head link;
    struct list_head hlink;

    struct cqueue_struct clink; 
    uint64_t uid;
#if L2_FRAGMENTATION_OFFLOAD
    uint packet_size;
    uint expected_packet_size;
#endif
    struct biovec biovec;
    struct iovec iov[LARGE_PACKET_IOV_MAX_SIZE];
    
    // l2socket and source on which the packet arrived from 
    struct bsocket bsocket;

    struct list_head l2packets;

#if TRACE_DEBUG
    // Sole purpose of this magic is to ensure that we are freeing the correct structure.
    ulong magic;
#endif
};

#define CHANNEL_MAGIC       0x7652494F // "vRIO"
#define F_FIRST_FRAGMENT    (1) 
#define F_LAST_FRAGMENT     (1 << 1) 
#define F_SINGLE_FRAGMENT   (F_FIRST_FRAGMENT | F_LAST_FRAGMENT) 
#if TRACE_DEBUG
#define F_MIN_SIZE_FRAGMENT (1 << 2)
#endif

struct socket_poll {
    poll_table            table;
    wait_queue_head_t     *wqh;
    wait_queue_t          wait;
    unsigned long		  mask;
};

struct raw_socket {
    int if_index;
    unchar mac_address[6];
    /* Next id used when sending outgoing packet */
    atomic_t next_id;
    struct l2socket *l2sockets[MAX_PORTS];    
    
    struct net_device *ndev;

    data_handler handler;

    void *private_data;

    struct l2packet *l2packet_list; 
    struct large_packet *large_packet_list; 

    struct llist_head ll2packet_free_list;
    struct llist_head llarge_packet_free_list;
    
    struct list_head large_packet_hash[HASH_KEY_RANGE];
    struct list_head large_packet_used_list;
    struct list_head large_packet_ready_list;

#if TRACE_DEBUG
    atomic_t l2packet_free_list_size;
    atomic_t large_packet_free_list_size;
#endif

#if RX_HANDLER_ATOMIC_ASSERT
    atomic_t debug_nr_entrance;
#endif

    spinlock_t lock;
};

void init_l2packet_free_list(struct raw_socket *raw_socket);
void init_large_packet_free_list(struct raw_socket *raw_socket);
void init_large_packet_hash(struct raw_socket *raw_socket);


struct l2packet* recv_l2packet_skb(struct raw_socket *raw_socket, struct sk_buff *skb);
bool process_l2packet(struct raw_socket *raw_socket, struct l2packet* l2packet);
struct large_packet* __recv_large_packet(struct raw_socket *raw_socket);
struct large_packet* recv_large_packet(struct raw_socket *raw_socket);
struct l2socket *process_large_packet(struct raw_socket *raw_socket, struct large_packet* large_packet);
void free_large_packet(struct raw_socket *raw_socket, struct large_packet* large_packet);
void free_all(struct raw_socket *raw_socket);

int sendskb(struct l2socket *l2socket, struct sk_buff *skb, struct l2address *l2address);
int __sendskb(struct l2socket *l2socket, 
              struct sk_buff *skb, 
              struct l2address *l2address,
              unchar           packet_id,
              u32              seq_number,
              int              expected_packet_size);

static inline int get_next_packet_id(struct raw_socket *raw_socket) {
    return atomic_inc_return(&raw_socket->next_id);
}

static inline int __send_raw_skb(struct sk_buff *skb, struct net_device *ndev) {
    int res;
//    unsigned long flags;

//    local_irq_save(flags);
    skb->dev = ndev;
    res = dev_queue_xmit(skb);
//    res = ndev->netdev_ops->ndo_start_xmit(skb, ndev);
//    local_irq_restore(flags);
    atrace(res < 0 || res == NET_XMIT_DROP, strace());
    return (res >= 0 && res != NET_XMIT_DROP);
//    return (res == NETDEV_TX_OK);
}

static inline void copy_mac(unchar *dest_mac, unchar *src_mac) {
    dest_mac[0] = src_mac[0];
    dest_mac[1] = src_mac[1];
    dest_mac[2] = src_mac[2];
    dest_mac[3] = src_mac[3];
    dest_mac[4] = src_mac[4];
    dest_mac[5] = src_mac[5];
}

static inline void l2socket_add_large_packet(struct l2socket *l2socket, struct large_packet *large_packet) {
    int ret;
    ret = cenqueue(l2socket->large_packet_ready_queue, &large_packet->clink);
    atrace(ret != CQUEUE_SUCCESS);
}

static inline struct large_packet *l2socket_dequeue_large_packet(struct l2socket *l2socket) {
    struct large_packet *large_packet = NULL;
    struct cqueue_struct *cq_elm;
    
    cq_elm = cdequeue(l2socket->large_packet_ready_queue);
    if (cq_elm) {
        large_packet = container_of(cq_elm, struct large_packet, clink);
    }

    return large_packet;
}

struct pseudo_iphdr {
    __u8    reserved; // version + ihl
    __u8	flags;
    __be16	tot_len;
    __be16	packet_size;
    __u8	src_port;
    __u8	dest_port;
    __u8	id;
    __u8	protocol;
    __sum16	check;
    __be32	saddr;
    __be32	daddr;
};

static inline __u8 channel_id(struct l2packet *l2packet) {
    struct pseudo_iphdr *piph = (struct pseudo_iphdr *)l2packet->l2_network_header;

    return piph->id;
}

static inline __u8 channel_src_port(struct l2packet *l2packet) {
    struct pseudo_iphdr *piph = (struct pseudo_iphdr *)l2packet->l2_network_header;

    return piph->src_port;
}

static inline __u8 channel_dest_port(struct l2packet *l2packet) {
    struct pseudo_iphdr *piph = (struct pseudo_iphdr *)l2packet->l2_network_header;

    return piph->dest_port;
}

static inline __u8 channel_flags(struct l2packet *l2packet) {
    struct pseudo_iphdr *piph = (struct pseudo_iphdr *)l2packet->l2_network_header;

    return piph->flags;
}

static inline __be32 channel_packet_size(struct l2packet *l2packet) {
#if L2_FRAGMENTATION_OFFLOAD
    struct tcphdr *tcph = (struct tcphdr *)l2packet->l2_transport_header;
    
    return tcph->ack_seq;
#else
    struct pseudo_iphdr *piph = (struct pseudo_iphdr *)l2packet->l2_network_header;

    return piph->packet_size;
#endif
}

static inline void set_channel_flags(struct l2packet *l2packet, __u8 flags) {
    struct pseudo_iphdr *piph = (struct pseudo_iphdr *)l2packet->l2_network_header;

    piph->flags = flags;
}

#endif /* _L2PACKET_H */
#endif
