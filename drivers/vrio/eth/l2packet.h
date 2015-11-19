#if 1 /* patchouli vrio-eth-module */
#ifndef _L2PACKET_H
#define _L2PACKET_H

#include <linux/vrio/l2socket.h>
#include <linux/vrio/cqueue.h>
#include <linux/vrio/cmempool.h>

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
#define L2HDR_SIZE                   (sizeof(struct l2header))

#if L2_FRAGMENTATION_OFFLOAD
#define L2_PACKET_HEADER_SIZE        (ETHHDR_SIZE + IPHDR_SIZE + TCPHDR_SIZE + L2HDR_SIZE)
#else
#define L2_PACKET_HEADER_SIZE        (ETHHDR_SIZE + IPHDR_SIZE)
#endif

#define L2_PACKET_TO_ETH_HDR(l2pkt)     ((struct ethhdr *)((l2pkt)->l2_mac_header))
#define L2_PACKET_TO_IP_HDR(l2pkt)      ((struct iphdr *)((l2pkt)->l2_network_header))
// #define L2_PACKET_TO_PIP_HDR(l2pkt)      ((struct pseudo_iphdr *)((l2pkt)->l2_network_header))
#define L2_PACKET_TO_TCP_HDR(l2pkt)     ((struct tcphdr *)((l2pkt)->l2_transport_header))
#define L2_PACKET_TO_HDR(l2pkt)     ((struct l2header *)((l2pkt)->l2_header))

#define L2_PACKET_DATA(l2pkt)           (l2pkt->l2packet + L2_PACKET_HEADER_SIZE)
#define __L2_PACKET_DATA_SIZE(l2pkt)    (l2pkt->packet_size)

struct cqueue;

/* 16 bytes */
struct l2header {
    /* TCP options */
    unchar pad[3];	
    unchar window_scale[3];  
    unchar kind;
    unchar size;

    /* l2header */
    unchar flags;
    unchar src_port;
    unchar dest_port;
    unchar packet_id;
    uint32_t expected_packet_size;  
} __attribute__((packed));


struct tcpsession {
    struct list_head link;

    __u32 src_ip;
    __u32 dest_ip;
    __be16 src_port;
    __be16 dest_port;

    atomic_t seq;
    atomic_t ack;

//    int type;
};


struct l2packet {
    struct llist_node llink;

    struct list_head link;

    uint packet_size;
#if L2_FRAGMENTATION_OFFLOAD
    uint partial_size;
#endif

    struct sk_buff *skb;
    struct iovec iov[UIO_MAXIOV];
    size_t iov_len;

    unchar *l2_mac_header;
    unchar *l2_network_header;
    unchar *l2_transport_header;
    unchar *l2_header;

#if TRACE_DEBUG
    atomic_t being_used;
#endif
};


struct large_packet {
    struct llist_node llink;

    struct list_head link;
    struct list_head hlink;

    struct cqueue_struct clink; 
    uint64_t uid;
#if L2_FRAGMENTATION_OFFLOAD
    uint seq_number;
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

#define CHANNEL_MAGIC       0x7E82 // 494F // "vRIO"
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

    struct cmempool l2packet_pool;
    struct cmempool large_packet_pool;

//    struct llist_head ll2packet_free_list;
//    struct llist_head llarge_packet_free_list;
    
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

    /* TCP session */
    struct list_head active_tcp_sessions;
    __u32 ip;

    spinlock_t lock;
};

/*
    int src_ip;
    int dest_ip;
    __be16 src_port;
    __be16 dest_port;
*/


static __be16 __generate_random_port(void) {
//    trace("__generate_random_port");
    __be16 port = (get_random_int() % 64000) + 1024;
    atrace(port<1024);
    return port;
}

static __be16 generate_random_port(struct raw_socket *raw_socket) {
//    trace("generate_random_port");
    __be16 port = __generate_random_port();
    // should check if that port is not taken

    return port;
}

static __be32 generate_random_ip(__be32 ip_addr) {
    int id = ip_addr >> 24;
    if (++id == 0)
        id++;

    return (ip_addr & 0x00FFFFFF) | ((id & 0xFF) << 24);
 }

static struct tcpsession *__alloc_tcp_session(struct raw_socket *raw_socket) {
//    trace("__alloc_tcp_session");
//    struct tcpsession *session = (struct tcpsession *)vmalloc(sizeof(struct tcpsession)); 
    struct tcpsession *session = (struct tcpsession *)kmalloc(sizeof(struct tcpsession), GFP_ATOMIC);  
//    session->type = 0;

    atomic_set(&session->seq, 0);
    atomic_set(&session->ack, 0);
    
    list_add(&session->link, &raw_socket->active_tcp_sessions);
    return session;
}

static void __free_tcp_session(struct tcpsession *session) {
    if (session) {
        list_del(&session->link);
        kfree(session);
    }
}

static struct tcpsession *get_tcp_session(struct raw_socket *raw_socket, 
                                          __u32 ip, __be16 port) {
//    trace("get_tcp_session");
    struct tcpsession *session, *i;

    list_for_each_entry_safe(session, i, &raw_socket->active_tcp_sessions, link) {
        if (session->dest_ip == ip && session->dest_port == port) 
            return session;
    }

    return NULL;
}

static void close_bsocket(struct bsocket *bsocket) {
//    trace("close_bsocket");
    struct tcpsession *session;

    session = get_tcp_session(bsocket->l2socket->raw_socket,
                              bsocket->l2address.ip_addr,
                              bsocket->l2address.tcp_port);
    __free_tcp_session(session);
}

static void attach_tcp_session(struct raw_socket *raw_socket, 
                               struct l2address *l2address) {
    struct tcpsession *session;

    session = get_tcp_session(raw_socket,
                              l2address->ip_addr,
                              l2address->tcp_port);

    if (!session) {
        session = __alloc_tcp_session(raw_socket);
        if (raw_socket->ip)
            session->src_ip = raw_socket->ip;
        else
            raw_socket->ip = generate_random_ip(l2address->ip_addr);

        session->src_port = __generate_random_port();
        session->dest_ip = l2address->ip_addr; // L2_PACKET_TO_IP_HDR(l2packet)->saddr;
        if (l2address->tcp_port == 0)
            l2address->tcp_port = generate_random_port(raw_socket);
        session->dest_port = l2address->tcp_port; // L2_PACKET_TO_TCP_HDR(l2packet)->source;
    }

    l2address->tcpsession = session;    
}

static int adjust_tcp_session_seq_number(struct l2address *l2address, int len) {
    int seq = 0;
    
    if (len) {
       seq = atomic_add_return(len, &l2address->tcpsession->seq) - len; 
    } else {
       atomic_set(&l2address->tcpsession->seq, 1);
    }

    return seq;
}  


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

/*
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
*/

static inline __u8 channel_id(struct l2packet *l2packet) {
    return L2_PACKET_TO_HDR(l2packet)->packet_id;
//    struct pseudo_iphdr *piph = (struct pseudo_iphdr *)l2packet->l2_network_header;

//    return piph->id;
}

static inline __u8 channel_src_port(struct l2packet *l2packet) {
    return L2_PACKET_TO_HDR(l2packet)->src_port;
//    struct pseudo_iphdr *piph = (struct pseudo_iphdr *)l2packet->l2_network_header;

//    return piph->src_port;
}

static inline __u8 channel_dest_port(struct l2packet *l2packet) {
    return L2_PACKET_TO_HDR(l2packet)->dest_port;
//    struct pseudo_iphdr *piph = (struct pseudo_iphdr *)l2packet->l2_network_header;

//    return piph->dest_port;
}

static inline __u8 channel_flags(struct l2packet *l2packet) {
    return L2_PACKET_TO_HDR(l2packet)->flags;
//    struct pseudo_iphdr *piph = (struct pseudo_iphdr *)l2packet->l2_network_header;

//    return piph->flags;
}

static inline __be32 channel_packet_size(struct l2packet *l2packet) {
#if L2_FRAGMENTATION_OFFLOAD
    return L2_PACKET_TO_HDR(l2packet)->expected_packet_size;
//1    struct tcphdr *tcph = (struct tcphdr *)l2packet->l2_transport_header;
    
//    tcph->window = htons(expected_packet_size & 0xFFFF)
//    tcph->urg_ptr = htons((expected_packet_size >> 16) & 0xFFFF)
//1    return ((ntohs(tcph->urg_ptr) & 0xF000) << 4) | ntohs(tcph->window);
//    return tcph->ack_seq;
#else
    struct pseudo_iphdr *piph = (struct pseudo_iphdr *)l2packet->l2_network_header;

    return piph->packet_size;
#endif
}

static inline void set_channel_flags(struct l2packet *l2packet, __u8 flags) {
//    struct pseudo_iphdr *piph = (struct pseudo_iphdr *)l2packet->l2_network_header;

//    piph->flags = flags;
    L2_PACKET_TO_HDR(l2packet)->flags = flags;
}
/*
static inline void channel_magic(struct l2packet *l2packet, __be32 magic) {
    L2_PACKET_TCP_HDR(l2packet)->window = htonl((__be16)magic);
}
*/
static inline __be32 channel_magic(struct l2packet *l2packet) {
    return ntohs(L2_PACKET_TO_TCP_HDR(l2packet)->window);
}


#endif /* _L2PACKET_H */
#endif
