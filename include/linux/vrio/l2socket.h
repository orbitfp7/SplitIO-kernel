#if 1 /* patchouli vrio-eth-module */
#ifndef ___L2PACKET_H
#define ___L2PACKET_H

#define L2_FRAGMENTATION_OFFLOAD        (1) 

#define L2_SEND_SKB_DIRECTLY            (1 && L2_FRAGMENTATION_OFFLOAD)

#define L2_MACVTAP_RX_SKB_BRIDGE        (1 && L2_FRAGMENTATION_OFFLOAD)
#define L2_MACVTAP_TX_SKB_BRIDGE        (1 && L2_FRAGMENTATION_OFFLOAD)
#define L2_RECEIVE_SKB                  (1)
                                        
#define L2_GNET_RUN_FROM_SOFTIRQ        (1)
#define L2_GNET_GOOD_COPY               (128) // 65535

struct raw_socket;
struct l2socket;
struct bsocket;
struct biovec;
struct cqueue;

typedef void (*data_handler)(struct bsocket *bsocket, struct biovec *biovec);

struct biovec {
    size_t iov_len;
    struct iovec *iov;

    unsigned char data[64];
};

struct l2address {
    unchar mac_address[6];
    unchar port;
};

struct l2socket {
    struct raw_socket *raw_socket;
    void *handler;
    bool run_from_softirq_context;
    unchar src_port;

    struct cqueue *large_packet_ready_queue; 

    /* free for use */
    char buffer[128];

    // For any purpose
    ulong private_data;
    ulong private_data2;
    ulong private_data3;
};

struct bsocket {
    struct l2socket *l2socket;
    struct l2address l2address;
};

#endif /* ___L2PACKET_H */
#endif
