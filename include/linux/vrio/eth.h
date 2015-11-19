#if 1 /* patchouli vrio-eth-module */
#ifndef _ETH_H
#define _ETH_H

#include <linux/vrio/l2socket.h>

struct raw_socket;

#define open_raw_socket(if_name, handler) __open_raw_socket(if_name, handler)

struct raw_socket *__open_raw_socket(char *if_name, data_handler handler);
void               close_raw_socket(struct raw_socket *raw_socket);

#define open_l2socket(raw_socket, port, handler) __open_l2socket(raw_socket, port, handler, false)

struct l2socket *__open_l2socket(struct raw_socket *raw_socket, int port, data_handler handler, bool run_from_softirq_context);
void             close_l2socket(struct l2socket *l2socket);

void free_packet(struct bsocket *bsocket, struct biovec* biovec);

int  send_iov(struct bsocket *bsocket, struct iovec *iov, size_t iov_len);
int  send_buff(struct bsocket *bsocket, char *buff, size_t length);
int  send_skb(struct bsocket *bsocket, struct sk_buff *skb);
void send_raw_skb(struct bsocket *bsocket, struct sk_buff *skb);

int  __send_iov(struct l2socket *l2socket, struct iovec *iov, size_t iov_len, struct l2address *l2address);
int  __send_buff(struct l2socket *l2socket, char *buff, size_t length, struct l2address *l2address);


int zsend(struct l2socket *l2socket, 
          struct iovec *iov, 
          size_t iov_len, 
          struct skb_frag_destructor *destroy, 
          struct l2address *l2address);

int zbsend_iov(struct bsocket *bsocket,
              struct iovec *iov,
              size_t iov_len,
              struct skb_frag_destructor *destroy);

struct sk_buff *iovec_to_skb(struct net_device *dev,
                             struct iovec *iov,
                             size_t iov_len,
                             struct skb_frag_destructor *destroy);

void             init_l2address(struct l2address *l2address, 
                                unchar *mac_address, 
                                unchar port, 
                                __u32 ip,
                                __be16 tcp_port);
struct l2address *create_l2address(unchar *mac_address, unchar port, 
                                  __u32 ip,
                                  __be16 tcp_port);
void             free_l2address(struct l2address *l2address);
//void             l2socket_address(struct l2address *l2address, struct l2socket *l2socket);
struct bsocket   *l2socket_dequeue(struct l2socket *l2socket, struct biovec **biovec);
void             l2socket_dequeue_list(struct l2socket *l2socket, struct list_head *head);
void             l2socket_splice_list(struct l2socket *l2socket, struct list_head *lp_list);
struct sk_buff   *detach_skb(struct biovec *biovec);

void             clear_socket_rx_buffers(struct raw_socket *raw_socket);

// For debug only
void trace_raw_socket(struct raw_socket *raw_socket);
#endif /* _ETH_H */
#endif
