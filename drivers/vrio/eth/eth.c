#if 1 /* patchouli vrio-eth-module */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/inetdevice.h>
#include <linux/virtio_net.h>
#include <linux/if_macvlan.h>
#include <linux/if_vlan.h>

//#define TRACE_LEVEL 4

#include <linux/vrio/trace.h>
#include <linux/vrio/eth.h>
#include <linux/vrio/utils.h>
#include <linux/vrio/vrio.h>

// #include "ksocket.h"
#include "l2packet.h"
// #include "socket.h"
// #include "unittest.h"

TRACE_ALL;

#include <linux/vrio/cqueue.h>
#include <linux/vrio/cmempool.h>

int l2_packet_size = 1514; 
module_param(l2_packet_size, int, S_IRUGO);
MODULE_PARM_DESC(l2_packet_size, "Layer 2 (eth) packet size");

int l2_packet_list_size = 4096;
module_param(l2_packet_list_size, int, S_IRUGO);
int large_packet_list_size = 4096;
module_param(large_packet_list_size, int, S_IRUGO);

int extensive_unit_test = 0;
module_param(extensive_unit_test, int, S_IRUGO);
MODULE_PARM_DESC(extensive_unit_test, "Run unit-tests");

int debug_lp_min = 8000;
module_param(debug_lp_min, int, S_IWUSR | S_IRUGO);

#if TRACE_DEBUG
int is_using_rdtsc = 0;
module_param(is_using_rdtsc, int, S_IWUSR | S_IRUGO);

long l2p_rx_work_cycles = 0;
module_param(l2p_rx_work_cycles, long, S_IWUSR | S_IRUGO);

long l2p_tx_work_cycles = 0;
module_param(l2p_tx_work_cycles, long, S_IWUSR | S_IRUGO);

long rx_work_cycles = 0;
module_param(rx_work_cycles, long, S_IWUSR | S_IRUGO);

#endif

int rx_dropped_packets = 0;
module_param(rx_dropped_packets, int, S_IWUSR | S_IRUGO);

static __always_inline struct raw_socket *raw_socket_get_rcu(const struct net_device *dev) {
    return rcu_dereference(dev->rx_handler_data);
}

rx_handler_result_t rx_handler(struct sk_buff **pskb) {
    struct sk_buff *skb = *pskb;
    struct raw_socket *raw_socket;
    struct l2socket *l2socket;    
    struct l2packet *l2packet;
    struct large_packet* large_packet;
    rx_handler_result_t ret = RX_HANDLER_PASS;

#if TRACE_DEBUG
    long s_cycles, e_cycles;
#endif

#if RX_HANDLER_ATOMIC_ASSERT
    int debug_nr_entrance;
#endif

#if TRACE_DEBUG
    if (is_using_rdtsc)
        s_cycles = get_cycles();
#endif

    atrace(skb->dev == NULL, return RX_HANDLER_PASS);
    raw_socket = raw_socket_get_rcu(skb->dev);    
    atrace(raw_socket == NULL, return RX_HANDLER_PASS);

#if RX_HANDLER_ATOMIC_ASSERT
    debug_nr_entrance = atomic_inc_return(&raw_socket->debug_nr_entrance);
    if (debug_nr_entrance != 1)
        etrace("rx_handler is not thread-safe (%d)", debug_nr_entrance);
#endif

    skb_push(skb, ETH_HLEN);
    l2packet = recv_l2packet_skb(raw_socket, skb);
//    trace("recv_l2packet: 0x%p", l2packet);
    if (l2packet == NULL) {
    	skb->len -= ETH_HLEN;
        skb->data += ETH_HLEN;
//        trace("recv_l2packet_skb returned NULL");
        rx_dropped_packets++;
        goto out;
    }
    process_l2packet(raw_socket, l2packet);
    large_packet = __recv_large_packet(raw_socket);

#if TRACE_DEBUG
    if (large_packet)
        l2socket = process_large_packet(raw_socket, large_packet);

#if TRACE_DEBUG
    if (is_using_rdtsc) {
        e_cycles = get_cycles();
        l2p_rx_work_cycles += (e_cycles - s_cycles);
    }
#endif

    if (large_packet && l2socket) {
#else
    if (large_packet && (l2socket = process_large_packet(raw_socket, large_packet))) {
#endif
        trace("packet is ready, source address: %.*b, source port: %d, dest port: %d; tcpsocket: src %d.%d.%d.%d:%d, dest %d.%d.%d.%d:%d ", 
                          6, 
                          large_packet->bsocket.l2address.mac_address, 
                          large_packet->bsocket.l2address.port, 
                          l2socket->src_port,
			  NIPQUAD(large_packet->bsocket.l2address.tcpsession->src_ip),
			  ntohs(large_packet->bsocket.l2address.tcpsession->src_port),
			  NIPQUAD(large_packet->bsocket.l2address.tcpsession->dest_ip),
                          ntohs(large_packet->bsocket.l2address.tcpsession->dest_port));
        trace("l2socket->handler: %lp, bsocket: %lp, biovec: %lp, from_softirq: %d",
            l2socket->handler, &large_packet->bsocket, &large_packet->biovec, l2socket->run_from_softirq_context);

        if (unlikely(l2socket->run_from_softirq_context)) {
            trace("calling handler from softirq");
            ((data_handler)l2socket->handler)(&large_packet->bsocket, 
                &large_packet->biovec);
        } else {     
            trace("calling socket_handler");
            raw_socket->handler(&large_packet->bsocket, 
                &large_packet->biovec);
        }
    }

#if TRACE_DEBUG
    if (is_using_rdtsc) {
        e_cycles = get_cycles();
        rx_work_cycles += (e_cycles - s_cycles);
    }
#endif

    ret = RX_HANDLER_CONSUMED;

out:
#if RX_HANDLER_ATOMIC_ASSERT
    atomic_dec(&raw_socket->debug_nr_entrance);
#endif
    return ret;
}

__u32 get_ifaddr_by_net_device(struct net_device *ndev) {
    struct in_device *in_dev = rcu_dereference(ndev->ip_ptr);
    struct in_ifaddr *ifap;

    // in_dev has a list of IP addresses (because an interface can have multiple)
    for (ifap = in_dev->ifa_list; ifap != NULL; ifap = ifap->ifa_next) {
        return (__u32)ifap->ifa_address;
    }

    return 0;
}

#if 0

>  int get_ifaddr_by_name(const char *ifname, __u32 * addr)
>  {
>         cnet_device;
>         struct in_device *pin_device;
>         struct in_ifaddr* inet_ifaddr;
>
>         read_lock_bh(&dev_base_lock);
>  #if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
>         pnet_device = dev_base;
>  #else
>         pnet_device = first_net_device();
>  #endif
>         while (pnet_device != NULL)
>         {
>                 if ((netif_running(pnet_device))
>                                 && (pnet_device->ip_ptr != NULL)
>                                 && (strcmp(pnet_device->name, ifname) == 0))
>                 {
>                         pin_device =
>                                 (struct in_device *) pnet_device->ip_ptr;
>                         inet_ifaddr = pin_device->ifa_list;
>                         if(inet_ifaddr == NULL)
>                         {
>                                 printk("ifa_list is null!\n");
>                                 break;
>                         }
>                         /* ifa_local: ifa_address is the remote point in ppp */
>                         *addr = (inet_ifaddr->ifa_local);
>                           read_unlock_bh(&dev_base_lock);
>                         return 1;
>                 }
>  #if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
>                 pnet_device = pnet_device->next;
>  #else
>                 pnet_device = next_net_device(pnet_device);
>  #endif
>
>         }
>
>         read_unlock_bh(&dev_base_lock);
>         return -1;              /* address not found! */
>  }
#endif

struct raw_socket *__open_raw_socket(char *if_name, data_handler handler) {
    struct net *net;
    struct net_device *ndev = NULL;
    struct raw_socket *raw_socket;
    unsigned char *mac_address;
    int i, err;

    raw_socket = (struct raw_socket*)vmalloc(sizeof(struct raw_socket)); 
    if (raw_socket == NULL) {
        etrace("failed to allocate memory");
        goto exit;
    }                                                                    

    for (i=0; i<MAX_PORTS; i++)
        raw_socket->l2sockets[i] = NULL;
/*
    raw_socket->l2packet_list = (struct l2packet *)vmalloc(sizeof(struct l2packet) * l2_packet_list_size);
    if (raw_socket->l2packet_list == NULL) {
        etrace("failed to allocate l2packet_list");
        goto free_raw_socket;
    }
    raw_socket->large_packet_list = (struct large_packet *)vmalloc(sizeof(struct large_packet) * large_packet_list_size);
    if (raw_socket->large_packet_list == NULL) {
        etrace("failed to allocate large_packet_list");
        goto free_l2packet_list;
    }
*/
    if (init_cmempool(&raw_socket->l2packet_pool, l2_packet_list_size, sizeof(struct l2packet)) == false) {
        etrace("failed to allocate l2packet_list");
        goto free_raw_socket;        
    }
    
    if (init_cmempool(&raw_socket->large_packet_pool, large_packet_list_size, sizeof(struct large_packet)) == false) {
        etrace("failed to allocate large_packet_list");
        goto free_l2packet_list;
    }

    init_l2packet_free_list(raw_socket);
    init_large_packet_free_list(raw_socket);
    init_large_packet_hash(raw_socket);

    rtnl_lock();        

    net = current->nsproxy->net_ns;
    ndev = __dev_get_by_name(net, if_name);
    if (!ndev) {
        etrace("__dev_get_by_name failed, interface name %s didn't found", if_name);
        goto free_rtnl_lock;
    }

    dev_hold(ndev);
    
    if (netdev_master_upper_dev_get(ndev)) {
        etrace("%s is a slave device, aborting", if_name);
        goto put_ndev;
    }

    raw_socket->ip = get_ifaddr_by_net_device(ndev);
    if  (raw_socket->ip)
        trace("IP address of device %s is %d.%d.%d.%d", if_name, NIPQUAD(raw_socket->ip));
    else {
        ntrace("Device %s doesn't have an IP address", if_name);
//        goto put_ndev;
    }

    err = dev_open(ndev);          
    if (err) {                         
        etrace("dev_open failed with error: %d", err);
        goto put_ndev;
    }

    err = netdev_rx_handler_register(ndev, rx_handler, raw_socket);
    if (err) {
        etrace("netdev_rx_handler_register failed with error: %d", err);
        goto put_ndev;
    }

    trace("setting ndev %s mtu's to %d", if_name, l2_packet_size);
    dev_set_mtu(ndev, l2_packet_size);

    raw_socket->ndev = ndev;
    rtnl_unlock();

    mac_address = ndev->dev_addr;
    copy_mac(raw_socket->mac_address, mac_address);
    atomic_set(&raw_socket->next_id, 0);

    INIT_LIST_HEAD(&raw_socket->active_tcp_sessions);

#if TRACE_DEBUG
    atomic_set(&raw_socket->l2packet_free_list_size, 0);
    atomic_set(&raw_socket->large_packet_free_list_size, 0);
#endif

#if RX_HANDLER_ATOMIC_ASSERT
    atomic_set(&raw_socket->debug_nr_entrance, 0);
#endif

    spin_lock_init(&raw_socket->lock);
    raw_socket->handler = handler;

    trace("socket created successfully: %X, %.*b, %d", raw_socket->ndev, 
                                                       6, raw_socket->mac_address, 
                                                       raw_socket->if_index);

    return raw_socket;

//unregister_rx:
//    netdev_rx_handler_unregister(ndev);
put_ndev:
    dev_put(ndev);
free_rtnl_lock:
    rtnl_unlock();
//free_large_packet_list:
    done_cmempool(&raw_socket->large_packet_pool);
//    vfree(raw_socket->large_packet_list);
free_l2packet_list:
    done_cmempool(&raw_socket->l2packet_pool);
//    vfree(raw_socket->l2packet_list);
free_raw_socket:
    vfree(raw_socket);
exit:
    return NULL;
}
EXPORT_SYMBOL(__open_raw_socket);

void close_raw_socket(struct raw_socket *raw_socket) {
    int i;

    atrace(raw_socket == NULL || raw_socket->ndev == NULL, return);
    
    for (i=0; i<MAX_PORTS; i++) {
        if (raw_socket->l2sockets[i])
            close_l2socket(raw_socket->l2sockets[i]);   
    }

    if (raw_socket->ndev) {
        trace("unregister rx_handler ndev: %lp", raw_socket->ndev);
        rtnl_lock();        
        netdev_rx_handler_unregister(raw_socket->ndev);
        rtnl_unlock();        

        trace("put ndev");
        dev_put(raw_socket->ndev);
        raw_socket->ndev = NULL;
    }
    
    done_cmempool(&raw_socket->l2packet_pool);
    done_cmempool(&raw_socket->large_packet_pool);
//    vfree(raw_socket->l2packet_list);
//    vfree(raw_socket->large_packet_list);

    vfree(raw_socket);
}
EXPORT_SYMBOL(close_raw_socket);

struct l2socket *__open_l2socket(struct raw_socket *raw_socket, int port, data_handler handler, bool run_from_softirq_context) {
    int i;
    struct l2socket *l2socket;

    if (raw_socket == NULL) {
        return NULL;
    }

    if (port == -1) {
        for (i=0; i<MAX_PORTS; ++i) {
            if (raw_socket->l2sockets[i] == NULL) {
                port = i;
                break;
            }
        }
    }

    if (port < 0 || port > MAX_PORTS-1) {
        return NULL;
    }

    if (raw_socket->l2sockets[port]) {
        etrace("port number already being used");
        return NULL;
    }

    l2socket = (struct l2socket*)vmalloc(sizeof(struct l2socket)); 
    if (l2socket == NULL) {
        etrace("failed to allocate memory");
        return NULL;
    }                                                                    

    l2socket->src_port = (unchar)port;
    l2socket->raw_socket = raw_socket;
    l2socket->handler = handler;
    l2socket->run_from_softirq_context = run_from_softirq_context;
    raw_socket->l2sockets[port] = l2socket;
    
    l2socket->large_packet_ready_queue = create_cqueue(large_packet_list_size);

    return l2socket;
}
EXPORT_SYMBOL(__open_l2socket);

void close_l2socket(struct l2socket *l2socket) {
    atrace(l2socket == NULL || l2socket->raw_socket == NULL, return);
        
    l2socket->raw_socket->l2sockets[(int)l2socket->src_port] = NULL;    
    free_cqueue(l2socket->large_packet_ready_queue);
    vfree(l2socket);
}
EXPORT_SYMBOL(close_l2socket);

void free_packet(struct bsocket *bsocket, struct biovec *biovec) {    
    struct large_packet *large_packet;

    large_packet = container_of(biovec, struct large_packet, biovec);                
#if TRACE_DEBUG
    // Make sure that iov points to the correct place
    atrace(large_packet->magic != (ulong)bsocket->l2socket->raw_socket, return);
#endif
    free_large_packet(bsocket->l2socket->raw_socket, large_packet);
}
EXPORT_SYMBOL(free_packet);

__always_inline int __send_iov(struct l2socket *l2socket, struct iovec *iov, size_t iov_len, struct l2address *l2address) {
    int res;
    res = zsend(l2socket, iov, iov_len, NULL, l2address);
    return res;
}
EXPORT_SYMBOL(__send_iov);

__always_inline int __send_buff(struct l2socket *l2socket, char *buff, size_t length, struct l2address *l2address) {
    struct iovec iov;
    int res = 0;

    iov.iov_base = buff;
    iov.iov_len = length;
    res = zsend(l2socket, &iov, 1, NULL, l2address);
    return res;
}
EXPORT_SYMBOL(__send_buff);

int send_iov(struct bsocket *bsocket, struct iovec *iov, size_t iov_len) {
    return __send_iov(bsocket->l2socket, iov, iov_len, &bsocket->l2address);
}
EXPORT_SYMBOL(send_iov);

int send_buff(struct bsocket *bsocket, char *buff, size_t length) {
    return __send_buff(bsocket->l2socket, buff, length, &bsocket->l2address);
}
EXPORT_SYMBOL(send_buff);

int send_skb(struct bsocket *bsocket, struct sk_buff *skb) {
    return sendskb(bsocket->l2socket, skb, &bsocket->l2address);
}
EXPORT_SYMBOL(send_skb);

void send_raw_skb(struct bsocket *bsocket, struct sk_buff *skb) {    
    __send_raw_skb(skb, bsocket->l2socket->raw_socket->ndev);
}
EXPORT_SYMBOL(send_raw_skb);

void init_l2address(struct l2address *l2address, 
                    unchar *mac_address, 
                    unchar port,
                    __u32 ip,
                    __be16 tcp_port) {
    copy_mac(l2address->mac_address, mac_address);
    l2address->port = port;

    /* TCP virtual socket */
    l2address->ip_addr = ip;
    l2address->tcp_port = tcp_port;

    l2address->tcpsession = NULL;

//    atomic_set(&l2address->tcpsocket.id, 1000-1);

//    atomic_set(&l2address->tcpsocket.seq, 0);
//    atomic_set(&l2address->tcpsocket.ack, 0);
//    l2address->tcpsocket.type = 0;
}
EXPORT_SYMBOL(init_l2address);

struct l2address *create_l2address(unchar *mac_address, unchar port,
                                   __u32 ip,
                                   __be16 tcp_port) {
    struct l2address *l2address;

    l2address = (struct l2address*)vmalloc(sizeof(struct l2address));
    if (l2address == NULL) {
        etrace("failed to allocate memory");
        return NULL;
    }                                                                    

    init_l2address(l2address, mac_address, port, 
                   ip,
                   tcp_port);
    return l2address;
}
EXPORT_SYMBOL(create_l2address);

void free_l2address(struct l2address *l2address) {
    vfree(l2address);
}
EXPORT_SYMBOL(free_l2address);
/*
void l2socket_address(struct l2address *l2address, struct l2socket *l2socket) {
    init_l2address(l2address, l2socket->raw_socket->mac_address, l2socket->src_port);
}
EXPORT_SYMBOL(l2socket_address);
*/
struct bsocket *l2socket_dequeue(struct l2socket *l2socket, struct biovec **biovec) {
    struct large_packet *large_packet;

    large_packet = l2socket_dequeue_large_packet(l2socket);
    if (large_packet) {
        *biovec = &large_packet->biovec;
        return &large_packet->bsocket;      
    }
    
    return NULL;
}
EXPORT_SYMBOL(l2socket_dequeue);

static __always_inline void __linearize_skb_portion(struct sk_buff *skb, size_t size) {
    unsigned int grow = size - skb_headlen(skb);
    skb_frag_t *frag = &skb_shinfo(skb)->frags[0];
//    atrace(grow > skb->len, return);
    atrace(grow > skb_frag_size(frag) && skb_shinfo(skb)->nr_frags > 1, return);
    grow = min(skb->len, grow);

    trace("skb->len: %d, skb->data_len: %d, skb_headlen: %d", 
        skb->len, skb->data_len, skb_headlen(skb));            
    skb->data_len -= grow;

    frag->page_offset += grow;
    skb_frag_size_sub(frag, grow);

    if (skb_frag_size(frag) == 0) {
        trace("freeing up frag[0]");
        skb_frag_unref(skb, 0);        
        memmove(skb_shinfo(skb)->frags,
            skb_shinfo(skb)->frags + 1,
            --skb_shinfo(skb)->nr_frags * sizeof(skb_frag_t));
    }

//    return grow;
}

static __always_inline void linearize_skb_portion(struct sk_buff *skb, size_t size) {
    unsigned int grow = size - skb_headlen(skb);
    skb_frag_t *frag = &skb_shinfo(skb)->frags[0];
    struct page *page = skb_frag_page(frag); 
//    int grow;

    atrace(grow > skb_frag_size(frag) && skb_shinfo(skb)->nr_frags > 1, return);
    grow = min(grow, (size_t)skb_frag_size(frag));
//    grow = min(size, (size_t)skb_frag_size(frag));
    trace("grow: %d, size: %d, frag_size: %d", grow, size, skb_frag_size(frag));
    trace("skb->data: %lp, skb->tail: %lp", skb->data, skb_tail_pointer(skb));
    if (!grow)
        return;

    memcpy(skb_tail_pointer(skb), 
        page_address(page) + frag->page_offset, 
        grow);   

    __linearize_skb_portion(skb, size); // grow);
    skb->tail += grow;
}

static __always_inline void strip_skb_headers(struct sk_buff *skb) {
    int header_size = L2_PACKET_HEADER_SIZE + sizeof(struct vrio_header);
    trace("stripping header_size: %d, skb->len: %d, skb_headroom: %d, skb_headlen: %d, skb_tailroom: %d, tailroom: %d", 
        header_size, skb->len, skb_headroom(skb), skb_headlen(skb), skb_tailroom(skb), skb->end - skb->tail);

    /* Complicated (bad) code, should be revised and simplified */

    if (header_size < skb_headlen(skb)) {
        int linearize_len = 54 + 10;

        skb_pull(skb, header_size);
        trace("(head: %lp, data: %lp, tail: %lp, end: %lp)", 
                skb->head, skb->data, skb->tail, skb->end);

        if (skb_headlen(skb) >= linearize_len)
            return;

        if (skb_shinfo(skb)->nr_frags &&  
            skb_headlen(skb) < linearize_len &&
            skb->len >= linearize_len) {
            trace("linearizing %d bytes (head: %lp, data: %lp, tail: %lp, end: %lp)", 
                linearize_len, skb->head, skb->data, skb->tail, skb->end);

            atrace((skb->end - skb->tail) < linearize_len, return);

            linearize_skb_portion(skb, linearize_len);
            trace("post linearize: %d", skb_headlen(skb));
        }
    } else {
        /* 
            
            Doesn't work

        */

        trace("using pskb_pull, header_size: %d, skb_headlen: %d, skb_shinfo(skb)->nr_frags: %d", header_size, skb_headlen(skb), skb_shinfo(skb)->nr_frags);        
        atrace(skb_shinfo(skb)->frag_list != NULL);

        if (skb_shinfo(skb)->nr_frags) {
            skb_reset_tail_pointer(skb);
            trace("skb_headroom(skb): %d, skb_tailroom(skb): %d",
                skb_headroom(skb), skb->end - skb->tail);

            __linearize_skb_portion(skb, header_size);
            skb->len -= header_size;
            linearize_skb_portion(skb, 10 + 54);
            trace("post linearizing (head: %lp, data: %lp, tail: %lp, end: %lp)", 
                   skb->head, skb->data, skb->tail, skb->end);
            trace("skb->data(%d): %.*b", skb_headlen(skb), skb_headlen(skb), skb->data);
            return;
        }

        etrace("error");
    }
}

struct sk_buff *detach_skb(struct biovec *biovec) {
    struct large_packet *large_packet;
    struct l2packet *l2packet;
    struct sk_buff *skb = NULL;
    large_packet = container_of(biovec, struct large_packet, biovec);

    if (likely(list_is_singular(&large_packet->l2packets))) {
        l2packet = list_first_entry(&large_packet->l2packets, struct l2packet, link);
        strip_skb_headers(l2packet->skb);

        skb = l2packet->skb;
        l2packet->skb = NULL;

    }
    return skb;
}
EXPORT_SYMBOL(detach_skb);

int llist_size(struct llist_head *head) {
    int i=0;
    struct llist_node *pos, *_head = (struct llist_node *)head;

    llist_for_each(pos, _head) {
        i++;
    }
    i--;

    return i;
}

int list_size(struct list_head *head) {
    int i=0;
    struct list_head *pos;

    list_for_each(pos, head) {
        i++;
    }

    return i;
}

void clear_socket_rx_buffers(struct raw_socket *raw_socket) {
    free_all(raw_socket);
}
EXPORT_SYMBOL(clear_socket_rx_buffers);

void trace_raw_socket(struct raw_socket *raw_socket) {
    int i;

    mtrace("raw_socket addr: %p", raw_socket);
    if (raw_socket == NULL) {
        return;
    }
    mtrace("if_index: %d", raw_socket->if_index);
    mtrace("mac_address: %.*b", 6, raw_socket->mac_address);
    mtrace("next_id: %d", atomic_read(&raw_socket->next_id)%256);

    for (i=0; i<MAX_PORTS; i++) {
        if (raw_socket->l2sockets[i]) {
            mtrace("l2socket[%d]: port: %d, handler: %p", i, raw_socket->l2sockets[i]->src_port, raw_socket->l2sockets[i]->handler);
            mtrace("  array: %lp", raw_socket->l2sockets[i]->large_packet_ready_queue->array);
            mtrace("  queue_max_size: %d", raw_socket->l2sockets[i]->large_packet_ready_queue->queue_max_size);    
            mtrace("  queue_size: %d", atomic_read(&raw_socket->l2sockets[i]->large_packet_ready_queue->queue_size));
            mtrace("  free_elm_index: %d", atomic_read(&raw_socket->l2sockets[i]->large_packet_ready_queue->free_elm_index));
            mtrace("  next_elm_index: %d", atomic_read(&raw_socket->l2sockets[i]->large_packet_ready_queue->next_elm_index));

#if TRACE_DEBUG
            mtrace("  stat_total_enqueue: %d", raw_socket->l2sockets[i]->large_packet_ready_queue->stat_total_enqueue);
            mtrace("  stat_total_dequeue: %d", raw_socket->l2sockets[i]->large_packet_ready_queue->stat_total_dequeue);

            mtrace("  stat_max_enqueue_rounds: %d", raw_socket->l2sockets[i]->large_packet_ready_queue->stat_max_enqueue_rounds);
            mtrace("  stat_max_dequeue_rounds: %d", raw_socket->l2sockets[i]->large_packet_ready_queue->stat_max_dequeue_rounds);

            if (raw_socket->l2sockets[i]->large_packet_ready_queue->stat_total_enqueue && raw_socket->l2sockets[i]->large_packet_ready_queue->stat_total_dequeue) {
                mtrace("  stat_avg_enqueue_rounds: %d", raw_socket->l2sockets[i]->large_packet_ready_queue->stat_total_enqueue_rounds / 
                                                        raw_socket->l2sockets[i]->large_packet_ready_queue->stat_total_enqueue);
                mtrace("  stat_avg_dequeue_rounds: %d", raw_socket->l2sockets[i]->large_packet_ready_queue->stat_total_dequeue_rounds / 
                                                        raw_socket->l2sockets[i]->large_packet_ready_queue->stat_total_dequeue);
            }
#endif
        }
    }                
    mtrace("ll2packet_free_list size: %d", cmempool_size(&raw_socket->l2packet_pool));// llist_size(&raw_socket->ll2packet_free_list));
    mtrace("llarge_packet_free_list size: %d", cmempool_size(&raw_socket->large_packet_pool));// llist_size(&raw_socket->llarge_packet_free_list));

#if TRACE_DEBUG
    mtrace("l2packet_free_list_size: %d", atomic_read(&raw_socket->l2packet_free_list_size));
    mtrace("large_packet_free_list_size: %d", atomic_read(&raw_socket->large_packet_free_list_size));
#endif

    mtrace("large_packet_used_list size: %d", list_size(&raw_socket->large_packet_used_list));
    mtrace("large_packet_ready_list size: %d", list_size(&raw_socket->large_packet_ready_list));
}
EXPORT_SYMBOL(trace_raw_socket);

void trace_large_packet(struct large_packet* large_packet) {
    struct l2packet *l2packet, *prev_l2packet = NULL;

    mtrace("large_packet->packet_size: %d", large_packet->packet_size); 
    mtrace("large_packet->uid: %X", large_packet->uid);

    if (!list_empty(&large_packet->l2packets)) {                
        list_for_each_entry(l2packet, &large_packet->l2packets, link) {        
            mtrace("l2header->flags: %d", L2_PACKET_TO_HDR(l2packet)->flags);
            mtrace("l2header->src_port: %d", L2_PACKET_TO_HDR(l2packet)->src_port);
            mtrace("l2header->dest_port: %d", L2_PACKET_TO_HDR(l2packet)->dest_port);
            mtrace("l2header->packet_id: %d", L2_PACKET_TO_HDR(l2packet)->packet_id);
            mtrace("l2header->expected_packet_size: %d", L2_PACKET_TO_HDR(l2packet)->expected_packet_size);
            mtrace("L2_PACKET_TO_IP_HDR(l2packet)->id: %d (seq16) ", L2_PACKET_TO_IP_HDR(l2packet)->id);
            mtrace("l2packet->partial_size: %d", l2packet->partial_size);
            mtrace("L2_PACKET_TO_TCP_HDR(l2packet)->seq: %d", L2_PACKET_TO_TCP_HDR(l2packet)->seq);
            mtrace("L2_PACKET_TO_TCP_HDR(l2packet)->ack_seq: %d", L2_PACKET_TO_TCP_HDR(l2packet)->ack_seq);

//            if (prev_l2packet) {                
//                atrace(l2packetHashID(prev_l2packet) != l2packetHashID(l2packet), 
//                       return);
//                atrace(l2packetUID(prev_l2packet) != l2packetUID(l2packet), return);
//            } else {
//                atrace((channel_flags(l2packet) & F_FIRST_FRAGMENT) == 0, return);
//            }
            prev_l2packet = l2packet;
        }
                           
        l2packet = container_of((&large_packet->l2packets)->prev, struct l2packet, link);
        atrace((channel_flags(l2packet) & F_LAST_FRAGMENT) == 0, return);
    }

    mtrace("LP seems to be correct");
    return;
}

void trace_biovec(struct biovec *biovec) {
    struct large_packet *large_packet;
    large_packet = container_of(biovec, struct large_packet, biovec);

    trace_large_packet(large_packet);
}
EXPORT_SYMBOL(trace_biovec);

bool __unit_test_cqueue(struct cqueue *cqueue) {
    bool ret = false;
    int res;
    
    struct cqueue_struct cq_elm[5];
    struct cqueue_struct *cq_elm_ptr;
   
    init_cqueue_elm(&cq_elm[0]);
    init_cqueue_elm(&cq_elm[1]);
    init_cqueue_elm(&cq_elm[2]);
    init_cqueue_elm(&cq_elm[3]);
    init_cqueue_elm(&cq_elm[4]);

    print_cqueue(cqueue);
    
    res = cenqueue(cqueue, &cq_elm[0]);
    atrace(res != CQUEUE_SUCCESS, goto out);
    res = cenqueue(cqueue, &cq_elm[0]);
    atrace(res != CQUEUE_ELM_IN_QUEUE, goto out);
    res = cenqueue(cqueue, &cq_elm[1]);
    atrace(res != CQUEUE_SUCCESS, goto out);
    res = cenqueue(cqueue, &cq_elm[2]);
    atrace(res != CQUEUE_QUEUE_IS_FULL, goto out);

    print_cqueue(cqueue);
    
    cq_elm_ptr = cdequeue(cqueue);
    atrace(cq_elm_ptr != &cq_elm[0], goto out);
    cq_elm_ptr = cdequeue(cqueue);
    atrace(cq_elm_ptr != &cq_elm[1], goto out);
    cq_elm_ptr = cdequeue(cqueue);
    atrace(cq_elm_ptr != NULL, goto out);

    print_cqueue(cqueue);

    ret = true;
out:
    return ret;
}

bool unit_test_cqueue(void) {
    bool ret = false;
    struct cqueue cqueue;

    if (init_cqueue(&cqueue, 2) == false) 
        return false;

    atrace(__unit_test_cqueue(&cqueue) == false, goto out);
    atrace(__unit_test_cqueue(&cqueue) == false, goto out);
    atrace(__unit_test_cqueue(&cqueue) == false, goto out);
    ret = true;

out:
    done_cqueue(&cqueue);
    return ret;
}










static __always_inline void set_skb_frag(struct sk_buff *skb, 
                                struct page *page,
                                unsigned int offset, 
                                unsigned int size, 
                                struct skb_frag_destructor *destroy) 
{
    int i = skb_shinfo(skb)->nr_frags;

    __skb_fill_page_desc(skb, i, page, offset, size);
    if (destroy) {
        skb_frag_set_destructor(skb, i, destroy);
        skb_frag_ref(skb, i);
    }
    skb->data_len += size;
    skb->len += size;
    skb->truesize += PAGE_SIZE;
    skb_shinfo(skb)->nr_frags++;
}

static __always_inline struct page *vaddr_to_page(void *vaddr) 
{
    if (is_vmalloc_addr(vaddr)) {
        trace("is_vmalloc_addr: %lp", vaddr);
        return vmalloc_to_page(vaddr);
    } else if (virt_addr_valid(vaddr)) {
        trace("virt_addr_valid: %lp", vaddr);
        return virt_to_page(vaddr);
    } else {
        etrace("Unknown address type (%lp)", vaddr);
        return NULL;
    }
}

static __always_inline int map_iovec_to_skb(struct sk_buff *skb, 
                                   struct iovec *iov, 
                                   size_t iov_len, 
                                   struct skb_frag_destructor *destroy) 
{
    unsigned int len;
#if TRACE_DEBUG
    struct iovec *_iov = iov;
    size_t        _iov_len = iov_len;
    int           i;
#endif

    while (iov_len--) {
        unsigned long base;

        len = iov->iov_len;
        if (!len) {
            ++iov;
            continue;
        }

        base = (unsigned long)iov->iov_base;
        while (len) {
            unsigned int off = base & ~PAGE_MASK;
            unsigned int size = min_t(unsigned int, len, PAGE_SIZE - off);
            unsigned long aligned_base = base & PAGE_MASK;
            struct page *page, *new_page;

            page = new_page = vaddr_to_page((void *)aligned_base);
            if (page == NULL) {
                etrace("vaddr_to_page returned NULL");
                return -EFAULT;
            }
            
            if (destroy == NULL) {
                new_page = alloc_page(GFP_ATOMIC);
                if (new_page == NULL) {
                    etrace("alloc_page returned NULL");
                    return -ENOMEM;
                }
                    
                memcpy(page_address(new_page) + off, page_address(page) + off, size);
            }
            set_skb_frag(skb, new_page, off, size, destroy);

            if (skb_shinfo(skb)->nr_frags > MAX_SKB_FRAGS) {
                etrace("MAX_SKB_FRAGS (%d) is not big enough", MAX_SKB_FRAGS);
#if TRACE_DEBUG
                etrace("iov_len: %d, _iov_len: %d", iov_len, _iov_len);
                for (i=0; i<_iov_len; i++) {
                    etrace("iov(%d).iov_base: %.*b", _iov[i].iov_len, _iov[i].iov_len, _iov[i].iov_base);
                    len = _iov[i].iov_len;
                    base = (unsigned long)iov->iov_base;
                    while (len) {
                        off = base & ~PAGE_MASK;
                        size = min_t(unsigned int, len, PAGE_SIZE - off);
                        aligned_base = base & PAGE_MASK;
    
                        etrace("(%d) frag address: %lp, offset: %d, size: %d", i, aligned_base, off, size);
                        base += size;
                        len -= size;
                    }
                }
#endif
                return -EMSGSIZE;
            }
            base += size;
            len -= size;
        }
        
        ++iov;
    }

    return 0;
}

#define GOOD_COPY_LEN 256

__always_inline struct sk_buff *iovec_to_skb(struct net_device *dev,
                                    struct iovec *iov,
                                    size_t iov_len,
                                    struct skb_frag_destructor *destroy) 
{
    unsigned int len = iov_length(iov, iov_len), copy;
    struct sk_buff *skb;
    int ret;

    if (likely(destroy))
        skb_frag_destructor_ref(destroy);

//    if (unlikely(iov_len > MAX_SKB_FRAGS))
//        copy = iov_length(iov, iov_len - MAX_SKB_FRAGS);
//    else
//        copy = len < GOOD_COPY_LEN ? len : GOOD_COPY_LEN;
    copy = len < GOOD_COPY_LEN ? len : GOOD_COPY_LEN;
//    copy = min(len, GOOD_COPY_LEN);

//    atrace(copy > PAGE_SIZE);

    skb = netdev_alloc_skb_ip_align(dev, copy);
    if (unlikely(!skb)) {
        etrace("netdev_alloc_skb_ip_align failed");
        goto out;
    }

    skb_put(skb, copy);
    ret = memcpy_fromiovecend_skip(skb->data, iov, iov_len, copy);
    atrace(ret != 0, goto free_skb);

    len -= copy;
    if (likely(len)) {
        if (map_iovec_to_skb(skb, iov, iov_len, destroy)) {
            etrace("map_iovec_to_skb failed");
            goto free_skb;
        }
    }

out:
    if (destroy)
        skb_frag_destructor_unref(destroy);

    return skb;

free_skb:
    dev_kfree_skb(skb);

    if (destroy)
        skb_frag_destructor_unref(destroy);
    return NULL;
}
EXPORT_SYMBOL(iovec_to_skb);

__always_inline int zsend(struct l2socket *l2socket, 
                 struct iovec *iov, 
                 size_t iov_len, 
                 struct skb_frag_destructor *destroy, 
                 struct l2address *l2address) {
    int len = iov_length(iov, iov_len), skb_len, expected_lpacket_size = len;
    unchar packet_id = get_next_packet_id(l2socket->raw_socket);
    struct sk_buff *skb;
    struct iovec _iov[MAX_SKB_FRAGS];
    size_t _iov_len;
    u32 seq; // = adjust_tcp_session_seq_number(l2address, len);  // atomic_add_return(len, &l2address->tcpsocket.seq) - len;
    int err = -1;
    
    attach_tcp_session(l2socket->raw_socket, l2address);
    seq = adjust_tcp_session_seq_number(l2address, len);  // atomic_add_return(len, &l2address->tcpsocket.seq) - len;

    if (likely(destroy))
        skb_frag_destructor_ref(destroy);

#define MAX_SIZE_P 65400
      do {
//    while (len > 0) {
        _iov_len = move_iovec_page(iov /* from */, _iov /* to */, 
                                   MAX_SIZE_P, MAX_SKB_FRAGS, iov_len);
        trace("len: %d, _iov_len: %d, expected_lpacket_size: %d, iov_len: %d", 
                len, _iov_len, expected_lpacket_size, iov_len);
        skb = iovec_to_skb(l2socket->raw_socket->ndev, _iov, _iov_len, destroy);
        if (unlikely(!skb)) {
            etrace("iovec_to_skb failed to create skb");
            goto error;
        }

        skb_len = skb->len;
        err = __sendskb(l2socket, skb, l2address, 
                        packet_id,
                        seq, expected_lpacket_size);

        if (unlikely(err < 0)) {
            etrace("__sendskb failed with %d, len: %d, expected_lpacket_size: %d", 
                    err, len, expected_lpacket_size);
            goto error;            
        }

        trace("skb_len: %d", skb_len);
        len -= skb_len;
        seq += skb_len;
    } while (len > 0);
    
    if (likely(destroy))
        skb_frag_destructor_unref(destroy);
    
//    if (expected_lpacket_size > debug_lp_min)
//        mtrace("lpacket_size: %d", expected_lpacket_size);
    return expected_lpacket_size;

error:
    if (destroy)
        skb_frag_destructor_unref(destroy);

    return err;
}

int zbsend_iov(struct bsocket *bsocket, 
              struct iovec *iov, 
              size_t iov_len, 
              struct skb_frag_destructor *destroy) {
    return zsend(bsocket->l2socket, iov, iov_len, destroy, &bsocket->l2address);
}
EXPORT_SYMBOL(zbsend_iov);


#define ns_to_us(x) (x >> 10)
#define us_to_ns(x) (x << 10)

static inline u64 get_us_clock(void)
{
    return ns_to_us(sched_clock());
}

ulong issue_time;
struct hrtimer timer;

static __always_inline enum hrtimer_restart timer_callback(struct hrtimer *timer)
{
    trace("timer_callback: duration: %d", get_us_clock() - issue_time);
 //   trace("timer_callback try: %d, timeout us (%d), actual duration: (%d)", 
//           vbr->retries, get_req_timeout(vbr), get_us_clock() - vbr->issue_time);

    return HRTIMER_NORESTART;
}

static __always_inline void setup_req_timer(ulong get_req_timeout) { // struct vrio_blk *vblk, struct virtblk_req *vbr) {
//    ulong get_req_timeout = 5e4;
    ktime_t ktime = ktime_set(0, us_to_ns(get_req_timeout));
    int err;
    
    trace("setup_req_timer (timeout us: %d)", get_req_timeout);
    hrtimer_init(&timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    timer.function = &timer_callback;
    err = hrtimer_start(&timer, ktime, HRTIMER_MODE_REL);
    atrace(err != 0);
}

static int __init eth_init(void) {
    mtrace("module vrio_eth up, l2_packet_size: %d", l2_packet_size);
    mtrace("L2_PACKET_HEADER_SIZE: %d", L2_PACKET_HEADER_SIZE);
/*
    char buff[64+1] = "AAAAAAAAAAAAAAAAA" \
                    "BBBBBBBBBBBBBBBBB" \
                    "CCCCCCCCCCCCCCCCC" \
                    "DDDDDDDDDDDDDDDDD";
    char key[16+1] =  "ABCDEFGHIJKLMNOPQ";

    mtrace("plain: %.*b", 64, buff);
    encrypt(buff, 64, key);
    mtrace("enc: %.*b", 64, buff);
    decrypt(buff, 64, key);
    mtrace("dec: %.*b", 64, buff);
*/

/*
    issue_time = get_us_clock();
    setup_req_timer(5e4);
    mdelay(1000);
    issue_time = get_us_clock();
    setup_req_timer(5e5);
    mdelay(1000);
    issue_time = get_us_clock();
    setup_req_timer(5e6);
*/
#if TRACE_DEBUG
//    atrace(unit_test_cqueue() == false, return -1);
//    atrace(test_smp_cqueue(extensive_unit_test) == false, return -1);
//    atrace(test_smp_l2packet(extensive_unit_test) == false, return -1);
#endif
    return 0;
}

 void __exit eth_exit(void) {
    mtrace("module eth down");
}

module_init(eth_init);
module_exit(eth_exit);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Yossi Kuperman");
MODULE_DESCRIPTION("vRIO - Ethernet as a transport");
#endif
