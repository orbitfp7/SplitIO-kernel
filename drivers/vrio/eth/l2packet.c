#if 1 /* patchouli vrio-eth-module */
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <linux/virtio_net.h>
#include <linux/mm.h>
#include <net/flow_keys.h>
#include <net/ip.h>
#include <linux/highmem.h>
#include <linux/skbuff.h>

// #define TRACE_LEVEL 4
#include <linux/vrio/trace.h>
#include <linux/vrio/utils.h>
#include <linux/vrio/vrio.h>

#include "l2packet.h"

TRACE_EXCLUDE("validate_l2packet", "iov_set_buf", "__skb_to_iovec", "__recv_l2packet_skb", "is_l2packet_valid");
// TRACE_ALL;

extern int is_using_rdtsc;
extern long l2p_tx_work_cycles;

#if TRACE_ENABLED
static void rs_trace(struct raw_socket *raw_socket) {
    int i;

    mtrace("raw_socket addr: %p", raw_socket);
    if (raw_socket == NULL) {
        return;
    }
    mtrace("if_index: %d", raw_socket->if_index);
    mtrace("mac_address: %.*b", 6, raw_socket->mac_address);
    mtrace("next_id: %d", atomic_read(&raw_socket->next_id));

    for (i=0; i<MAX_PORTS; i++) {
        if (raw_socket->l2sockets[i]) {
            mtrace("l2socket[%d]: port: %d, handler: %p", i, raw_socket->l2sockets[i]->src_port, raw_socket->l2sockets[i]->handler);
        }
    }

#if TRACE_DEBUG
    mtrace("l2packet_free_list_size: %d", atomic_read(&raw_socket->l2packet_free_list_size));
    mtrace("large_packet_free_list_size: %d", atomic_read(&raw_socket->large_packet_free_list_size));
#endif
}
#endif


static __always_inline void init_l2packet(struct l2packet *l2packet) {        
    // Initialize new l2packet struct        
    INIT_LIST_HEAD(&l2packet->link);      
#if TRACE_DEBUG
    atomic_set(&l2packet->being_used, 1);
#endif 
}
void trace_raw_socket(struct raw_socket *raw_socket);

static __always_inline void put_l2packet(struct raw_socket *raw_socket, struct l2packet *l2packet) {    
#if TRACE_DEBUG
    atrace(atomic_dec_return(&l2packet->being_used) != 0, strace());
#endif
//    llist_add(&l2packet->llink, &raw_socket->ll2packet_free_list);
    cmempool_free(&raw_socket->l2packet_pool, l2packet);
#if TRACE_DEBUG
    atomic_dec(&raw_socket->l2packet_free_list_size);
#endif
       
    l2packet->iov[1].iov_len = 0;
}

void init_l2packet_free_list(struct raw_socket *raw_socket) {
    int i;
//    struct l2packet *l2packet = raw_socket->l2packet_list;
    struct l2packet *l2packet;

 //   init_llist_head(&raw_socket->ll2packet_free_list);
    for (i=0; i<l2_packet_list_size; i++) {
        l2packet = cmempool_alloc(&raw_socket->l2packet_pool);
        atrace(l2packet == NULL);
        init_l2packet(l2packet);
        put_l2packet(raw_socket, l2packet);
//        l2packet++;
    }
}

static __always_inline struct l2packet* __alloc_l2packet(struct raw_socket *raw_socket) {
    struct l2packet *l2packet; //  = NULL;
//    struct llist_node *llist_node;

    l2packet = cmempool_alloc(&raw_socket->l2packet_pool);
  if (likely(l2packet)) {
//    llist_node = llist_del_first(&raw_socket->ll2packet_free_list);
//    if (likely(llist_node)) {
//        l2packet = llist_entry(llist_node, struct l2packet, llink);
#if TRACE_DEBUG
        atomic_inc(&raw_socket->l2packet_free_list_size);
        atrace(atomic_inc_return(&l2packet->being_used) != 1, strace());
#endif
    }

    return l2packet;
}

static __always_inline void free_l2packet(struct raw_socket *raw_socket, struct l2packet* l2packet) {
    if (l2packet->skb) {
        trace("freeing skb");
        kfree_skb(l2packet->skb);
        l2packet->skb = NULL;
    }
    put_l2packet(raw_socket, l2packet);
}

void init_large_packet_hash(struct raw_socket *raw_socket) {
    int i;

    for (i=0; i<HASH_KEY_RANGE; i++) {
        INIT_LIST_HEAD(&raw_socket->large_packet_hash[i]);        
    }
}

static __always_inline void init_large_packet(struct large_packet *large_packet) {        
    // Initialize new large_packet struct        
    INIT_LIST_HEAD(&large_packet->link);
    INIT_LIST_HEAD(&large_packet->hlink);
    INIT_LIST_HEAD(&large_packet->l2packets);    
    init_cqueue_elm(&large_packet->clink);
}

static __always_inline void put_large_packet(struct raw_socket *raw_socket, struct large_packet *large_packet) {    
    init_large_packet(large_packet);
#if TRACE_DEBUG
        large_packet->magic = (ulong)raw_socket;
#endif
//    llist_add(&large_packet->llink, &raw_socket->llarge_packet_free_list);
    cmempool_free(&raw_socket->large_packet_pool, large_packet);

#if TRACE_DEBUG
    atomic_dec(&raw_socket->large_packet_free_list_size);
#endif
}

void init_large_packet_free_list(struct raw_socket *raw_socket) {
    int i;
//    struct large_packet *large_packet = raw_socket->large_packet_list;
    struct large_packet *large_packet;

//    init_llist_head(&raw_socket->llarge_packet_free_list);
    for (i=0; i<large_packet_list_size; i++) {
        large_packet = cmempool_alloc(&raw_socket->large_packet_pool);

        put_large_packet(raw_socket, large_packet);
//        large_packet++;
    }

    INIT_LIST_HEAD(&raw_socket->large_packet_used_list);
    INIT_LIST_HEAD(&raw_socket->large_packet_ready_list);
}

static __always_inline struct large_packet* __alloc_large_packet(struct raw_socket *raw_socket) {
    struct large_packet *large_packet; // = NULL;
    large_packet = cmempool_alloc(&raw_socket->large_packet_pool);
//    struct llist_node *llist_node;
    if (large_packet) {
//    llist_node = llist_del_first(&raw_socket->llarge_packet_free_list);
//    if (llist_node) {
//        large_packet = llist_entry(llist_node, struct large_packet, llink);
#if TRACE_DEBUG
        atomic_inc(&raw_socket->large_packet_free_list_size);
#endif
    }

    return large_packet;
}

__always_inline void free_large_packet(struct raw_socket *raw_socket, struct large_packet* large_packet) {
    struct l2packet* i, *n;

    if (likely(!list_empty(&large_packet->l2packets))) {
        list_for_each_entry_safe(i, n, &large_packet->l2packets, link) {
            list_del(&i->link);
            free_l2packet(raw_socket, i);
        }
    }

    put_large_packet(raw_socket, large_packet);
}

static __always_inline void __free_large_packet(struct raw_socket *raw_socket, struct large_packet* large_packet) {
    list_del(&large_packet->link);    
    list_del(&large_packet->hlink);        
    free_large_packet(raw_socket, large_packet);
}

static __always_inline void free_LRU_large_packet(struct raw_socket *raw_socket) {
    struct large_packet* large_packet;

    if (likely(!list_empty(&raw_socket->large_packet_used_list))) {      
        large_packet = container_of(raw_socket->large_packet_used_list.prev, struct large_packet, link);

        etrace("freed LRU large packet");
        __free_large_packet(raw_socket, large_packet);
    }
}

__always_inline void free_all(struct raw_socket *raw_socket) {
    struct large_packet *i, *n;
    int nr_lpackets = 0;

    mtrace("freeing all used large packets and l2packets structures");
    list_for_each_entry_safe(i, n, &raw_socket->large_packet_used_list, link) {
        __free_large_packet(raw_socket, i);
        ++nr_lpackets;
    }

    mtrace("freed %d lpackets", nr_lpackets);
}

static __always_inline bool is_l2packet_valid(struct raw_socket *raw_socket, struct l2packet* l2packet, int res) {
    struct ethhdr *l2ethhdr = L2_PACKET_TO_ETH_HDR(l2packet); 

    // No magic? something wrong.
//    if (unlikely(L2_PACKET_TO_IP_HDR(l2packet)->saddr != CHANNEL_MAGIC)) {
    if (unlikely(channel_magic(l2packet) != CHANNEL_MAGIC)) {
        trace("l2packet header MAGIC doesn't match (%X / %X)", 
                channel_magic(l2packet), 
//                L2_PACKET_TO_IP_HDR(l2packet)->saddr, 
               CHANNEL_MAGIC);
        return false;
    }

    // Was it destined to me?
    if (unlikely(l2ethhdr->h_dest[0] != raw_socket->mac_address[0] ||
                 l2ethhdr->h_dest[1] != raw_socket->mac_address[1] ||
                 l2ethhdr->h_dest[2] != raw_socket->mac_address[2] ||
                 l2ethhdr->h_dest[3] != raw_socket->mac_address[3] ||
                 l2ethhdr->h_dest[4] != raw_socket->mac_address[4] ||
                 l2ethhdr->h_dest[5] != raw_socket->mac_address[5]))
    {                                          
        trace("l2packet header MAC doesn't match (%.*b / %.*b)", 6, l2ethhdr->h_dest, 6, raw_socket->mac_address);
        return false;
    }

    return true;
}

static __always_inline void iov_set_buf(struct iovec *iov, void *iov_base, size_t iov_len) {
    iov[0].iov_base = iov_base;
    iov[0].iov_len = iov_len;
    trace("iov_base(%d): %.*b", iov_len, iov_len, iov_base);
}

static __always_inline size_t __skb_to_iovec(struct sk_buff *skb, struct iovec *iov) {
    size_t iov_len = 0;

    trace("skb->len: %d, skb_shinfo(skb)->nr_frags: %d, skb_headlen(skb): %d", skb->len, skb_shinfo(skb)->nr_frags, skb_headlen(skb));

    if (likely(skb_shinfo(skb)->nr_frags)) {
        int offset_delta = skb_headlen(skb);
        struct page *page;
        skb_frag_t *frag;
        int i;

        trace("offset_delta: %d", offset_delta);
        for (i=0; i<skb_shinfo(skb)->nr_frags; i++) {
            frag = &skb_shinfo(skb)->frags[i];
            page = skb_frag_page(frag); 
            
            iov_set_buf(iov++, page_address(page) + frag->page_offset - offset_delta, skb_frag_size(frag) + offset_delta);
            iov_len++;
            offset_delta = 0;
        }
    } else {
        iov_set_buf(iov++, skb->data, skb_headlen(skb));
        iov_len++; 
    }

//    atrace(skb_shinfo(skb)->frag_list != NULL);
    return iov_len;
}

static __always_inline size_t skb_to_iovec(struct sk_buff *skb, struct iovec *iov) {
    size_t iov_len = __skb_to_iovec(skb, iov);
    struct sk_buff *fs;

    if (skb_has_frag_list(skb)) {
//        etrace("skb_has_frag_list");
//        return iov_len;
        skb_walk_frags(skb, fs) 
            iov_len += __skb_to_iovec(fs, iov + iov_len);
    }

    return iov_len;
}

static __always_inline struct l2packet* alloc_l2packet(struct raw_socket *raw_socket) {
    struct l2packet* l2packet;

    l2packet = __alloc_l2packet(raw_socket);
    if (!l2packet) {
        // Try to free up a dangling resource
        etrace("failed to allocate l2packet, freeing LRU");
        free_LRU_large_packet(raw_socket);
        l2packet = __alloc_l2packet(raw_socket);
    }

#if TRACE_DEBUG
    if (unlikely(!l2packet)) {
        etrace("second failure to allocate l2packet");
        rs_trace(raw_socket);
    }
#endif

    return l2packet;
}

static __always_inline struct l2packet* __recv_l2packet_skb(struct raw_socket *raw_socket, int *res, struct sk_buff *skb) {
    struct l2packet* l2packet;

    l2packet = alloc_l2packet(raw_socket);    
    if (l2packet) {
        l2packet->skb = skb;
        *res =  l2packet->skb->len;
        l2packet->iov_len = skb_to_iovec(l2packet->skb, l2packet->iov);
        trace("skb->len: %d, l2packet->iov_len: %d", l2packet->skb->len, l2packet->iov_len);
        atrace(iov_length(l2packet->iov, l2packet->iov_len) != l2packet->skb->len, 
            etrace("iov_length(l2packet->iov, l2packet->iov_len): %d, l2packet->skb: %d", 
                iov_length(l2packet->iov, l2packet->iov_len), l2packet->skb->len));
#if TRACE_DEBUG
        if (l2packet->iov[0].iov_len + l2packet->iov[1].iov_len < 
            /*ETHHDR_SIZE + IPHDR_SIZE + TCPHDR_SIZE*/L2_PACKET_HEADER_SIZE) {                
                trace("l2packet->iov[0].iov_len + l2packet->iov[1].iov_len: %d", l2packet->iov[0].iov_len + l2packet->iov[1].iov_len);
                goto packet_error;
        }
#endif

        l2packet->l2_mac_header = l2packet->iov[0].iov_base;
        if (l2packet->iov[0].iov_len == ETHHDR_SIZE) {
//            l2packet->l2_mac_header = l2packet->iov[0].iov_base;
            l2packet->l2_network_header = l2packet->iov[1].iov_base;
            l2packet->l2_transport_header = l2packet->l2_network_header + IPHDR_SIZE; // ((unchar *)l2packet->iov[1].iov_base) + IPHDR_SIZE;
            l2packet->l2_header = l2packet->l2_transport_header + TCPHDR_SIZE;
        } else if (l2packet->iov[0].iov_len == ETHHDR_SIZE + IPHDR_SIZE) {
//            l2packet->l2_mac_header = l2packet->iov[0].iov_base;
            l2packet->l2_network_header = l2packet->l2_mac_header + ETHHDR_SIZE; // ((unchar *)l2packet->iov[0].iov_base) + sizeof(struct ethhdr);
            l2packet->l2_transport_header = l2packet->iov[1].iov_base;
            l2packet->l2_header = l2packet->l2_transport_header + TCPHDR_SIZE;
        } else if (l2packet->iov[0].iov_len == ETHHDR_SIZE + IPHDR_SIZE + TCPHDR_SIZE) {
//            l2packet->l2_mac_header = l2packet->iov[0].iov_base;
            l2packet->l2_network_header = l2packet->l2_mac_header + ETHHDR_SIZE;// ((unchar *)l2packet->iov[0].iov_base) + ETHHDR_SIZE;
            l2packet->l2_transport_header = l2packet->l2_network_header + IPHDR_SIZE; // ((unchar *)l2packet->iov[0].iov_base) + ETHHDR_SIZE + IPHDR_SIZE;
            l2packet->l2_header = l2packet->iov[1].iov_base;
        } else {
//            l2packet->l2_mac_header = l2packet->iov[0].iov_base;
            l2packet->l2_network_header = l2packet->l2_mac_header + ETHHDR_SIZE;// ((unchar *)l2packet->iov[0].iov_base) + ETHHDR_SIZE;
            l2packet->l2_transport_header = l2packet->l2_network_header + IPHDR_SIZE; // ((unchar *)l2packet->iov[0].iov_base) + ETHHDR_SIZE + IPHDR_SIZE;
            l2packet->l2_header = l2packet->l2_transport_header + TCPHDR_SIZE;
        }

          trace("virtio_net_hdr: %d", (int)sizeof(struct virtio_net_hdr));
          trace("l2_mac_header: %.*b, l2_network_header: %.*b, l2_transport_header: %.*b, l2_header: %.*b",						
                        14, l2packet->l2_mac_header,
                        20, l2packet->l2_network_header,
                        20, l2packet->l2_transport_header,
                        L2HDR_SIZE, l2packet->l2_header);
    }
//*res = -EAGAIN;
//put_l2packet(raw_socket, l2packet);
//l2packet = NULL;
    return l2packet;

#if TRACE_DEBUG
packet_error:
    *res = -EAGAIN; 
    return l2packet;
#endif    
}

static __always_inline struct l2packet* validate_l2packet(struct raw_socket *raw_socket, struct l2packet* l2packet, int res) {
    if (res < 0 || !is_l2packet_valid(raw_socket, l2packet, res)) {
        // Packet wasn't meant for us or some error occurred, let's free up resources.
#if TRACE_DEBUG         
        if (res != -EAGAIN) {          
       /*n*/trace("l2packet is being freed as it seems to be invalid (res: %d)", res);            
        }
#endif
        put_l2packet(raw_socket, l2packet);
        l2packet = NULL;
    } else {
#if TRACE_DEBUG && !L2_FRAGMENTATION_OFFLOAD         
        if (likely((channel_flags(l2packet) & F_MIN_SIZE_FRAGMENT) == 0)) {
            atrace(channel_packet_size(l2packet) != res);          
        }
#endif

#if L2_FRAGMENTATION_OFFLOAD
        l2packet->packet_size = res - L2_PACKET_HEADER_SIZE;
#else
        l2packet->packet_size = (int)channel_packet_size(l2packet) - L2_PACKET_HEADER_SIZE;
#endif
    }
    
    return l2packet;
}

struct l2packet* recv_l2packet_skb(struct raw_socket *raw_socket, struct sk_buff *skb) {
    struct l2packet* l2packet;
    int res;

    l2packet = __recv_l2packet_skb(raw_socket, &res, skb);
    if (l2packet) {        
        l2packet = validate_l2packet(raw_socket, l2packet, res);

#if TRACE_DEBUG
        if (l2packet) {
           trace("l2packet->packet_size: %d", l2packet->packet_size);
           trace("l2packet->id: %d",          channel_id(l2packet));
           trace("l2packet->src_port: %d",    channel_src_port(l2packet));
           trace("l2packet->dest_port: %d",   channel_dest_port(l2packet));
           trace("l2packet->flags: %d",       channel_flags(l2packet));
           trace("l2packet->skb->len: %d, l2packet->iov_len: %d, skb_shinfo(skb)->nr_frags: %d, skb_headlen(skb): %d", 
                l2packet->skb->len, 
                l2packet->iov_len, 
                skb_shinfo(skb)->nr_frags, 
                skb_headlen(skb)); 
        }
#endif
    }

    return l2packet;
}

static __always_inline struct large_packet* alloc_large_packet(struct raw_socket *raw_socket) {
    struct large_packet* large_packet;

    large_packet = __alloc_large_packet(raw_socket);
    if (unlikely(!large_packet)) {
        // Try to free up a dangling resource
        etrace("failed to allocate large_packet, freeing LRU");
        free_LRU_large_packet(raw_socket);
        large_packet = __alloc_large_packet(raw_socket);
    }
#if TRACE_DEBUG
    if (unlikely(!large_packet)) {
        etrace("second failure to allocate large_packet");
        rs_trace(raw_socket);
    }
#endif
    return large_packet;
}

static __always_inline uint16_t l2packetHashID(struct l2packet* l2packet) {
    struct ethhdr *l2ethhdr  = L2_PACKET_TO_ETH_HDR(l2packet); 

    return ((l2ethhdr->h_source[5] << 8) | 
            (channel_id(l2packet)  << 0)) & 0xFFFF;
}

static __always_inline uint64_t l2packetUID(struct l2packet* l2packet) {
    struct ethhdr *l2ethhdr  = L2_PACKET_TO_ETH_HDR(l2packet); 

    return (((uint64_t)(l2ethhdr->h_source[5]) << 48) | 
            ((uint64_t)(l2ethhdr->h_source[4]) << 40) | 
            ((uint64_t)(l2ethhdr->h_source[3]) << 32) | 
            ((uint64_t)(l2ethhdr->h_source[2]) << 24) | 
            ((uint64_t)(l2ethhdr->h_source[1]) << 16) | 
            ((uint64_t)(l2ethhdr->h_source[0]) << 8)  | 
            (channel_id(l2packet)  << 0));
}

bool process_l2packet(struct raw_socket *raw_socket, struct l2packet* l2packet) {
    struct large_packet *large_packet, *i;
    uint64_t uid;
    int hashid;
    
    large_packet = NULL;

    // Fast track - tackle single-fragment packets fast
    if (likely((channel_flags(l2packet) & F_SINGLE_FRAGMENT) == F_SINGLE_FRAGMENT)) { // && likely(ntohl(L2_PACKET_TO_TCP_HDR(l2packet)->seq) == 0)) {
        large_packet = alloc_large_packet(raw_socket);
        if (unlikely(!large_packet)) {
            etrace("l2packet is being freed due to alloc_large_packet failure"); 
            free_l2packet(raw_socket, l2packet);
            return false;
        }
    
        list_add_tail(&l2packet->link, &large_packet->l2packets);
        list_add(&large_packet->link, &raw_socket->large_packet_ready_list);

#if L2_FRAGMENTATION_OFFLOAD
        large_packet->seq_number = ntohl(L2_PACKET_TO_TCP_HDR(l2packet)->seq);
        l2packet->partial_size = l2packet->packet_size;
#endif
        return true;
    }

    hashid = l2packetHashID(l2packet);
    atrace(hashid > 0xFFFF, etrace("hashid: %d", hashid));

#if L2_FRAGMENTATION_OFFLOAD
//    set_channel_flags(l2packet, (ntohl(L2_PACKET_TO_TCP_HDR(l2packet)->seq) == 0) ? F_FIRST_FRAGMENT : 0);
    set_channel_flags(l2packet, 
        (__be16)ntohl(L2_PACKET_TO_TCP_HDR(l2packet)->seq) == ntohs(L2_PACKET_TO_IP_HDR(l2packet)->id) ? F_FIRST_FRAGMENT : 0);
    trace("hashid: %d, "
        "channel_packet_size(l2packet): 0x%X, " 
        "ntohs(L2_PACKET_TO_IP_HDR(l2packet)->id): %d, "
        "ntohl(L2_PACKET_TO_TCP_HDR(l2packet)->seq): %d", 
        hashid,
        channel_packet_size(l2packet), 
        ntohs(L2_PACKET_TO_IP_HDR(l2packet)->id), 
        (__be16)ntohl(L2_PACKET_TO_TCP_HDR(l2packet)->seq));
//    trace("ntohl(L2_PACKET_TO_TCP_HDR(l2packet)->seq): %d", ntohl(L2_PACKET_TO_TCP_HDR(l2packet)->seq));
#endif

    if (unlikely(channel_flags(l2packet) & F_FIRST_FRAGMENT)) {
        large_packet = alloc_large_packet(raw_socket);
        if (unlikely(!large_packet)) {
            etrace("l2packet is being freed due to alloc_large_packet failure");
            free_l2packet(raw_socket, l2packet);
            return false;
        }

        list_add(&large_packet->link, &raw_socket->large_packet_used_list);
        large_packet->uid = l2packetUID(l2packet);
// Use it all the time, not just in debug mode (fix hash list)
/*
#if TRACE_DEBUG
        if (!list_empty(&raw_socket->large_packet_hash[hashid])) {
            list_for_each_entry_safe(i, n, &(raw_socket->large_packet_hash[hashid]), hlink) {
                __free_large_packet(raw_socket, i);                        
            }
        }
#endif
*/
        list_add(&large_packet->hlink, &raw_socket->large_packet_hash[hashid]);

#if L2_FRAGMENTATION_OFFLOAD
        large_packet->seq_number = ntohl(L2_PACKET_TO_TCP_HDR(l2packet)->seq); 
        large_packet->packet_size = l2packet->packet_size;
        large_packet->expected_packet_size = channel_packet_size(l2packet);
        l2packet->partial_size = l2packet->packet_size;
        trace("hashid: %d, L2_PACKET_TO_TCP_HDR(l2packet)->seq: %d", hashid, ntohl(L2_PACKET_TO_TCP_HDR(l2packet)->seq));
        trace("large_packet->packet_size: %d, l2packet->packet_size: %d, channel_packet_size(l2packet): %d", large_packet->packet_size, l2packet->packet_size, channel_packet_size(l2packet));
#endif

        /* Although unexpected, this packet could be the last one, due to GRO */
        set_channel_flags(l2packet, (large_packet->packet_size == large_packet->expected_packet_size)
            ? F_SINGLE_FRAGMENT : channel_flags(l2packet));        
    } else {        
//        if (likely(list_is_singular(&(raw_socket->large_packet_hash[hashid])))) {
//            large_packet = list_first_entry(&(raw_socket->large_packet_hash[hashid]), struct large_packet, hlink);
//            goto found_large_packet;            
//        }

        uid = l2packetUID(l2packet);
        list_for_each_entry(i, &(raw_socket->large_packet_hash[hashid]), hlink) {
            if (i->uid == uid) {
                large_packet = i;
                goto found_large_packet;
            }
        }
#if 0
        mtrace("missed l2packet uid: %lx, hashid: %X", uid, hashid);
        list_for_each_entry(i, &(raw_socket->large_packet_hash[hashid]), hlink) {
            etrace("large_packet->uid: %lx", i->uid);
//            if (i->uid == uid) {
//                large_packet = i;
//                goto found_large_packet;
//            }
        }
#endif

        etrace("l2packet is being freed due to hash miss");            
        free_l2packet(raw_socket, l2packet);          
        return false;

found_large_packet:    
        // Touch large_packet, move it to the head of the list (in case of low memory, free up LRU (least-recently-used) resource (tail)
        list_del(&large_packet->link);
        list_add(&large_packet->link, &raw_socket->large_packet_used_list);

#if L2_FRAGMENTATION_OFFLOAD
        large_packet->packet_size += l2packet->packet_size; 
        set_channel_flags(l2packet, (large_packet->packet_size == large_packet->expected_packet_size)
            ? F_LAST_FRAGMENT : 0);
        trace("hashid: %X, large_packet->packet_size: %d, l2packet->packet_size: %d, channel_packet_size(l2packet): %d", hashid, large_packet->packet_size, l2packet->packet_size, channel_packet_size(l2packet));
        trace("large_packet->expected_packet_size: %d", large_packet->expected_packet_size);
        l2packet->partial_size = (ntohl(L2_PACKET_TO_TCP_HDR(l2packet)->seq) - large_packet->seq_number) + l2packet->packet_size;
        trace("large_packet->packet_size: %d", large_packet->packet_size);
        trace("l2packet->partial_size: %d", l2packet->partial_size);

        if (unlikely(large_packet->packet_size != l2packet->partial_size)) {
            etrace("large_packet is being freed due to malformation");
            free_l2packet(raw_socket, l2packet);          
            __free_large_packet(raw_socket, large_packet);
            return false;
        }
#endif
    }

    list_add_tail(&l2packet->link, &large_packet->l2packets);
    if (unlikely(channel_flags(l2packet) & F_LAST_FRAGMENT)) {
        trace("hashid: %d, large packet is ready", hashid);
        // Remove LP from hash list
        list_del(&large_packet->hlink);
        // All fragments are here which means the packet is ready to be dispatched
        list_move_tail(&large_packet->link, &raw_socket->large_packet_ready_list);
    }

    return true;
}

struct large_packet* __recv_large_packet(struct raw_socket *raw_socket) {
    struct large_packet* large_packet;

    large_packet = NULL;
    if (!list_empty(&raw_socket->large_packet_ready_list)) {
        large_packet = list_first_entry(&raw_socket->large_packet_ready_list, struct large_packet, link);
        list_del(&large_packet->link);
    }

    return large_packet;
}

#define list_last_entry(ptr, type, member) \
        list_entry((ptr)->prev, type, member)

void process_large_packet_tcp_session(struct raw_socket *raw_socket, struct large_packet* large_packet) {
//    struct tcphdr *tcph;
    struct tcpsession *session;
    struct l2packet *last_l2packet;
    struct l2packet *first_l2packet = list_first_entry(&large_packet->l2packets, struct l2packet, link);
 
//    tcph = L2_PACKET_TO_TCP_HDR(l2packet);

    session = get_tcp_session(raw_socket, 
                              large_packet->bsocket.l2address.ip_addr,
                              large_packet->bsocket.l2address.tcp_port);

//trace("**** session: %lp", session);
    if (!session) {
        trace("allocating tcp session");
        session = __alloc_tcp_session(raw_socket);
//trace("**** session: %lp", session);
//        L2_PACKET_TO_TCP_HDR(l2packet)->syn = 1;
//        L2_PACKET_TO_TCP_HDR(l2packet)->ack = 1;
    }
//return;

#if 0
    if (l2address->tcpsocket.type == 1) {
        tcph->syn = 1;
    } else if (l2address->tcpsocket.type == 2) {
    tcph->syn = 1;
        tcph->ack = 1;

        tcph->seq = 0;
        tcph->ack_seq = htonl(1);
    } else if (l2address->tcpsocket.type == 3) {
    tcph->ack = 1;

        tcph->seq = htonl(1);
        tcph->ack_seq = htonl(1);
    } else if (l2address->tcpsocket.type == 4) {
        tcph->ack = 1;
        
        tcph->ack_seq = htonl(1 + 488); // sizeof(struct ioctl_param));    
    }
#endif
    session->src_ip = L2_PACKET_TO_IP_HDR(first_l2packet)->daddr;
    session->src_port = L2_PACKET_TO_TCP_HDR(first_l2packet)->dest;
    session->dest_ip = L2_PACKET_TO_IP_HDR(first_l2packet)->saddr;
    session->dest_port = L2_PACKET_TO_TCP_HDR(first_l2packet)->source;

    last_l2packet = list_last_entry(&large_packet->l2packets, struct l2packet, link); 

    __be32 seq = ntohl(L2_PACKET_TO_TCP_HDR(last_l2packet)->seq);
    int packet_size = last_l2packet->packet_size ?
                      last_l2packet->packet_size : 
                      1;
//    int packet_size = channel_packet_size(first_l2packet) ?
//                      channel_packet_size(first_l2packet) : 
//                      1;

//    if (seq == 1)
//        seq = 0;
    atomic_set(&session->ack, packet_size  + seq); // + 1);
    trace("chanel_packet_size: %d, seq: %d, ack: %d", channel_packet_size(first_l2packet), seq,
        atomic_read(&session->ack));
    large_packet->bsocket.l2address.tcpsession = session;
}

#if TRACE_DEBUG
bool verify_large_packet_integrity(struct large_packet* large_packet) {
    struct l2packet *l2packet, *prev_l2packet = NULL;

    if (!list_empty(&large_packet->l2packets)) {                
        list_for_each_entry(l2packet, &large_packet->l2packets, link) {        
            if (prev_l2packet) {                
                atrace(l2packetHashID(prev_l2packet) != l2packetHashID(l2packet), 
                       return false);
                atrace(l2packetUID(prev_l2packet) != l2packetUID(l2packet), return false);
            } else {
                atrace((channel_flags(l2packet) & F_FIRST_FRAGMENT) == 0, return false);
            }
            prev_l2packet = l2packet;
        }
                           
        l2packet = container_of((&large_packet->l2packets)->prev, struct l2packet, link);
        atrace((channel_flags(l2packet) & F_LAST_FRAGMENT) == 0, return false);
    }

    return true;
}
#endif

struct l2socket *process_large_packet(struct raw_socket *raw_socket, struct large_packet* large_packet) {
    struct l2packet *l2packet;
#if TRACE_DEBUG
    bool failed = false;
#endif
    int len = 0;

    large_packet->biovec.iov_len = 0;
    large_packet->biovec.iov = large_packet->iov;

#if TRACE_DEBUG
    if (!verify_large_packet_integrity(large_packet)) {
        etrace("verify_large_packet_integrity failed");
        failed = true;
        // let it pass, let's hope that the malformed packet will get caught later (partial_size)
        //goto free_packet;
    }

    atrace(list_empty(&large_packet->l2packets));
#endif

    if (likely(!list_empty(&large_packet->l2packets))) {                
        l2packet                             = list_first_entry(&large_packet->l2packets, struct l2packet, link);
        large_packet->bsocket.l2socket       = raw_socket->l2sockets[channel_dest_port(l2packet)];

	    init_l2address(&large_packet->bsocket.l2address, 
            L2_PACKET_TO_ETH_HDR(l2packet)->h_source, 
            channel_src_port(l2packet),
            L2_PACKET_TO_IP_HDR(l2packet)->saddr,
            L2_PACKET_TO_TCP_HDR(l2packet)->source); 
//        large_packet->bsocket.l2address.port = channel_src_port(l2packet);
//        copy_mac(large_packet->bsocket.l2address.mac_address, L2_PACKET_TO_ETH_HDR(l2packet)->h_source);
//1        large_packet->bsocket.l2address.tcpsocket.src_ip = L2_PACKET_TO_IP_HDR(l2packet)->daddr;
//1	    large_packet->bsocket.l2address.tcpsocket.src_port = L2_PACKET_TO_TCP_HDR(l2packet)->dest;
//1	    large_packet->bsocket.l2address.tcpsocket.dest_ip = L2_PACKET_TO_IP_HDR(l2packet)->saddr;
//1	    large_packet->bsocket.l2address.tcpsocket.dest_port = L2_PACKET_TO_TCP_HDR(l2packet)->source;

        struct iovec b_iov[8];
        memcpy(&b_iov, l2packet->iov, sizeof(struct iovec)*8); 

        list_for_each_entry(l2packet, &large_packet->l2packets, link) {
            large_packet->biovec.iov_len += move_iovec_skip(l2packet->iov, 
                large_packet->biovec.iov + large_packet->biovec.iov_len, 
                L2_PACKET_HEADER_SIZE, 
                l2packet->packet_size, 
                l2packet->iov_len);

            len += l2packet->packet_size;
            atrace(large_packet->biovec.iov_len > ARRAY_SIZE(large_packet->iov));   
        }            

#if TRACE_DEBUG
        l2packet = list_first_entry(&large_packet->l2packets, struct l2packet, link);

        if (iov_length(large_packet->biovec.iov, large_packet->biovec.iov_len) != len) { 
            etrace("iov_length(large_packet->biovec.iov, large_packet->biovec.iov_len (%d)): %d, len: %d", large_packet->biovec.iov_len, iov_length(large_packet->biovec.iov, large_packet->biovec.iov_len), len); 
            int i;
            etrace("l2packet->packet_size: %d, len: %d, l2packet->iov_len: %d", 
                    l2packet->packet_size, len, l2packet->iov_len);
            
            for (i=0; i<8; i++) {
                etrace("b_iov[%d].iov_len: %d", i, b_iov[i].iov_len);
            }

            for (i=0; i<l2packet->iov_len; i++) {
                etrace("l2packet->iov[%d].iov_len: %d", i, l2packet->iov[i].iov_len);
            }
 
           for (i=0; i<large_packet->biovec.iov_len; i++) {
                etrace("large_packet->biovec.iov[%d].iov_len: %d", i, large_packet->biovec.iov[i].iov_len);
            }
             
            goto free_packet;
        }             
#endif

        process_large_packet_tcp_session(raw_socket, large_packet);
#if TRACE_DEBUG
        if (failed == true) {
            etrace("\"let's hope that the malformed packet will get caught later (partial_size)\" assumption - failed");
            goto free_packet;
        }
#endif  

        return large_packet->bsocket.l2socket; 
    }

#if TRACE_DEBUG
free_packet:
    etrace("large_packet is being freed due to malformation");
    free_large_packet(raw_socket, large_packet);
#endif
    return NULL;
}

static __always_inline void set_iph_csum(struct iphdr *iph, int len) {
    trace("len: %d", len);
    iph->tot_len = htons(len - ETHHDR_SIZE);
    iph->check = 0;
    iph->check = ip_fast_csum(iph, iph->ihl);
    trace("ip header checksum: %X", iph->check & 0xffff);
}

static __always_inline void initialize_l2_header(struct l2socket  *l2socket,
                                                 struct l2address *l2address,
                                                 struct l2header  *l2header,
                                                 struct tcphdr *tcph,
                                                 int    packet_id,
//                                                 int    seq_number,
                                                 int    expected_packet_size) {

//    l2header->MAGIC     = CHANNEL_MAGIC;
    
    l2header->pad[0] = 1;
    l2header->pad[1] = 1;
    l2header->pad[2] = 1;

    if (tcph->syn) {
        l2header->window_scale[0] = 3;
        l2header->window_scale[1] = 3;
        l2header->window_scale[2] = 14; // Multiply by 1024
    } else {
        l2header->window_scale[0] = 1;
        l2header->window_scale[1] = 1;
        l2header->window_scale[2] = 1;        
    }

    l2header->kind = 8;
    l2header->size = 10;

    l2header->flags     = F_FIRST_FRAGMENT;
    l2header->src_port  = l2socket->src_port;
    l2header->dest_port = l2address->port;
    l2header->packet_id = packet_id;
    trace("packet_id: %d", packet_id);
//    l2header->seq       = seq_number;
    l2header->expected_packet_size = expected_packet_size;
}

static __always_inline void initialize_tcp_header(struct l2address *l2address,
                                                  struct tcphdr *tcph,
//                                                  int    packet_id,
                                                  int    seq_number) {
//                                                  int    expected_packet_size) {

    /* TCP header */
    memset(tcph, 0, TCPHDR_SIZE);
    tcph->doff    = 5 + (sizeof(struct l2header) >> 2); /* options */
    tcph->seq     = htonl(seq_number);

//    tcph->ack_seq = expected_packet_size;
  
    tcph->window  = htons(CHANNEL_MAGIC); // htons((expected_packet_size & 0xFFFF));
//    tcph->urg_ptr = htons((((expected_packet_size >> 4) & 0xF000) 
//                          | (CHANNEL_MAGIC & 0xFFF)));

    tcph->source  = l2address->tcpsession->src_port; // 3110;
    tcph->dest    = l2address->tcpsession->dest_port; // 3111;

    if (!seq_number)
        tcph->syn = 1;

//    tcph->ack_seq = htonl(atomic_xchg(&l2address->tcpsession->ack, 0));
    tcph->ack_seq = htonl(atomic_read(&l2address->tcpsession->ack));
    if (tcph->ack_seq)
        tcph->ack = 1;

#if 0
    if (l2address->tcpsocket.type == 1) {
        tcph->syn = 1;
    } else if (l2address->tcpsocket.type == 2) {
	tcph->syn = 1;
        tcph->ack = 1;

        tcph->seq = 0;
        tcph->ack_seq = htonl(1);
    } else if (l2address->tcpsocket.type == 3) {
	tcph->ack = 1;

        tcph->seq = htonl(1);
        tcph->ack_seq = htonl(1);
    } else if (l2address->tcpsocket.type == 4) {
        tcph->ack = 1;
        
        tcph->ack_seq = htonl(1 + 488); // sizeof(struct ioctl_param));    
    }
#endif    
}

static __always_inline void initialize_eth_header(struct l2socket  *l2socket,
                                                  struct l2address *l2address,
                                                  struct ethhdr    *l2ethhdr) {
    struct raw_socket *raw_socket;
    raw_socket = l2socket->raw_socket;        

    l2ethhdr->h_proto = htons(ETH_P_IP);
    copy_mac(l2ethhdr->h_dest, l2address->mac_address);
    copy_mac(l2ethhdr->h_source, raw_socket->mac_address);
}

static __always_inline void initialize_ip_header(struct l2socket   *l2socket,
                                                 struct l2address  *l2address,
                                                 struct iphdr      *iph,
                                                 u8                 ip_protocol,
                                                 int                seq_number) {
    struct raw_socket *raw_socket;
//    struct pseudo_iphdr *piph;

//    piph = (struct pseudo_iphdr *)iph;
    raw_socket = l2socket->raw_socket;        

    /* IP header */
    iph->ihl       = IPHDR_SIZE / 4; 
    iph->version   = IPVERSION;
    iph->tos       = 0;
    iph->protocol  = ip_protocol;
    iph->id        = htons((u16)seq_number); // atomic_read(&l2address->tcpsession->seq)); // htons(atomic_inc_return(&l2address->tcpsocket.id)-1);
    trace("iph->id %d, seq_number: %d", iph->id, seq_number);
    iph->frag_off  = ntohs(IP_DF);
    iph->ttl       = 64;
    iph->saddr     = l2address->tcpsession->src_ip; // CHANNEL_MAGIC; 
    iph->daddr     = l2address->tcpsession->dest_ip; // 0x0101A8C0; // 192.168.1.1 
//    piph->packet_size = CHANNEL_MAGIC & 0xFFFF;

//1    piph->id        = (unchar)packet_id;
//1    piph->src_port  = l2socket->src_port;
//1    piph->dest_port = l2address->port;
//1    piph->flags     = F_FIRST_FRAGMENT;

//    return packet_id;
}

__always_inline int __sendskb(struct l2socket *l2socket, 
                                     struct sk_buff *skb, 
                                     struct l2address *l2address,
                                     unchar           packet_id,
                                     u32              seq_number,
                                     int              expected_packet_size) {
    struct skb_shared_info *sinfo = skb_shinfo(skb);
    struct ethhdr *l2ethhdr;
    struct iphdr *iph; 
//    struct pseudo_iphdr *piph;
    struct tcphdr *tcph;  
    struct l2header *l2header;
    struct raw_socket *raw_socket;
    int packet_size = skb->len, skb_len;
    
    trace("skb_headroom(skb): %d", skb_headroom(skb));
    if (skb_headroom(skb) < L2_PACKET_HEADER_SIZE) {
        etrace("freeing skb, skb_headroom lacks header space");
        kfree_skb(skb);
        return -ENOMEM;
    }

    raw_socket = l2socket->raw_socket;        
    /* L2 header */
    l2header = (struct l2header *)skb_push(skb, L2HDR_SIZE);
    
    /* TCP header */
    tcph = (struct tcphdr *)skb_push(skb, TCPHDR_SIZE);
    skb_reset_transport_header(skb);

    /* IP header */
    iph = (struct iphdr *)skb_push(skb, IPHDR_SIZE);
    skb_reset_network_header(skb);
//    piph = (struct pseudo_iphdr *)iph;

    /* ETH header */
    l2ethhdr = (struct ethhdr *)skb_push(skb, ETHHDR_SIZE);
    skb_reset_mac_header(skb);

    initialize_eth_header(l2socket, l2address, l2ethhdr);
    initialize_ip_header(l2socket, l2address, iph, 6, seq_number);
    initialize_tcp_header(l2address, tcph, seq_number);
    initialize_l2_header(l2socket, l2address, l2header, tcph, packet_id, // seq_number, 
                         expected_packet_size);

    atrace(skb->len > L2_TCP_MAX_SEGMENT_SIZE, etrace("skb->len: %d", skb->len); return -EFAULT);

    if (!skb_partial_csum_set(skb, ETHHDR_SIZE + IPHDR_SIZE, 
                                   offsetof(struct tcphdr, check))) {
        kfree_skb(skb);
        return -EINVAL;
    }

    trace("skb_checksum_start_offset(skb): %d, skb->csum_offset: %d", skb_checksum_start_offset(skb), skb->csum_offset);
    trace("skb->protocol: %X, eth_hdr(skb)->h_proto: %X", skb->protocol, eth_hdr(skb)->h_proto);

    trace("skb->mac_header: %lp", skb->mac_header);
    trace("skb->network_header: %lp", skb->network_header);
    trace("skb->transport_header: %lp", skb->transport_header);

    trace("skb->mac_header: %.*b", 14, skb_mac_header(skb));
    trace("skb->network_header: %.*b", 20, skb_network_header(skb));
    trace("skb->transport_header: %.*b", 20 + L2HDR_SIZE, skb_transport_header(skb));

    skb->protocol = eth_hdr(skb)->h_proto;

    trace("skb->len: %d, l2_packet_size: %d", skb->len, l2_packet_size);
    if (likely((skb->len <= l2_packet_size) && (packet_size == expected_packet_size))) {
        trace("single fragment");
//        piph->flags = F_SINGLE_FRAGMENT;
        l2header->flags = F_SINGLE_FRAGMENT;
        sinfo->gso_type = 0;
        sinfo->gso_size = 0;
        sinfo->gso_segs = 1;
    } else {
        /* Header must be checked, and gso_segs computed. */
        sinfo->gso_type = SKB_GSO_TCPV4; 
        sinfo->gso_size = l2_packet_size - L2_PACKET_HEADER_SIZE;
        sinfo->gso_segs = DIV_ROUND_UP(skb->len - L2_PACKET_HEADER_SIZE, sinfo->gso_size);
        trace("multiple fragments: %d, gso_size: %d", sinfo->gso_segs, sinfo->gso_size);
    }

    set_iph_csum(iph, skb->len);
    skb_len = skb->len;
    __send_raw_skb(skb, raw_socket->ndev);
    return skb_len;
}

int sendskb(struct l2socket *l2socket, struct sk_buff *skb, struct l2address *l2address) {
    u32 seq;
    attach_tcp_session(l2socket->raw_socket, l2address);
    seq = adjust_tcp_session_seq_number(l2address, skb->len);
    
    return __sendskb(l2socket, 
                     skb, 
                     l2address,
                     (unchar)get_next_packet_id(l2socket->raw_socket), 
                     seq, 
                     skb->len);
}

#endif
