#if 1 /* patchouli vrio */
#ifndef _DEBUG_H
#define _DEBUG_H

#if TRACE_DEBUG
struct skb_cb_rdtsc {
    int magic;
    long cycles;
};

#define SKB_CB_MAGIC 0xAABBCCDD
#endif

#endif /* _DEBUG_H */
#endif
