#if 1 /* patchouli vrio */
#ifndef _CQUEUE_H
#define _CQUEUE_H

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>

#define CQUEUE_USE_SPINLOCK 0

//
// this cyclic queue can be used with more than one consumer, it's thread safe lock-free (x86)
//

#define __INDEX2PTR(x, q) ((x) % (q)->queue_max_size)
#define __NEXT_ELM(x, q)  __INDEX2PTR(x+1, q)

#define INDEX2PTR(x)      __INDEX2PTR(x, cqueue)
#define NEXT_ELM(x)       __NEXT_ELM(x, cqueue)

#define FREE_INDEX(q)     (atomic_read(&(q)->free_elm_index))
#define NEXT_INDEX(q)     (atomic_read(&(q)->next_elm_index))

#define FREE_PTR(q)       __INDEX2PTR(FREE_INDEX(q), q)
#define NEXT_PTR(q)       __INDEX2PTR(NEXT_INDEX(q), q)

#define CQ_FLAG_QUEUED        0
#define CQ_FLAG_NO_MARK       1
#define CQ_FLAG_MANUAL_UNMARK 2

enum {
    CQUEUE_QUEUE_IS_FULL = 0,
    CQUEUE_SUCCESS       = 1,
    CQUEUE_ELM_IN_QUEUE  = 2,
};

struct cqueue_struct {    
    ulong flags;
};

struct cqueue {
    struct cqueue_struct **array;
    size_t queue_max_size;

    atomic_t free_elm_index;
    atomic_t next_elm_index;      

    atomic_t queue_size;
#if TRACE_DEBUG
    int stat_total_enqueue;
    int stat_total_dequeue;

    int stat_max_enqueue_rounds;
    int stat_max_dequeue_rounds;

    int stat_total_enqueue_rounds;
    int stat_total_dequeue_rounds;
#endif

#if CQUEUE_USE_SPINLOCK
    spinlock_t lock;
#endif
};

static inline void init_cqueue_elm(struct cqueue_struct *cq_elm) {
    cq_elm->flags = 0;
}

static inline bool cqueue_empty(struct cqueue *cqueue) {
    return (atomic_read(&cqueue->queue_size) == 0);
}

static inline bool cqueue_full(struct cqueue *cqueue) {
    return (atomic_read(&cqueue->queue_size) == cqueue->queue_max_size);
}

static inline size_t cqueue_size(struct cqueue *cqueue) {
    return (size_t)atomic_read(&cqueue->queue_size);
}

static bool init_cqueue(struct cqueue *cqueue, size_t queue_max_size) {
    int i;
    queue_max_size++;

    cqueue->array = (struct cqueue_struct **)vmalloc(queue_max_size * sizeof(struct cqueue_struct *));
    if (cqueue->array == NULL) {
        etrace("failed to allocate memory");
        return false;
    }

    for (i=0; i<queue_max_size; ++i) 
        cqueue->array[i] = NULL;

    cqueue->queue_max_size = queue_max_size;
    atomic_set(&cqueue->free_elm_index, 0);
    atomic_set(&cqueue->next_elm_index, 0);

    atomic_set(&cqueue->queue_size, 0);

#if TRACE_DEBUG
    cqueue->stat_total_enqueue = 0;
    cqueue->stat_total_dequeue = 0;

    cqueue->stat_max_enqueue_rounds = 0;
    cqueue->stat_max_dequeue_rounds = 0;

    cqueue->stat_total_enqueue_rounds = 0;
    cqueue->stat_total_dequeue_rounds = 0;
#endif

#if CQUEUE_USE_SPINLOCK
    spin_lock_init(&cqueue->lock);
#endif 
    return true;
}

static __maybe_unused struct cqueue* create_cqueue(size_t queue_max_size) {
    struct cqueue* cqueue = NULL;

    cqueue = (struct cqueue *)vmalloc(sizeof(struct cqueue));
    if (cqueue == NULL) {
        etrace("failed to allocate memory");
        goto exit;
    }

    if (init_cqueue(cqueue, queue_max_size) == false) {
        goto free_cqueue;
    }

    return cqueue;

free_cqueue:
    vfree(cqueue);
exit:   
    return NULL;
}

static void done_cqueue(struct cqueue *cqueue) {
    vfree(cqueue->array);   
}
 
static __maybe_unused void free_cqueue(struct cqueue *cqueue) {           
    done_cqueue(cqueue);
    vfree(cqueue);    
} 

static inline void set_cq_flag(struct cqueue_struct *cq_elm, ulong flag) {
    set_bit(flag, &cq_elm->flags);
}

static inline bool cqueue_no_mark(struct cqueue_struct *cq_elm) {
    return test_bit(CQ_FLAG_NO_MARK, &cq_elm->flags);
}

static inline bool cqueue_manual_unmark(struct cqueue_struct *cq_elm) {
    return test_bit(CQ_FLAG_MANUAL_UNMARK, &cq_elm->flags);
}

static inline bool cqueue_elm_marked(struct cqueue_struct *cq_elm) {    
    return test_bit(CQ_FLAG_QUEUED, &cq_elm->flags);
}

static inline void unmark_cqueue_elm(struct cqueue_struct *cq_elm) {
    clear_bit(CQ_FLAG_QUEUED, &cq_elm->flags);
}

static inline bool test_and_mark_cqueue_elm(struct cqueue_struct *cq_elm) {
    /* Avoid memory barrier incurred by the "heavy" atomic test_and_set */        
    if (cqueue_elm_marked(cq_elm)) 
        return true;

    return test_and_set_bit(CQ_FLAG_QUEUED, &cq_elm->flags);
}

static __maybe_unused void print_cqueue(struct cqueue *cqueue) {
    etrace("array: %lp", cqueue->array);
    etrace("queue_max_size: %d", cqueue->queue_max_size);    
    etrace("queue_size: %d", atomic_read(&cqueue->queue_size));
    etrace("free_elm_index: %d", atomic_read(&cqueue->free_elm_index));
    etrace("next_elm_index: %d", atomic_read(&cqueue->next_elm_index));
}

static inline int cenqueue(struct cqueue *cqueue, struct cqueue_struct *cq_elm) {
    int free_index;
    int free_ptr;
#if TRACE_DEBUG
    int stat_enqueue_rounds = 0;
#endif 

#if CQUEUE_USE_SPINLOCK
    unsigned long flags;
#endif 

    atrace(cq_elm == NULL);
    if (!cqueue_no_mark(cq_elm) && test_and_mark_cqueue_elm(cq_elm)) 
        return CQUEUE_ELM_IN_QUEUE;

#if CQUEUE_USE_SPINLOCK
    spin_lock_irqsave(&cqueue->lock, flags);                
#endif 

    free_index = FREE_INDEX(cqueue);
    free_ptr = INDEX2PTR(free_index);
    while (atomic_read(&cqueue->queue_size) < cqueue->queue_max_size - 1) {
#if TRACE_DEBUG
        stat_enqueue_rounds++;
#endif 
        if ((cqueue->array[free_ptr] == NULL) && 
            (free_index == atomic_cmpxchg(&cqueue->free_elm_index, /*old */ free_index, /* new */ free_index+1)))  {
            atomic_inc(&cqueue->queue_size);
            atrace(atomic_read(&cqueue->queue_size) > cqueue->queue_max_size - 1);
            cqueue->array[free_ptr] = cq_elm;
#if TRACE_DEBUG
            cqueue->stat_max_enqueue_rounds = max(cqueue->stat_max_enqueue_rounds, stat_enqueue_rounds);
            cqueue->stat_total_enqueue++;
            cqueue->stat_total_enqueue_rounds += stat_enqueue_rounds;
#endif

#if CQUEUE_USE_SPINLOCK
            spin_unlock_irqrestore(&cqueue->lock, flags);            
#endif
            return CQUEUE_SUCCESS;
        }           
        free_index = FREE_INDEX(cqueue);
        free_ptr = INDEX2PTR(free_index);
    }

#if CQUEUE_USE_SPINLOCK
    spin_unlock_irqrestore(&cqueue->lock, flags);            
#endif
    unmark_cqueue_elm(cq_elm);
    return CQUEUE_QUEUE_IS_FULL; 
}

static inline struct cqueue_struct *cdequeue(struct cqueue *cqueue) {
    struct cqueue_struct *cq_elm;
    int next_index;
    int next_ptr;
#if TRACE_DEBUG
    int stat_dequeue_rounds = 0;
#endif 

#if CQUEUE_USE_SPINLOCK
    unsigned long flags;
#endif 
    
#if CQUEUE_USE_SPINLOCK
    spin_lock_irqsave(&cqueue->lock, flags);                
#endif 

    next_index = NEXT_INDEX(cqueue);
    next_ptr = INDEX2PTR(next_index);
    while (atomic_read(&cqueue->queue_size) > 0) { 
#if TRACE_DEBUG
        stat_dequeue_rounds++;
#endif 
        if ((cqueue->array[next_ptr] != NULL) && 
            (next_index == atomic_cmpxchg(&cqueue->next_elm_index, /*old */ next_index, /* new */ next_index+1)))  {
            atomic_dec(&cqueue->queue_size);
            atrace(atomic_read(&cqueue->queue_size) < 0);
            atrace(cqueue->array[next_ptr] == NULL);
            cq_elm = cqueue->array[next_ptr];
            if (!cqueue_manual_unmark(cq_elm) && !cqueue_no_mark(cq_elm))
                unmark_cqueue_elm(cq_elm);
            cqueue->array[next_ptr] = NULL;
#if TRACE_DEBUG
            cqueue->stat_max_dequeue_rounds = max(cqueue->stat_max_dequeue_rounds, stat_dequeue_rounds);
            cqueue->stat_total_dequeue++;
            cqueue->stat_total_dequeue_rounds += stat_dequeue_rounds;
#endif

#if CQUEUE_USE_SPINLOCK
            spin_unlock_irqrestore(&cqueue->lock, flags);            
#endif
            return cq_elm;
        }
        next_index = NEXT_INDEX(cqueue);
        next_ptr = INDEX2PTR(next_index);
    }

#if CQUEUE_USE_SPINLOCK
    spin_unlock_irqrestore(&cqueue->lock, flags);            
#endif
    return NULL;
}

#endif /* _CQUEUE_H */
#endif
