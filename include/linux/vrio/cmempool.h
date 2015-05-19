#if 1 /* patchouli vrio */
#ifndef _CMEMPOOL_H
#define _CMEMPOOL_H

#include "cqueue.h"

struct cmempool {
    struct cqueue cqueue; 
    char *elements;
};

struct cmempool_elm {
    char *ptr;
};

static bool init_cmempool(struct cmempool *cmempool, size_t queue_size, size_t sizeof_elm) {
    int i;
    struct cmempool_elm *cmempool_elm;
    char *elements;

    cmempool->elements = elements = vmalloc(queue_size * sizeof_elm);
    if (cmempool->elements == NULL) {
        etrace("failed to allocate memory");
        return false;
    }
    
    if (init_cqueue(&cmempool->cqueue, queue_size, sizeof(struct cmempool_elm)) == false) {
        goto free_elements;
    }

    for (i=0; i<queue_size; ++i) {
        cmempool_elm = (struct cmempool_elm *)calloc_elm(&cmempool->cqueue);
        atrace(cmempool_elm == NULL);
        cmempool_elm->ptr = elements;
        cenqueue(&cmempool->cqueue, cmempool_elm);

        elements += sizeof_elm;
    }

    return true;
free_elements:
    vfree(cmempool->elements);
    return false;
}

static void done_cmempool(struct cmempool *cmempool) {
    done_cqueue(&cmempool->cqueue);
    if (cmempool->elements)
        vfree(cmempool->elements);
}

static inline void *cmempool_alloc(struct cmempool *cmempool) {
    struct cmempool_elm *cmempool_elm;
    char *ptr = NULL;

    cmempool_elm = cdequeue(&cmempool->cqueue);
    if (cmempool_elm) {
        ptr = cmempool_elm->ptr;
        cmempool_elm->ptr = NULL;
        cfree_elm(&cmempool->cqueue, cmempool_elm);
    }

    return ptr;
}

static inline void cmempool_free(struct cmempool *cmempool, void *ptr) {
    struct cmempool_elm *cmempool_elm;

    cmempool_elm = (struct cmempool_elm *)calloc_elm(&cmempool->cqueue);
    atrace(cmempool_elm == NULL);
    cmempool_elm->ptr = ptr;
    cenqueue(&cmempool->cqueue, cmempool_elm);
}
#endif /* _CMEMPOOL_H */
#endif
