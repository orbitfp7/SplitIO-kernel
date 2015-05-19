#if 1 /* patchouli vrio */
#ifndef _LMEMPOOL_H
#define _LMEMPOOL_H

#include <linux/llist.h>

struct lmempool {
    char *elements;

    struct llist_head free_list;
};

struct lmempool_elm {
    struct llist_node llink;

    char data[];
};

static bool init_lmempool(struct lmempool *lmempool, size_t list_size, size_t sizeof_elm) {
    struct lmempool_elm *lmempool_elm;
    char *elements;
    int i;

    trace("sizeof_elm: %d, sizeof(struct lmempool_elm): %d", (int)sizeof_elm, (int)sizeof(struct lmempool_elm));
    sizeof_elm += sizeof(struct lmempool_elm);
    lmempool->elements = elements = vmalloc(list_size * sizeof_elm);
    if (lmempool->elements == NULL) {
        etrace("failed to allocate memory");
        return false;
    }
    trace("elements: %lp", elements);

    init_llist_head(&lmempool->free_list);
    for (i=0; i<list_size; ++i) {
        lmempool_elm = (struct lmempool_elm *)elements;
        llist_add(&lmempool_elm->llink, &lmempool->free_list);
        elements += sizeof_elm;
    }

    return true;
}

static void done_lmempool(struct lmempool *lmempool) {
    if (lmempool->elements) {
        trace("elements: %lp", lmempool->elements);
        vfree(lmempool->elements);
    }
}

static inline void *lmempool_alloc(struct lmempool *lmempool) {
    struct lmempool_elm *lmempool_elm;
    struct llist_node *llist_node;
    char *ptr = NULL;

    llist_node = llist_del_first(&lmempool->free_list);
    if (likely(llist_node)) {
        lmempool_elm = llist_entry(llist_node, struct lmempool_elm, llink);
        ptr = lmempool_elm->data;
    }

    return ptr;
}

static inline void lmempool_free(struct lmempool *lmempool, void *ptr) {
    struct lmempool_elm *lmempool_elm;
    lmempool_elm = container_of(ptr, struct lmempool_elm, data);
    llist_add(&lmempool_elm->llink, &lmempool->free_list);
}
#endif /* _LMEMPOOL_H */
#endif
