#if 1 /* patchouli vrio */
#ifndef _UTILS_H
#define _UTILS_H

static __maybe_unused __always_inline int memcpy_fromiovecend_skip(unsigned char *kdata, struct iovec *iov, int iov_len, int len)
{
    int seg = 0;

    while (len > 0 && seg < iov_len) {
        int copy = min_t(unsigned int, len, iov->iov_len);
        if (copy > 0) {            
            memcpy(kdata, iov->iov_base, copy);
            len -= copy;
            kdata += copy;
            iov->iov_len -= copy;
            iov->iov_base += copy;
        }
            
        iov++;
        seg++;
    }

    return len;
}

static __always_inline int iovec_pop_len(struct iovec *iov, int iov_len, int len)
{
    int seg = 0;

    while (len > 0 && seg < iov_len) {
        int copy = min_t(unsigned int, len, iov->iov_len);
        if (copy > 0) {            
            len -= copy;
            iov->iov_len -= copy;
            iov->iov_base += copy;
        }
            
        iov++;
        seg++;
    }

    return len;
}

static __maybe_unused __always_inline int move_iovec_skip(struct iovec *from, struct iovec *to,
               size_t skip, size_t len, int iov_count)
{
    int seg = 0;
    size_t size;

    while (len && seg < iov_count) {
        if (unlikely(from->iov_len == 0)) {
            --iov_count;
            ++from;
            continue;
        }
        
        if (unlikely(skip)) {
            size = min(from->iov_len, skip);
            skip -= size;
            from->iov_base += size;
            from->iov_len -= size;
            continue;
        }

        size = min(from->iov_len, len);
        to->iov_base = from->iov_base;
        to->iov_len = size;
        from->iov_len -= size;
        from->iov_base += size;
        len -= size;
        ++from;
        ++to;
        ++seg;
    }
    
    return seg;
}

static __maybe_unused __always_inline int move_iovec(struct iovec *from, struct iovec *to,
              size_t len, int iov_count)
{
    return move_iovec_skip(from, to, 0, len, iov_count);
}

static __maybe_unused __always_inline int move_iovec_page(struct iovec *from, struct iovec *to,
              size_t len, int nr_pages, int iov_count)
{
    int off, seg = 0;
    size_t size;

    while (len && seg < nr_pages && iov_count) {
        if (unlikely(from->iov_len == 0)) {
            --iov_count;
            ++from;
            continue;
        }
        off = (ulong)from->iov_base & ~PAGE_MASK;
        size = PAGE_SIZE - off;
        if (size > from->iov_len)
            size = from->iov_len;
        if (size > len)
            size = len;

        to->iov_base = from->iov_base;
        to->iov_len = size;
        from->iov_len -= size;
        from->iov_base += size;
        len -= size;
        ++to;
        ++seg;
    }
    
    return seg;
}

static __maybe_unused struct file* file_open(const char* path, int flags, int rights) {
    struct file* filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);

    if(IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

static __maybe_unused void file_close(struct file* file) {
    filp_close(file, NULL);
}

static __maybe_unused long file_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    mm_segment_t fs;
    long ret = -EINVAL;

    fs = get_fs();     /* save previous value */
    set_fs(get_ds()); /* use kernel limit */

    if (file->f_op->unlocked_ioctl) 
        ret = file->f_op->unlocked_ioctl(file, cmd, arg);
    else
        if (file->f_op->compat_ioctl) 
            ret = file->f_op->compat_ioctl(file, cmd, arg);

    set_fs(fs); /* restore before returning to user space */
    return ret;
}

#endif /* _UTILS_H */
#endif