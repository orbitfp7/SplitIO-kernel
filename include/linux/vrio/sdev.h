#if 1 /* patchouli vrio */
#ifndef _SDEV_H
#define _SDEV_H

#define SDEV_FLAGS_WRITE_ZCOPY    (1 << 0)
#define SDEV_FLAGS_READ_ZCOPY     (1 << 1)
#define SDEV_FLAGS_CHECKSUM       (1 << 2)
#define SDEV_FLAGS_ACK_ON_WRITE   (1 << 3)

#define SDEV_OPERATION_WRITE 1
#define SDEV_OPERATION_READ  2
#define SDEV_OPERATION_ACK   3

#define SDEV_HEADER_SIZE (sizeof(struct sdev_header))

#define MAX_REQUEST_SIZE    2097152
#define MAX_IOV             128

struct sdev_header {
    ulong private;

    int size;
    int operation;
    int flags;    

    ulong checksum;
};

struct sdev_req {
    char buffer[MAX_REQUEST_SIZE];
    struct sdev_header shdr;
    char __destroy[1024];
//    struct skb_frag_destructor *destroy;

    struct iovec iov[MAX_IOV];
    int nr_iov;
};

static void init_buffer(char *buff, int size, long seed) 
{
    int i;
    for (i=0; i < size/8; i++) {
        ((long *)buff)[i] = seed++;
    }
}

static void map_request_iov(struct sdev_req *req, int size, int segs) 
{
    char *data = req->buffer;
    int nr_iov = 0, psize;
    int i;
    
    req->iov[nr_iov].iov_base = &req->shdr;
    req->iov[nr_iov].iov_len = sizeof(struct sdev_header);
    nr_iov++;

    psize = size / segs;

    for (i=0; i<segs-1; i++) {
        req->iov[nr_iov].iov_base = data;
        req->iov[nr_iov].iov_len = psize;
        nr_iov++;

        data += psize;
        size -= psize;
    }

    req->iov[nr_iov].iov_base = data;
    req->iov[nr_iov].iov_len = size;
    nr_iov++;

    req->nr_iov = nr_iov;
}

static ulong calc_sdev_checksum(struct iovec *iov, int iov_len) {
    int i, j;
    int index = 0;    
    ulong checksum = 0;

    for(i=0; i<iov_len; i++) {
        for (j=0; j<iov[i].iov_len; j++) {
            checksum += ((char *)iov[i].iov_base)[j] * (index++);
        }
    }

    return checksum;
}

static ulong calc_sdev_checksum_buff(char *buff, int size) {
    struct iovec iov[1];
    iov[0].iov_base = buff;
    iov[0].iov_len = size;

    return calc_sdev_checksum(iov, 1);
}

static bool is_sdev_checksum_valid(struct iovec *iov, int iov_len, ulong checksum) {
    return (checksum == calc_sdev_checksum(iov, iov_len));
}

#endif /* _SDEV_H */
#endif
