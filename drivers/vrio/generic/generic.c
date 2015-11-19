#if 1 /* patchouli vrio-generic-module */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/cpufreq.h>

#include <asm/uaccess.h>

// #define TRACE_LEVEL 4

#include <linux/vrio/trace.h>
#include <linux/vrio/l2socket.h>
#include <linux/vrio/eth.h>
#include <linux/vrio/generic.h>
#include <linux/vrio/utils.h>
#include <linux/vrio/vrio.h>

TRACE_ALL;

#define SDEV_HACK 1 // default should be 1

#include <linux/vrio/cqueue.h>
#include <linux/vrio/lmempool.h>

static struct class  *fs_class;
static struct device *fs_devices;

#define MODULE_NAME               "vrio"
#define FS_DIRECTORY_DEVICE       "dev"


int unit_test = 0;
module_param(unit_test, int, S_IRUGO);
int work_queue_size = 256;
module_param(work_queue_size, int, S_IRUGO);

int poll_budget = 100;
module_param(poll_budget, int, S_IWUSR | S_IRUGO);

////////////////////////////////////////////////////
// Statistics
int total_packets = 0;
module_param(total_packets, int, S_IWUSR | S_IRUGO);
int contended_packets = 0;
module_param(contended_packets, int, S_IWUSR | S_IRUGO);
////////////////////////////////////////////////////

#define MEASURE_IOHYP_CYCLES 1 // 1

#if MEASURE_IOHYP_CYCLES 
int is_using_rdtsc = 1;
module_param(is_using_rdtsc, int, S_IWUSR | S_IRUGO);

//long iohyp_work_cycles = 0;
//module_param(iohyp_work_cycles, long, S_IWUSR | S_IRUGO);

//long iohyp_gpoll_cycles = 0;
//module_param(iohyp_gpoll_cycles, long, S_IWUSR | S_IRUGO);

//long iohyp_gpoll_loops = 0;
//module_param(iohyp_gpoll_loops, long, S_IWUSR | S_IRUGO);

//long iohyp_empty_loops = 0;
//module_param(iohyp_empty_loops, long, S_IWUSR | S_IRUGO);


//atomic64_t iohyp_work_cycles_t;
//atomic64_t iohyp_gpoll_cycles_t;
#endif

bool iohyp_schedule_on_empty_loop = 0;
module_param(iohyp_schedule_on_empty_loop, bool, S_IWUSR | S_IRUGO);

#define TCP_PORT 0
#define CONTROL_PORT 1
spinlock_t g_lock;

bool generic_driver_registered = false;

#define L2SOCKET_GWORK(l2socket) ((struct gwork_struct *)l2socket->buffer)

//
// I/O Hypervisor (Host)
//

int   h_eth_name_argc;
char *h_eth_name[MAX_ETH_COUNT];
module_param_array(h_eth_name, charp, &h_eth_name_argc, S_IRUGO);

int h_cpu_affinity_argc;
int h_cpu_affinity[MAX_IO_CORES] = {0}; 
module_param_array(h_cpu_affinity, int, &h_cpu_affinity_argc, S_IRUGO);
MODULE_PARM_DESC(h_cpu_affinity, "Array of CPU affinity for iocore threads; 0 - no affinity, negative - spinning, positive - thread will sleep");

//
// I/O Guest
//

int g_eth_name_argc;
char *g_eth_name[MAX_ETH_COUNT];
module_param_array(g_eth_name, charp, &g_eth_name_argc, S_IRUGO);

int g_cpu_affinity_argc;
int g_cpu_affinity[MAX_IO_CORES] = {0};
module_param_array(g_cpu_affinity, int, &g_cpu_affinity_argc, S_IRUGO);
MODULE_PARM_DESC(h_cpu_affinity, "Array of CPU affinity for iocore threads; 0 - no affinity, negative - spinning, positive - thread will sleep");
                                                                                                                           
struct gsocket {
    struct bsocket bsocket;
};

struct generic {
    struct list_head devices_list;

    data_handler                  tcp_handler;
    data_handler                  control_handler;
    data_handler                  handler;
    struct channel {
        struct raw_socket *raw_socket;    
        struct l2socket *tcp_socket;
        struct l2socket *control_socket;

        char interface_name[64];

        int allowed_iocores[MAX_IO_CORES];
        int nr_iocores;

#if TRACE_DEBUG
        int total_rx_packets;
        int total_tx_packets;
#endif
    } channels[MAX_ETH_COUNT];

    struct iocore {
        struct cqueue work_queue; 
        struct task_struct *user_thread;

    #if TRACE_DEBUG
        int stat_total_jobs;
        atomic_t stat_outstanding_jobs;
        int stat_max_outstanding_jobs;
    #endif

        atomic_t does_polling;
        struct list_head poll_interfaces;

        int core_id;
        int physical_core_id;
        bool spinning_worker;

        long iohyp_empty_loops;
        long iohyp_gpoll_loops;
        atomic64_t iohyp_work_cycles_t;
        atomic64_t iohyp_gpoll_cycles_t;

        char iocore_name[32];
        struct dev_ext_attribute fs_iocore_attr;        
    } iocores[MAX_IO_CORES];

    atomic_t next_iocore;
    struct device *fs_iocore_dev;

    int num_interface;
    char **interface_name;
    int num_iocores;
    int *cpu_affinity;
};

static struct generic host;
static struct generic guest;

// 
// Encapsulating vrio_eth module
//
/*
int gsend_iov(struct gsocket *gsocket, struct iovec *iov, size_t iov_len) {
    return send_iov((struct bsocket *)gsocket, iov, iov_len);
}
EXPORT_SYMBOL(gsend_iov);

//int igsend_iov(struct gsocket *gsocket, struct iovec *iov, size_t iov_len, struct iovec *diov) {
//    return isend_iov((struct bsocket *)gsocket, iov, iov_len, diov);
//}
//EXPORT_SYMBOL(igsend_iov);

int gsend_buff(struct gsocket *gsocket, char *buff, size_t length) {
    return send_buff((struct bsocket *)gsocket, buff, length);
}
EXPORT_SYMBOL(gsend_buff);

int gsend_skb(struct gsocket *gsocket, struct sk_buff *skb) {
    return send_skb((struct bsocket *)gsocket, skb);
}
EXPORT_SYMBOL(gsend_skb);

void gsend_raw_skb(struct gsocket *gsocket, struct sk_buff *skb) {
    send_raw_skb((struct bsocket *)gsocket, skb);
}
EXPORT_SYMBOL(gsend_raw_skb);

void gfree_packet(struct gsocket *gsocket, struct giovec* giovec) {
    free_packet((struct bsocket *)gsocket, (struct biovec *)giovec);
}
EXPORT_SYMBOL(gfree_packet);

void gfree_gsocket(struct gsocket *gsocket) {
    kfree(gsocket);
}
EXPORT_SYMBOL(gfree_gsocket);

struct sk_buff *gdetach_skb(struct giovec *giovec) {
    return detach_skb((struct biovec *)giovec);
}
EXPORT_SYMBOL(gdetach_skb);

struct sk_buff *giovec_to_skb(struct net_device *dev,
                              struct iovec *iov,
                              size_t iov_len,
                              struct skb_frag_destructor *destroy) {
    return iovec_to_skb(dev, iov, iov_len, destroy);
}
EXPORT_SYMBOL(giovec_to_skb);

int gzbsend(struct gsocket *gsocket, struct iovec *iov, size_t iov_len, struct skb_frag_destructor *destroy) {
    return zbsend_iov((struct bsocket *)gsocket, iov, iov_len, destroy);
}
EXPORT_SYMBOL(gzbsend);
*/

__always_inline static struct generic *bsocket_to_generic(struct bsocket *bsocket) {
    return (struct generic *)(bsocket->l2socket->private_data3);
}

__always_inline static struct channel *l2socket_to_channel(struct l2socket *l2socket) {
    return (struct channel *)l2socket->private_data2;
}

__always_inline static struct channel *bsocket_to_channel(struct bsocket *bsocket) {
    return l2socket_to_channel(bsocket->l2socket);
}

__always_inline static struct iocore *get_default_iocore(struct generic *generic) {
    return &generic->iocores[0];
}

__always_inline static int get_next_iocore_id(struct generic *generic, struct bsocket *bsocket) {
    struct channel *channel = bsocket_to_channel(bsocket);
    int iocore;

    if (channel->nr_iocores == 0) {
        iocore = atomic_read(&generic->next_iocore) % generic->num_iocores;
//1        trace("selected iocroe: %d", iocore);
    } else {
        iocore = channel->allowed_iocores[atomic_read(&generic->next_iocore) % channel->nr_iocores]; 
        trace("allowed cpu: %d", iocore);
    }

    atomic_inc(&generic->next_iocore);
    return iocore;
}

__always_inline static struct iocore *get_next_iocore(struct generic *generic, struct bsocket *bsocket) {
    int iocore = get_next_iocore_id(generic, bsocket);
//    atrace(iocore >= generic->num_iocores);
    return &generic->iocores[iocore];
}

__always_inline static struct iocore *sprinkler(struct generic *generic, struct bsocket *bsocket, struct biovec *biovec) {
    struct giocore *giocore;
    struct vrio_header *vhdr;
    int iocore;

#if SDEV_HACK
    atrace(biovec->iov[0].iov_len < VRIO_HEADER_SIZE, return NULL);
    vhdr = (struct vrio_header *)biovec->iov[0].iov_base;
    giocore = (struct giocore *)vhdr->host_priv;

    if (atomic_read(&giocore->iopackets)) {
        iocore = giocore->affinity_core_id;
        trace("Number of iopackets in iocore queue: %d, iocore: %d", atomic_read(&giocore->iopackets), iocore);
    } else {
        iocore = get_next_iocore_id(generic, bsocket);
        giocore->affinity_core_id = iocore;
        trace("assigning new iocore: %d", iocore);
    }
    atomic_inc(&giocore->iopackets);
#else
    iocore = get_next_iocore_id(generic, bsocket);
#endif    

    return &generic->iocores[iocore];
}

struct poll_interface {
    struct list_head link;

    char if_name[32];
    struct net_device *dev;
};

struct poll_if_work {
    struct gwork_struct gwork;

    struct iocore *iocore;
    char if_name[32];
    bool add;
};

static struct poll_interface *get_polling_interface(struct list_head *pifs, char *if_name) {
    struct poll_interface *pif, *n;

    list_for_each_entry_safe(pif, n, pifs, link) {
        if (strcmp(pif->if_name, if_name) == 0) 
            return pif;
    }

    return NULL;
}

static struct net_device *get_net_device(char *if_name) {        
    struct net_device *dev;
    struct net *net;

    rtnl_lock();        
    net = current->nsproxy->net_ns;
    dev = __dev_get_by_name(net, if_name);
    if (!dev) {
        etrace("__dev_get_by_name failed, interface name %s didn't found", if_name);    
        rtnl_unlock();
        return NULL;
    }

    rtnl_unlock();
    return dev;
}

static void add_polling_interface(struct iocore *iocore, char *if_name) {
    struct list_head *pifs = &iocore->poll_interfaces;
    struct poll_interface *pif;
    struct net_device *dev;

    dev = get_net_device(if_name);
    if (!dev) {
        etrace("get_net_device failed");
        return;
    }

    if (!dev->netdev_ops->ndo_set_poll_mode) {
        etrace("device %s doesn't support polling", dev->name);
        return;
    }

    pif = get_polling_interface(pifs, if_name);
    if (pif == NULL) {        
        pif = (struct poll_interface *)kmalloc(sizeof(struct poll_interface), GFP_ATOMIC); 
        strcpy(pif->if_name, if_name);
        pif->dev = dev;

        dev->netdev_ops->ndo_set_poll_mode(dev ,true);

        list_add(&pif->link, pifs);

        mtrace("interface %s added to polling list of iocore: %d", if_name, iocore->core_id+1);    
        atomic_inc(&iocore->does_polling);

        if (iocore->user_thread->state != TASK_RUNNING)
            wake_up_process(iocore->user_thread);        
    }
}

static void __remove_polling_interface(struct iocore *iocore, struct poll_interface *pif) {
    pif->dev->netdev_ops->ndo_set_poll_mode(pif->dev ,false);
    list_del(&pif->link);
    kfree(pif);

    atomic_dec(&iocore->does_polling);
}

static void remove_polling_interface(struct iocore *iocore, char *if_name) {
    struct list_head *pifs = &iocore->poll_interfaces;
    struct poll_interface *pif;

    pif = get_polling_interface(pifs, if_name);
    if (pif == NULL) {
        ntrace("interface %s doesn't exist", if_name);
        return;
    }
    
    mtrace("interface %s removed from iocore %d polling list", if_name, iocore->core_id+1);
    __remove_polling_interface(iocore, pif);
}

static void __remove_all_polling_interfaces(struct iocore *iocore) {
    struct list_head *pifs = &iocore->poll_interfaces;
    struct poll_interface *pif, *n;

    trace("removing all remaining polling interfaces");
    list_for_each_entry_safe(pif, n, pifs, link) {
        trace("removing %s interface", pif->if_name);
        __remove_polling_interface(iocore, pif);
    }

    atrace(atomic_read(&iocore->does_polling) != 0, etrace("atomic_read(&iocore->does_polling) = %d", atomic_read(&iocore->does_polling)));
}

static void remove_all_polling_interfaces(struct generic *generic) {
    int i;

    for (i=0; i<generic->num_iocores; i++) {
        __remove_all_polling_interfaces(&generic->iocores[i]);
    }
}
static bool __queue_gwork(struct iocore *iocore, struct gwork_struct *gwork);

void iocore_poll_work(struct gwork_struct *gwork) {
    struct poll_if_work *poll_if_work = container_of(gwork, struct poll_if_work, gwork);
//    mtrace("iocore_poll_work");

    if (poll_if_work->add) 
        add_polling_interface(poll_if_work->iocore, poll_if_work->if_name);
    else 
        remove_polling_interface(poll_if_work->iocore, poll_if_work->if_name);

    kfree(poll_if_work);
}

static void remove_interface_from_polling(struct generic *generic, unchar *interface_name) {
    struct poll_if_work *poll_if_work;
    int i;

    for (i=0; i< generic->num_iocores; i++) {
        poll_if_work = (struct poll_if_work *)kmalloc(sizeof(struct poll_if_work), GFP_ATOMIC); 
        atrace(poll_if_work == NULL, continue);
        init_gwork_func(&poll_if_work->gwork, iocore_poll_work);
        strncpy(poll_if_work->if_name, interface_name, 64);
        poll_if_work->iocore = &generic->iocores[i];
        poll_if_work->add = false;
                
        __queue_gwork(poll_if_work->iocore, &poll_if_work->gwork);
    }
}

__always_inline static int gpoll(struct list_head *pifs, int budget) {
    struct poll_interface *pif, *n;
    int total_rx_packets = 0;

    list_for_each_entry_safe(pif, n, pifs, link) {
        trace("polling on: %s", pif->if_name);
        total_rx_packets += pif->dev->netdev_ops->ndo_poll(pif->dev, budget);   
    }

    return total_rx_packets;
}

__always_inline static bool __queue_gwork(struct iocore *iocore, struct gwork_struct *gwork) {
    int res;
    res = cenqueue(&iocore->work_queue, &gwork->clink);
    if (res == CQUEUE_QUEUE_IS_FULL) {
        etrace("queue is full, dropping work");
        return false;
    }
    if (res == CQUEUE_ELM_IN_QUEUE) {
        trace("work already queued");
        return true;
    }

#if TRACE_DEBUG
    iocore->stat_total_jobs++;
    atomic_inc(&iocore->stat_outstanding_jobs);
    iocore->stat_max_outstanding_jobs = max(iocore->stat_max_outstanding_jobs, 
                                            atomic_read(&iocore->stat_outstanding_jobs));
#endif
    if (iocore->user_thread->state != TASK_RUNNING)
        wake_up_process(iocore->user_thread);
    return true;
}

bool queue_gwork(struct gsocket *gsocket, struct gwork_struct *gwork) {
    struct generic *generic;
    struct iocore *iocore;

    atrace(gsocket == NULL, return false);

    generic = bsocket_to_generic(&gsocket->bsocket);
    iocore = get_next_iocore(generic, &gsocket->bsocket);

    return __queue_gwork(iocore, gwork);
}
EXPORT_SYMBOL(queue_gwork);

struct iopacket {
    struct gwork_struct gwork;
    struct bsocket *bsocket;
    struct biovec *biovec;
};

void iopacket_handler(struct gwork_struct *gwork) {
    struct iopacket *iopacket = container_of(gwork, struct iopacket, gwork);
    struct bsocket *bsocket;
    struct biovec *biovec;

    trace("iopacket_handler");
    bsocket = iopacket->bsocket;
    biovec = iopacket->biovec; 

    ((gwork_handler)bsocket->l2socket->handler)((ulong)bsocket, (ulong)biovec);
}

void h_iopacket_handler(struct gwork_struct *gwork) {
    struct iopacket *iopacket = container_of(gwork, struct iopacket, gwork);
    struct giocore *giocore;
    struct bsocket *bsocket;
    struct biovec *biovec;

    struct vrio_header *vhdr;

    trace("h_iopacket_handler");
    bsocket = iopacket->bsocket;
    biovec = iopacket->biovec; 

#if SDEV_HACK
    atrace(biovec->iov[0].iov_len < VRIO_HEADER_SIZE, return);
    vhdr = (struct vrio_header *)biovec->iov[0].iov_base;
    giocore = (struct giocore *)vhdr->host_priv;

    ((gwork_handler)bsocket->l2socket->handler)((ulong)bsocket, (ulong)biovec);
    atomic_dec(&giocore->iopackets);
#else
    ((gwork_handler)bsocket->l2socket->handler)((ulong)bsocket, (ulong)biovec);
#endif    
}

void h_socket_handler(struct bsocket *bsocket, struct biovec* biovec) {    
    struct generic *generic;
    struct channel *channel;
    struct iocore *iocore;
    struct iopacket *iopacket = (struct iopacket *)biovec->data;
    trace("h_socket_handler");

    iopacket->bsocket = bsocket;
    iopacket->biovec = biovec;

    generic = bsocket_to_generic(bsocket);
    channel = bsocket_to_channel(bsocket); 
    
    if (unlikely(channel->control_socket == bsocket->l2socket)) {
        trace("control iopacket, dispatching to default iocore");
        init_gwork_func(&iopacket->gwork, iopacket_handler);
        set_cq_flag(&iopacket->gwork.clink, CQ_FLAG_NO_MARK);
        iocore = get_default_iocore(generic);
        __queue_gwork(iocore, &iopacket->gwork);
    } else {
        trace("calling sprinkler to decide on iocore");
        init_gwork_func(&iopacket->gwork, h_iopacket_handler);
        set_cq_flag(&iopacket->gwork.clink, CQ_FLAG_NO_MARK);
        iocore = sprinkler(generic, bsocket ,biovec);
        atrace(iocore == NULL, return);
        __queue_gwork(iocore, &iopacket->gwork);
    }
}

void g_socket_handler(struct bsocket *bsocket, struct biovec* biovec) {    
    struct iopacket *iopacket = (struct iopacket *)biovec->data;
    struct generic *generic;
    struct iocore *iocore;

    trace("g_socket_handler");

    iopacket->bsocket = bsocket;
    iopacket->biovec = biovec;

    generic = bsocket_to_generic(bsocket); 

    init_gwork_func(&iopacket->gwork, iopacket_handler);
    set_cq_flag(&iopacket->gwork.clink, CQ_FLAG_NO_MARK);
    iocore = get_default_iocore(generic);

    __queue_gwork(iocore, &iopacket->gwork);
}

__always_inline static long calculate_cycles(long s, long e) {
    return (e - s); 
}

/*
int get_iocore(struct iocore *iocore) {
    return iocore->core_id;
}
*/

#define ns_to_us(x) (x >> 10)
#define us_to_ns(x) (x << 10)

int generic_handler_thread(void *data) { 
    struct gwork_struct *gwork;
    struct cqueue_struct *cq_elm;
    struct iocore *iocore = (struct iocore *)data;
    struct cqueue *cqueue = &iocore->work_queue;
    int total_rx_packets;

#if TRACE_DEBUG
    bool is_contended_flag = false;
#endif
            
#if MEASURE_IOHYP_CYCLES
    long s_cycles = 0, e_cycles = 0;
#endif

    trace("start");
repeat:
    if (unlikely(kthread_should_stop())) {
        //__set_current_state(TASK_RUNNING);
        trace("done");
        return 0;
    }

    cq_elm = cdequeue(cqueue); 
    if (likely(cq_elm)) {
#if TRACE_DEBUG
        total_packets++;
        if (is_contended_flag) 
            contended_packets++; 
        is_contended_flag = true;
#endif

#if MEASURE_IOHYP_CYCLES
        if (is_using_rdtsc)
            s_cycles = get_cycles();
#endif
        trace("calling user handler");
        gwork = container_of(cq_elm, struct gwork_struct, clink);  
        gwork->func(gwork);
        trace("calling user handler done");

#if TRACE_DEBUG
        atomic_dec(&iocore->stat_outstanding_jobs);
#endif
#if MEASURE_IOHYP_CYCLES
        if (is_using_rdtsc) {
            e_cycles = get_cycles();
            atomic64_add(calculate_cycles(s_cycles, e_cycles), &iocore->iohyp_work_cycles_t);
//            atomic64_add(calculate_cycles(s_cycles, e_cycles), &iohyp_work_cycles_t);
//            iohyp_work_cycles = atomic64_read(&iohyp_work_cycles_t);
        }
#endif
    } else { /* no work to-do */
        if (atomic_read(&iocore->does_polling)) {
#if MEASURE_IOHYP_CYCLES
            if (is_using_rdtsc) 
                s_cycles = get_cycles();
#endif
            total_rx_packets = gpoll(&iocore->poll_interfaces, poll_budget);
#if MEASURE_IOHYP_CYCLES
            if (total_rx_packets)
                iocore->iohyp_gpoll_loops++;

            if (is_using_rdtsc && total_rx_packets) {
                e_cycles = get_cycles();
                atomic64_add(calculate_cycles(s_cycles, e_cycles), &iocore->iohyp_gpoll_cycles_t);

//                atomic64_add(calculate_cycles(s_cycles, e_cycles), &iohyp_gpoll_cycles_t);
//                iohyp_gpoll_cycles = atomic64_read(&iohyp_gpoll_cycles_t);
            }
#endif            
            if (!total_rx_packets) {
#if MEASURE_IOHYP_CYCLES
                iocore->iohyp_empty_loops++;
#endif
                if (iohyp_schedule_on_empty_loop)
                    schedule();
            }
        } else
            if (!iocore->spinning_worker) {
                trace("There's no more work to do, going to sleep");
                set_current_state(TASK_INTERRUPTIBLE);  /* mb paired w/ kthread_stop */
                schedule();
            }


#if TRACE_DEBUG
        is_contended_flag = false;
#endif
    }
    
    if (unlikely(need_resched()))
        schedule();

    goto repeat;
}

struct l2socket *open_socket(struct raw_socket *raw_socket, int port, data_handler handler, bool run_from_softirq_context) {
    struct l2socket *l2socket;

    l2socket = __open_l2socket(raw_socket, port, handler, run_from_softirq_context);
    return l2socket;
}

void __unregister(struct vdev *vdev);

void add_vdev_l2socket(struct vdev *vdev, struct l2socket *l2socket) {
    vdev->l2sockets[vdev->l2sockets_nr++] = l2socket;
}

bool remove_vdev_l2socket(struct vdev *vdev, struct raw_socket* raw_socket) {
    struct l2socket **_l2socket = NULL;
    int i;

    for (i=0; i<MAX_ETH_COUNT; i++) {
        if (vdev->l2sockets[i]->raw_socket == raw_socket) {
            _l2socket = &vdev->l2sockets[i];
            break;
        }
    }

    close_l2socket(*_l2socket);

    atrace(_l2socket == NULL, return false);
    memcpy(_l2socket, _l2socket+1, 
        sizeof(struct l2socket *) *          
        (MAX_ETH_COUNT - (_l2socket - vdev->l2sockets) - 1));
    vdev->l2sockets_nr--;

    return true;
}

struct channel *alloc_channel(struct generic *generic) {
    return &generic->channels[generic->num_interface++];
}

struct channel *get_channel(struct generic *generic, unchar *interface_name);
static void remove_interface_from_polling(struct generic *generic, unchar *interface_name);

bool remove_channel(struct generic *generic, unchar *interface_name) {
    struct channel *channel;
    struct vdev *vdev;

    channel = get_channel(generic, interface_name);
    atrace(channel == NULL, return false);
    
    remove_interface_from_polling(generic, interface_name);
    mdelay(500);

    if (likely(!list_empty(&generic->devices_list))) {
        list_for_each_entry(vdev, &generic->devices_list, link) {
            remove_vdev_l2socket(vdev, channel->raw_socket);
        }
    }

    close_raw_socket(channel->raw_socket);

    memcpy(channel, channel+1, 
        sizeof(struct channel) * 
        (MAX_ETH_COUNT - (channel - generic->channels) - 1));
    generic->num_interface--;

    return true;
};

bool __register_channel(struct generic *generic, struct channel *channel, struct vdev *vdev) {
    struct l2socket *l2socket;

    l2socket = open_socket(channel->raw_socket, -1, (data_handler)vdev->handler, vdev->run_from_softirq_context);
    if (l2socket == NULL) {
        etrace("open_socket failed");
        return false;
    }

    add_vdev_l2socket(vdev, l2socket);

    l2socket->private_data2 = (ulong)channel;
    l2socket->private_data3 = (ulong)generic;
    return true;
}

bool __open_socket(struct channel *channel, struct generic *generic, char *interface_name);

bool register_channel(struct generic *generic, unchar *interface_name) {
    struct channel *channel;
    struct vdev *vdev;
    bool ret;

    channel = get_channel(generic, interface_name);
    atrace(channel != NULL, return false);
    channel = alloc_channel(generic);
    atrace(channel == NULL, return false);

    ret = __open_socket(channel, generic, interface_name);
    atrace(!ret, return false);

    if (likely(!list_empty(&generic->devices_list))) {
        list_for_each_entry(vdev, &generic->devices_list, link) {
            ret = __register_channel(generic, channel, vdev);
            atrace(!ret, goto close_raw_socket);
        }
    }

    return true;

close_raw_socket:
    close_raw_socket(channel->raw_socket);
    return false;
}

bool __register(struct generic *generic, struct vdev *vdev) {            
    bool ret;
    int i;
   
    list_add(&vdev->link, &generic->devices_list);
        
    for (i=0; i<MAX_ETH_COUNT; ++i) {
        vdev->l2sockets[i] = NULL;
    }
    vdev->l2sockets_nr = 0;

    for (i=0; i<generic->num_interface; ++i) {
        ret = __register_channel(generic, &generic->channels[i], vdev);
        if (!ret) {
            etrace("__register_channel");
            __unregister(vdev);
            return false;
        }
    }

    return true;
}

void __unregister(struct vdev *vdev) {    
    int i;

    list_del(&vdev->link);
    for (i=0; i<MAX_ETH_COUNT; ++i) {
        if (vdev->l2sockets[i]) {
            close_l2socket(vdev->l2sockets[i]);
        }
    }
}


static struct device *fs_dir_init(void *owner, 
                                  struct device *parent,
                                  const char *fmt, ...);

static void fs_dir_exit(struct device *fs_dev);

bool vhost_register(struct vdev *vdev) {
    vdev->fs_dev = fs_dir_init(NULL, fs_devices, vdev->name);
    atrace(vdev->fs_dev == NULL);

    return __register(&host, vdev);
}
EXPORT_SYMBOL(vhost_register);

void vhost_unregister(struct vdev *vdev) {    
    fs_dir_exit(vdev->fs_dev);

    __unregister(vdev);
}
EXPORT_SYMBOL(vhost_unregister);

bool vdev_register(struct vdev *vdev) {
    return __register(&guest, vdev);
}
EXPORT_SYMBOL(vdev_register);

void vdev_unregister(struct vdev *vdev) {
    __unregister(vdev);    
}
EXPORT_SYMBOL(vdev_unregister);

struct channel *get_channel(struct generic *generic, unchar *interface_name) {
    int i;

    trace("interface_name: %s", interface_name);
    for (i=0; i<generic->num_interface; i++) {            
        if (strncmp(generic->channels[i].interface_name, interface_name, 32) == 0) {
            return &generic->channels[i];
        }
    }
    
    return NULL;
}

struct l2socket *get_tcp_socket(struct generic *generic, unchar *interface_name) {
    struct channel *channel = get_channel(generic, interface_name);
    if (channel)
        return channel->tcp_socket;

    return NULL;
}

struct l2socket *get_control_socket(struct generic *generic, unchar *interface_name) {    
    struct channel *channel = get_channel(generic, interface_name);
    if (channel) 
        return channel->control_socket;

    return NULL;
}

struct vdev *get_vdev(struct generic *generic, unchar *device_name) {
    struct vdev *vdev;

    trace("device_name: %s", device_name);
    if (likely(!list_empty(&generic->devices_list))) {
        list_for_each_entry(vdev, &generic->devices_list, link) {
            if (strncmp(vdev->name, device_name, sizeof(vdev->name)) == 0) {                
                return vdev;
            }
        }
    }

    return NULL;
}

struct l2socket *get_l2socket(struct vdev *vdev, unchar *interface_name) {
    int i;
    struct channel *channel;

    atrace(vdev == NULL, return NULL);

    for (i=0; i<MAX_ETH_COUNT; i++) {
        if (vdev->l2sockets[i] == NULL)
            break;

        channel = l2socket_to_channel(vdev->l2sockets[i]); //(struct channel *)vdev->l2sockets[i]->private_data2;

        if (strncmp(channel->interface_name, interface_name, 32) == 0) {                
            return vdev->l2sockets[i];     
        }
    }

    return NULL;
}

long dispatch_ioctl(struct generic *generic, struct ioctl_param *ioctl_param) {
    struct vdev *vdev;
    long ret = -EFAULT;

    trace("dispatching ioctl %lp to %s", ioctl_param, ioctl_param->device_name);
    vdev = get_vdev(generic, ioctl_param->device_name);
    if (vdev) {
        ret = vdev->ioctl(ioctl_param);
    }

    return ret;
}

struct l2socket *get_vdev_l2socket(struct generic *generic, char *device_name, char *interface_name) { 
    struct vdev *vdev;
    struct l2socket *l2socket;

    trace("device_name: %s, interface_name: %s", device_name, interface_name);
    vdev = get_vdev(generic, device_name);
    atrace(vdev == NULL, return NULL);
    l2socket = get_l2socket(vdev, interface_name);

    return l2socket;
}

int get_vdev_data_port(struct generic *generic, char *device_name, char *interface_name) { 
    struct l2socket *l2socket;

    trace("device_name: %s, interface_name: %s", device_name, interface_name);
    l2socket = get_vdev_l2socket(generic, device_name, interface_name);
    atrace(l2socket == NULL, return -1);

    return l2socket->src_port;
}

char *get_l2socket_if_name(struct l2socket *l2socket) {
    struct channel *channel;
    channel = l2socket_to_channel(l2socket); //(struct channel *)l2socket->private_data2;        
    return channel->interface_name;
}

void close_sockets(struct generic *generic);
void close_iocores(struct generic *generic);

bool __open_socket(struct channel *channel, struct generic *generic, char *interface_name) {
    strncpy(channel->interface_name, interface_name, sizeof(channel->interface_name));
    trace("creating raw socket on interface: %s", channel->interface_name);
    // Creating raw socket on particular interface
    channel->raw_socket = __open_raw_socket(channel->interface_name, generic->handler);
    atrace(channel->raw_socket == NULL, goto out);

    channel->nr_iocores = 0;
    channel->tcp_socket = open_socket(channel->raw_socket, TCP_PORT, generic->tcp_handler, true);
    channel->control_socket = open_socket(channel->raw_socket, CONTROL_PORT, generic->control_handler, false);
    channel->control_socket->private_data2 = (ulong)channel;
    channel->control_socket->private_data3 = (ulong)generic;
    atrace(channel->control_socket == NULL, goto out);

#if TRACE_DEBUG
    channel->total_rx_packets = 0;
    channel->total_tx_packets = 0;
#endif

    return true;

out:
    return false;
}

bool open_sockets(struct generic *generic) {
    struct channel *channel;
    bool ret;
    int i;

    for (i=0; i<generic->num_interface; i++) {
        channel = &generic->channels[i];
        ret =__open_socket(channel, generic, generic->interface_name[i]);
        if (!ret) {
            goto close_socket;
        }
    }

    return true;
close_socket:
    close_sockets(generic);
    return false;
}

void close_sockets(struct generic *generic) {
    int i;

    for (i=0; i<generic->num_interface; i++) {
        if (generic->channels[i].raw_socket) 
            close_raw_socket(generic->channels[i].raw_socket);
    }
}

static ssize_t generic_fs_iocore_get_stats(struct device *dir,
                                           struct device_attribute *attr, 
                                           char *buf) {
    struct iocore *iocore = (struct iocore *)((struct dev_ext_attribute *)attr)->var;
    unsigned long cpufreq = cpufreq_get(iocore->physical_core_id) * 1000;
    int cpu_util = 0;
    ssize_t length = 0;
    trace("querying cpu for frequency: %d", iocore->physical_core_id);

//    static unsigned long last_jiffies = 0;
//    static unsigned long last_cycles;

//    unsigned long now_jiffies = jiffies;
    unsigned long now_cycles = atomic64_read(&iocore->iohyp_work_cycles_t) + 
                               atomic64_read(&iocore->iohyp_gpoll_cycles_t);
/*    if (last_jiffies) {
        unsigned long interval = now_jiffies - last_jiffies;
        if (interval)
             cpu_util = ((100 * (now_cycles - last_cycles)) / cpufreq)  / (interval / HZ);
//        cpu_util += 1;
    }
    last_jiffies = now_jiffies;
    last_cycles = now_cycles;
*/
    length = sprintf(buf, "%-22s%-22s%-30s%-22s%-22s%-22s%-22s%-22s%-22s%-22s\n"
                          "%-22lu%-22s%-30d%-22lu%-22lu%-22lu%-22lu%-22lu%-22d%-22lu\n", 
                          "CPU_frequency", "Spinning_Worker", "Number_of_Polled_Interfaces", "Empty_Loops", 
                          "Poll_Loops", "Work_Cycles", "Poll_Cycles", "Total_Core_Cycles", "CPU_Utilization",
                          "timestamp",
        cpufreq,
        iocore->spinning_worker == true ? "YES" : "NO",
        atomic_read(&iocore->does_polling),
        iocore->iohyp_empty_loops,
        iocore->iohyp_gpoll_loops,
        atomic64_read(&iocore->iohyp_work_cycles_t),
        atomic64_read(&iocore->iohyp_gpoll_cycles_t),
        now_cycles,
        cpu_util,
        jiffies);

    return length;
}

void create_iocores_sysfs_dir(struct generic *generic) {
    int i;

    for (i=0; i<generic->num_iocores; i++) {
        sprintf(generic->iocores[i].iocore_name, "iocore%d", generic->iocores[i].physical_core_id); // core_id+1); // t_core);        
        generic->iocores[i].fs_iocore_attr = (struct dev_ext_attribute){ .attr = { .attr = { .name = generic->iocores[i].iocore_name, 
                                                                                             .mode = S_IRUSR | S_IRGRP | S_IROTH }, 
                                                                                   .show = generic_fs_iocore_get_stats, 
                                                                                   .store = NULL }, 
                                                                         .var = &generic->iocores[i] };
        fs_device_file_create(generic->fs_iocore_dev, &generic->iocores[i].fs_iocore_attr);
    }
}

void remove_iocores_sysfs_dir(struct generic *generic) {
    int i;

    for (i=0; i<generic->num_iocores; i++) {
        fs_device_file_remove(generic->fs_iocore_dev, &generic->iocores[i].fs_iocore_attr);
    }
}

bool open_iocores(struct generic *generic) {
    int i, t_core;

    for (i=0; i<generic->num_iocores; i++) {
        generic->iocores[i].core_id = i;        

        // New thread to handle all raw socket's I/O requests
        t_core = generic->cpu_affinity[i];
        init_cqueue(&generic->iocores[i].work_queue, work_queue_size);
        
        generic->iocores[i].user_thread = kthread_create(generic_handler_thread, &generic->iocores[i], "iocore-%d", (int)abs(t_core));
        atrace(generic->iocores[i].user_thread == NULL, goto close_iocores);

        if (t_core) {
            generic->iocores[i].spinning_worker = (t_core < 0);

            t_core = abs(t_core) - 1;
            generic->iocores[i].physical_core_id = t_core;

            trace("setting thread affinity to %d", t_core);
            kthread_bind(generic->iocores[i].user_thread, t_core);
        } else {
            generic->iocores[i].spinning_worker = false;
//            ntrace("DEPRECATED");
        }

        INIT_LIST_HEAD(&generic->iocores[i].poll_interfaces);
        atomic_set(&generic->iocores[i].does_polling, 0);

        generic->iocores[i].iohyp_empty_loops = 0;
        generic->iocores[i].iohyp_gpoll_loops = 0;
        atomic64_set(&generic->iocores[i].iohyp_work_cycles_t, 0);
        atomic64_set(&generic->iocores[i].iohyp_gpoll_cycles_t, 0);
        
        trace("iocore's thread: %p, core: %d", generic->iocores[i].user_thread, t_core);
        wake_up_process(generic->iocores[i].user_thread);
    }

    return true;
close_iocores:
    close_iocores(generic);
    return false;
}

void close_iocores(struct generic *generic) {
    int i;

    for (i=0; i<generic->num_iocores; i++) {
        if (generic->iocores[i].user_thread) {
            trace("stopping user thread");
            kthread_stop(generic->iocores[i].user_thread);
            trace("user thread stopped");
            generic->iocores[i].user_thread = NULL;
            done_cqueue(&generic->iocores[i].work_queue);
        }
    }
}

//struct gsocket *galloc_gsocket(struct l2socket *l2socket, struct tcpsocket *tcpsocket, unsigned char *mac_address, unsigned char port) 
struct gsocket *galloc_gsocket(struct l2socket *l2socket, 
                               unsigned char *mac_address, unsigned char port,
                               __u32 ip,
                               __be16 tcp_port) 
{
    struct gsocket *gsocket;

    gsocket = (struct gsocket *)kmalloc(sizeof(struct gsocket), GFP_ATOMIC);
    atrace(gsocket == NULL, return NULL);
    if (gsocket) {
        gsocket->bsocket.l2socket = l2socket; 
        init_l2address(&gsocket->bsocket.l2address, 
                       mac_address, 
                       port, ip, tcp_port);
    }

    return gsocket;
}

//struct gsocket *galloc_gsocket(struct l2socket *l2socket, struct l2address *l2address, unsigned char *mac_address, unsigned char port) {
//}

void h_control_handler(struct bsocket *bsocket, struct biovec* biovec) {
//void h_control_handler(ulong param1, ulong param2) {
//    struct bsocket *bsocket = (struct bsocket *)param1;
//    struct biovec *biovec = (struct biovec *)param2;
    struct ioctl_param local_param;
    int ret;
    trace("h_control_handler");

    ret = memcpy_fromiovecend_skip((char *)&local_param, biovec->iov, biovec->iov_len, sizeof(struct ioctl_param));
    atrace(ret != 0);

//    if (local_param.cmd == 30) {
//        static int times=0;
//
//        if (times < 2)
//            send_buff(bsocket, (char *)&local_param, sizeof(struct ioctl_param));
//        times++;
//    }

    if (local_param.cmd == VRIO_IOCTL_HOST) {
        trace("guest MAC address: %.*b", 6, bsocket->l2address.mac_address);
        local_param.x.create.gsocket = (ulong)galloc_gsocket(
            get_vdev_l2socket(&host, 
                    local_param.device_name, 
                    get_l2socket_if_name(bsocket->l2socket)),  
 // bsocket->l2socket,
//            &bsocket->l2address.tcpsocket,
            bsocket->l2address.mac_address, 
            local_param.x.create.guest_port,
            bsocket->l2address.ip_addr,
            bsocket->l2address.tcp_port);

        trace("host gsocket: %p / guest_port: %d", local_param.x.create.gsocket, 
            local_param.x.create.guest_port);
        
        dispatch_ioctl(&host, &local_param);


//        local_param.cmd = 30;
//        trace("sending packet to guest a30a");
//        send_buff(bsocket, (char *)&local_param, sizeof(struct ioctl_param));
//        send_buff(bsocket, (char *)&local_param, sizeof(struct ioctl_param));
        //send_buff(bsocket, (char *)&local_param, sizeof(struct ioctl_param));

//
//        local_param.cmd = VRIO_IOCTL_ACK;
//        bsocket->l2address.tcpsocket.type = 3;
//        trace("VRIO_IOCTL_HOST, sending ACK");
//        send_buff(bsocket, (char *)&local_param, sizeof(struct ioctl_param));
//          
    } else {
        trace("ioctl: no such command");            
    }

    free_packet(bsocket, biovec);
}

void sanity_check(struct generic *generic);

//void g_control_handler(ulong param1, ulong param2) {
void g_control_handler(struct bsocket *bsocket, struct biovec* biovec) {
    struct ioctl_param local_param;
    int ret;
    trace("g_control_handler_work");

//    free_packet(bsocket, biovec);
//    return;
	
    ret = memcpy_fromiovecend_skip((char *)&local_param, biovec->iov, biovec->iov_len, sizeof(struct ioctl_param));
    atrace(ret != 0, return);

    switch (local_param.cmd) {
        case 30: {
//            msleep(100);
//            trace("sending packet back");
//            send_buff(bsocket, (char *)&local_param, sizeof(struct ioctl_param));
//            send_buff(bsocket, (char *)&local_param, sizeof(struct ioctl_param));
            break;
        }
        case VRIO_IOCTL_CREATE_SDEV:
        case VRIO_IOCTL_CREATE_NET:                                             
        case VRIO_IOCTL_CREATE_BLK: {
            local_param.x.create.gsocket = (ulong)galloc_gsocket(/*bsocket->l2socket*/
                get_vdev_l2socket(&guest, 
                    local_param.device_name, 
                    get_l2socket_if_name(bsocket->l2socket)),  
                // &bsocket->l2address.tcpsocket, 
		bsocket->l2address.mac_address, 
                local_param.x.create.host_port,
                bsocket->l2address.ip_addr,
                bsocket->l2address.tcp_port);

            trace("guest gsocket: %p / host_port: %d", local_param.x.create.gsocket, 
                local_param.x.create.host_port);
            break;                            
        }    

        case VRIO_IOCTL_SANITY_CHECK: {
#if IOCTL_CHECKSUM
            atrace(local_param.checksum != calc_checksum(&local_param));            
#endif            
            sanity_check(&guest);    
            break;
        }

        default: {
            trace("ioctl: no such command");            
            break;
        }
    }

    dispatch_ioctl(&guest, &local_param);    
    if (local_param.cmd == VRIO_IOCTL_CREATE_NET) {
        local_param.x.create.guest_port = get_vdev_data_port(&guest, 
            local_param.device_name, 
            get_l2socket_if_name(bsocket->l2socket));
        
        local_param.cmd = VRIO_IOCTL_HOST;
//        bsocket->l2address.tcpsocket.type = 4; // 2
//	atomic_set(&bsocket->l2address.tcpsocket.seq, 1);
        trace("VRIO_IOCTL_CREATE_NET, sending guest_priv: %lp", local_param.x.create.guest_priv);
        send_buff(bsocket, (char *)&local_param, sizeof(struct ioctl_param));
    }

    free_packet(bsocket, biovec);
}

struct l2address g_l2address;
bool g_flag = false;

void h_tcp_handler(struct bsocket *bsocket, struct biovec* biovec) {
    trace("h_tcp_handler");

    g_l2address = bsocket->l2address;
    g_flag = true;
    free_packet(bsocket, biovec);
}

void g_tcp_handler(struct bsocket *bsocket, struct biovec* biovec) {
    trace("g_tcp_handler");

    trace("sending 2nd packet handshake");
//    bsocket->l2address.tcpsocket.type = 2;
    send_buff(bsocket, NULL, 0);
 
    free_packet(bsocket, biovec);
}

//
// IOCTL Interface
//

static int generic_open(struct inode *inode, struct file *file) {
    trace("generic_open");
    return 0;
}

static int generic_close(struct inode *inode, struct file *file) {    
    trace("generic_close");
    return 0;
}

//#define QUADIP(a,b,c,d) \
//    ((d&0xFF) << 24 | (c&0xFF) << 16 | (b&0xFF) << 8 | (a&0xFF))

static int remote_ioctl(struct ioctl_param *ioctl_param) {
    struct l2address l2address;
    struct l2socket *l2socket;
    int ret = 0;
                
    trace("remote mac address: %.*b, ip address: %d.%d.%d.%d", 
        6, ioctl_param->guest_mac_address, 
        NIPQUAD(ioctl_param->guest_ip_address));
//    init_l2address(&l2address, (unchar *)ioctl_param->guest_mac_address, CONTROL_PORT);
    init_l2address(&l2address, (unchar *)ioctl_param->guest_mac_address, 
        TCP_PORT, ioctl_param->guest_ip_address, 0);
//1    init_l2address(&l2address, (unchar *)ioctl_param->guest_mac_address, 
//1        TCP_PORT, QUADIP(10,0,0,245), 0);
//
//    l2socket = get_control_socket(&host, ioctl_param->interface_name);            
    l2socket = get_tcp_socket(&host, ioctl_param->interface_name);            
    if (l2socket) {
        ret = __send_buff(l2socket, (char *)ioctl_param, 0, &l2address);        
        trace("__send_buff: %d", ret);
    }
   
//	return ret;
 
    msleep(1000);
    if (g_flag == false) {
        etrace("g_flag is false");
        return -1;
    }

//    g_l2address.tcpsocket.type = 3;
    g_l2address.port = CONTROL_PORT;
    l2socket = get_control_socket(&host, ioctl_param->interface_name);
    if (l2socket) {
        ret = __send_buff(l2socket, (char *)ioctl_param, sizeof(struct ioctl_param), &g_l2address);
        trace("__send_buff: %d", ret);
    }

    return 0; // ret;
}

void sanity_check_work(struct gwork_struct *gwork) {
    mtrace("sanity_check_work");
}

void trace_biovec(struct biovec *biovec);

void trace_giovec(struct giovec *giovec) {
    trace_biovec((struct biovec *)giovec);
}
EXPORT_SYMBOL(trace_giovec);

void sanity_check_generic(struct generic *generic) {
    int i;
    struct channel *channel;
    struct iocore *iocore;
    struct gsocket gsocket;
    static struct gwork_struct gwork;

    for (i=0; i<generic->num_interface; i++) {
        channel = &generic->channels[i];
        if (channel->raw_socket) {
            mtrace("interface_name: %s", channel->interface_name);
            mtrace("--");

            trace_raw_socket(channel->raw_socket);
            gsocket.bsocket.l2socket = channel->control_socket;

            clear_socket_rx_buffers(channel->raw_socket);
            
            init_gwork_func(&gwork, sanity_check_work);
            queue_gwork(&gsocket, &gwork);
        }
    }

    for (i=0; i<generic->num_iocores; i++) {
        iocore = &generic->iocores[i];
        trace("iocore id %d, job_queue empty: %d", i, cqueue_empty(&iocore->work_queue));
#if TRACE_DEBUG
            mtrace("iocore id: %d, total_jobs: %d, outstanding_jobs: %d, max_outstanding_jobs: %d", 
                iocore->core_id,
                iocore->stat_total_jobs,
                atomic_read(&iocore->stat_outstanding_jobs), 
                iocore->stat_max_outstanding_jobs);

            mtrace("stat_total_enqueue: %d", iocore->work_queue.stat_total_enqueue);
            mtrace("stat_total_dequeue: %d", iocore->work_queue.stat_total_dequeue);

            mtrace("stat_max_enqueue_rounds: %d", iocore->work_queue.stat_max_enqueue_rounds);
            mtrace("stat_max_dequeue_rounds: %d", iocore->work_queue.stat_max_dequeue_rounds);

            if (iocore->work_queue.stat_total_enqueue && iocore->work_queue.stat_total_dequeue) {
                mtrace("stat_avg_enqueue_rounds: %d", iocore->work_queue.stat_total_enqueue_rounds / 
                                                      iocore->work_queue.stat_total_enqueue);
                mtrace("stat_avg_dequeue_rounds: %d", iocore->work_queue.stat_total_dequeue_rounds / 
                                                      iocore->work_queue.stat_total_dequeue);
            }
#endif                                 
    }
}

void sanity_check(struct generic *generic) {
    mtrace("sanity_check");
    sanity_check_generic(generic);
}

void fs_device_file_create(struct device *fs_dev, struct dev_ext_attribute *attr) {
    int res;
    trace("creating file %s.\n", attr->attr.attr.name);
    
    res = device_create_file(fs_dev, &attr->attr);
    if (res < 0){
        WARN(res < 0, "couldn't create class file %s, err = %d.\n",
                    attr->attr.attr.name, res);
        trace("DONE - ERROR.");
        return;
    }
}
EXPORT_SYMBOL(fs_device_file_create);

void fs_device_file_remove(struct device *fs_dev, struct dev_ext_attribute *attr) {
    trace("removing file %s.\n", attr->attr.attr.name); 
    device_remove_file(fs_dev, &attr->attr);
}
EXPORT_SYMBOL(fs_device_file_remove);

static struct device *fs_dir_init(void *owner, 
                                  struct device *parent,
                                  const char *fmt, ...) {
    struct device *fs_dev;
    va_list vargs;
    trace("START.");

    va_start(vargs, fmt);
    fs_dev = device_create_vargs(fs_class, parent, (dev_t)0,
                                 owner, fmt, vargs);
    va_end(vargs);

    if (IS_ERR(fs_dev)) {
        etrace("Failed to create directory %s", fmt);
        return NULL;
    }

    trace("DONE.");
    return fs_dev;
}

static void fs_dir_exit(struct device *fs_dev) {
    trace("START.");
    if (!fs_dev)
        return;
    // Releasing the device directory
    trace("Releasing the device directory.");
    // vhost_printk("Decrement reference count to device object.");
    // put_device(vhost_fs_dev);
    trace("Unregistering the device.");
    device_unregister(fs_dev);
    trace("DONE.");
}

static void vhost_fs_init(void) {
    trace("START.");

    // create the vhost class
    trace("create the vhost class.");
    fs_class = class_create(THIS_MODULE, MODULE_NAME);
    if (IS_ERR(fs_class)) {
        WARN(IS_ERR(fs_class), "couldn't create class, err = %ld\n",
             PTR_ERR(fs_class));
        return;
    }

    // add device directory
    trace("add devices directory.");
    fs_devices = fs_dir_init(NULL, NULL, "%s", FS_DIRECTORY_DEVICE);

    trace("DONE.");
}

static void vhost_fs_exit(void) {
    trace("START.");

    // Remove devices directory
    trace("Remove devices directory.");
    fs_dir_exit(fs_devices);

    trace("Destroy the vhost fs class.");
    if (fs_class)
        class_destroy(fs_class);
    trace("DONE.");
}

/*
struct ioctl_param g_local_param;

void remote_ioctl_work(ulong param1, ulong param2) {   
    trace("remote_ioctl_work");
    remote_ioctl(&g_local_param);
}
*/

static long generic_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param) {
    long ret = 0;
    struct ioctl_param local_param;

    spin_lock(&g_lock);
    trace("generic_ioctl");

    if (copy_from_user((void *)&local_param, (void *)ioctl_param, sizeof(struct ioctl_param))) {                    
        return  -ENOMEM;            
    }

    switch (ioctl_num) {
        case GENERIC_IOCTL_CREATE: {    
            mtrace("GENERIC_IOCTL_CREATE");
            local_param.x.create.host_port = get_vdev_data_port(&host, 
                local_param.device_name, 
                local_param.interface_name);

            ret = dispatch_ioctl(&host, &local_param);
            if (ret) {
                etrace("dispatch_ioctl failed");
                break;
            }
//            if (local_param.cmd == VRIO_IOCTL_CREATE_NET) {
//                if (local_param.interface_name[0] == '-')
//                    add_polling_interface(&poll_interfaces, local_param.interface_name + 1);                
//            }
            ret = remote_ioctl(&local_param);
            break;                     
        }

        case GENERIC_IOCTL_REMOVE: {
            mtrace("GENERIC_IOCTL_REMOVE");
//            if (local_param.cmd == VRIO_IOCTL_CREATE_NET) {
//                if (local_param.interface_name[0] == '-')
//                    add_polling_interface(&poll_interfaces, local_param.interface_name + 1);                
//            }
            ret = dispatch_ioctl(&host, &local_param);
            if (ret) {
                etrace("dispatch_ioctl failed");
                break;
            }

            ret = remote_ioctl(&local_param);
            break;                            
        }
        case GENERIC_IOCTL_IOCORE: {
            int i;
            struct channel *channel = get_channel(&host, local_param.interface_name);
            mtrace("GENERIC_IOCTL_IOCORE (array_nr: %d)", local_param.x.iocore.nr_iocores);
            if (channel != NULL) {
                for (i=0; i<local_param.x.iocore.nr_iocores; i++) {
                    atrace(local_param.x.iocore.iocores[i]-1 >= host.num_iocores);
                    channel->allowed_iocores[i] = (local_param.x.iocore.iocores[i]-1) % host.num_iocores;
                    mtrace("allowed_iocores[%d]: %d", i, channel->allowed_iocores[i]+1);
                }   
                channel->nr_iocores = local_param.x.iocore.nr_iocores;
            } else 
                etrace("Channel with interface name %s couldn't be found", local_param.interface_name);
            break;
        }
        case GENERIC_IOCTL_POLL: {
            struct poll_if_work *poll_if_work;
            int iocore, i;

            mtrace("GENERIC_IOCTL_POLL");
            for (i=0; i< local_param.x.poll.nr_iocores; i++) {
                iocore = local_param.x.poll.iocores[i];
                if (abs(iocore) > host.num_iocores)
                    continue;

                poll_if_work = (struct poll_if_work *)kmalloc(sizeof(struct poll_if_work), GFP_ATOMIC); 
                atrace(poll_if_work == NULL, continue);
                init_gwork_func(&poll_if_work->gwork, iocore_poll_work);
                strncpy(poll_if_work->if_name, local_param.interface_name, 32);
                poll_if_work->iocore = &host.iocores[abs(iocore)-1];
                poll_if_work->add = (iocore < 0) ? true : false;
                
                __queue_gwork(poll_if_work->iocore, &poll_if_work->gwork);
            }

            break;
        }
        case GENERIC_IOCTL_CHANNEL: {
            bool ret;

            mtrace("GENERIC_IOCTL_CHANNEL");
            if (local_param.interface_name[0] == '-') {
                ret = remove_channel(&host, local_param.interface_name+1);
                mtrace("remove_channel %s (%d)", local_param.interface_name, ret);
            } else {
                ret = register_channel(&host, local_param.interface_name);
                mtrace("register_channel %s (%d)", local_param.interface_name, ret);
            }
            break;
        }
        case GENERIC_IOCTL_GENERIC: {
            mtrace("GENERIC_IOCTL_GENERIC");

            dispatch_ioctl(&host, &local_param);
            remote_ioctl(&local_param);
            break;
        }
        case GENERIC_SANITY_CHECK: {
            mtrace("GENERIC_SANITY_CHECK");
            sanity_check(&host);
            dispatch_ioctl(&host, &local_param);
#if IOCTL_CHECKSUM
            local_param.checksum = calc_checksum(&local_param);
#endif
            remote_ioctl(&local_param);
            break;                            
        }                           
        
        default: {            
            etrace("ioctl: no such command\n");            
            ret = -EINVAL;                     
        }
    } 

    spin_unlock(&g_lock);
    return ret;
}

struct file_operations generic_dev_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = generic_ioctl,
    .open           = generic_open,
    .release        = generic_close,
};

static struct miscdevice generic_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "iohyp",
    .fops  = &generic_dev_fops,
};

static int __init generic_init(void) {
    int ret;
    mtrace("module generic up");
    spin_lock_init(&g_lock);

    // hack - need to fix
//    if (init_lmempool(&poll_mempool, 64, sizeof(struct poll_interface)) == false) {
//        etrace("init_mempool failed");
//        goto out_error;
//    }

//    INIT_LIST_HEAD(&poll_interfaces);
//    atomic_set(&does_polling, 0);
//#if MEASURE_IOHYP_CYCLES
//    atomic64_set(&iohyp_work_cycles_t, 0);
//    atomic64_set(&iohyp_gpoll_cycles_t, 0);
//#endif
    INIT_LIST_HEAD(&host.devices_list);
    host.tcp_handler      = h_tcp_handler;
    trace("hTCP handler: %lp", h_tcp_handler);
    host.control_handler  = h_control_handler;
    host.handler          = h_socket_handler;
    host.num_interface    = h_eth_name_argc;
    host.num_iocores      = h_cpu_affinity_argc;
    host.interface_name   = h_eth_name;
    host.cpu_affinity     = h_cpu_affinity;
    atomic_set(&host.next_iocore, 0);

    INIT_LIST_HEAD(&guest.devices_list);
    guest.tcp_handler     = g_tcp_handler;
    trace("gTCP handler: %lp", g_tcp_handler);
    guest.control_handler = g_control_handler;
    guest.handler         = g_socket_handler;
    guest.num_interface   = g_eth_name_argc;
    guest.num_iocores     = g_cpu_affinity_argc;
    guest.interface_name  = g_eth_name;
    guest.cpu_affinity    = g_cpu_affinity;
    atomic_set(&guest.next_iocore, 0);

    if (!open_sockets(&guest)) {
        etrace("guest open_sockets failed");
        goto out_error;
    }

    if (!open_iocores(&guest)) {
        etrace("guest open_iocores failed");
        goto out_close_guest;
    }

    if (host.num_interface > 0) {

        if (host.num_interface == 1 && host.interface_name[0][0] == '\0')
            host.num_interface = 0;

        //
        // Register misc device (for ioctl) only for host
        //
        ret = misc_register(&generic_misc);	
        if (ret < 0) {
            etrace("Registration failed");
            goto out_close_guest_iocore;
        }
        generic_driver_registered = true;

        mtrace("misc driver registerd successfully");
        
        if (!open_sockets(&host)) {          
            etrace("host open_sockets failed");        
            goto out_misc_deregister;
        }

        if (!open_iocores(&host)) {          
            etrace("host open_iocores failed");        
            goto out_close_host;
        }

        vhost_fs_init();

        host.fs_iocore_dev = fs_dir_init(NULL, fs_devices, "core");
        atrace(host.fs_iocore_dev == NULL);

        create_iocores_sysfs_dir(&host);        
    }

    return 0;

out_close_host:
    close_sockets(&host);
out_misc_deregister:
    misc_deregister(&generic_misc);
out_close_guest_iocore:
    close_iocores(&guest);
out_close_guest:
    close_sockets(&guest);
out_error:
    return -1;
}

static void __exit generic_exit(void) {
    mtrace("module generic down");

    close_iocores(&host);
    close_iocores(&guest);
    if (generic_driver_registered) { // host.num_interface > 0) {
        misc_deregister(&generic_misc);
        remove_all_polling_interfaces(&host);

        remove_iocores_sysfs_dir(&host);
        fs_dir_exit(host.fs_iocore_dev);    

        vhost_fs_exit();
    }
    close_sockets(&host);
    close_sockets(&guest);
}

module_init(generic_init);
module_exit(generic_exit);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Yossi Kuperman");
MODULE_DESCRIPTION("vRIO - generic layer");

#endif
