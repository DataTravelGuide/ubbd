#ifndef UBBD_INTERNAL_H
#define UBBD_INTERNAL_H

#include <linux/bsearch.h>
#include <linux/xarray.h>

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/blk-mq.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/idr.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/uio.h>
#include <net/genetlink.h>

#include <linux/types.h>

#include <linux/uio_driver.h>

#include "ubbd.h"
#include "compat.h"

#define DEV_NAME_LEN 32
#define UBBD_SINGLE_MAJOR_PART_SHIFT 4
#define UBBD_DRV_NAME "ubbd"

#define UBBD_UIO_DATA_PAGES	(256 * 1024)
#define UBBD_UIO_DATA_RESERVE_PERCENT	75

/* request stats */
#undef UBBD_REQUEST_STATS

#ifdef UBBD_REQUEST_STATS
#define ubbd_req_stats_ktime_get(V) V = ktime_get() 
#define ubbd_req_stats_ktime_aggregate(T, D) T = ktime_add(T, D)
#define ubbd_req_stats_ktime_delta(V, ST) V = ktime_sub(ktime_get(), ST)
#else
#define ubbd_req_stats_ktime_get(V)
#define ubbd_req_stats_ktime_aggregate(T, D)
#define ubbd_req_stats_ktime_delta(V, ST)
#endif /* UBBD_REQUEST_STATS */

extern struct workqueue_struct *ubbd_wq;

struct ubbd_queue {
	struct ubbd_device	*ubbd_dev;

	int			index;
	struct list_head	inflight_reqs;
	spinlock_t		inflight_reqs_lock;
	u64			req_tid;

	struct uio_info		uio_info;
	struct xarray		data_pages_array;
	unsigned long		*data_bitmap;

	struct ubbd_sb		*sb_addr;

	void			*cmdr;
	void			*compr;
	size_t			data_off;
	u32			data_pages;
	u32			data_pages_allocated;
	u32			data_pages_reserve;
	uint32_t		max_blocks;
	size_t			mmap_pages;

	struct mutex   		req_lock;
	spinlock_t 		state_lock;
	unsigned long		flags;

	struct inode		*inode;
	struct work_struct	complete_work;
	cpumask_t		cpumask;

	struct dentry		*q_debugfs_d;
#ifdef	UBBD_REQUEST_STATS
	struct dentry		*q_debugfs_req_stats_f;

	uint64_t		stats_reqs;

	ktime_t			start_to_prepare;
	ktime_t			start_to_submit;

	ktime_t			start_to_complete;
	ktime_t			start_to_release;
#endif /* UBBD_REQUEST_STATS */
};

#define UBBD_QUEUE_FLAGS_REMOVING	1

struct ubbd_device {
	int			dev_id;		/* blkdev unique id */

	int			major;		/* blkdev assigned major */
	int			minor;
	struct gendisk		*disk;		/* blkdev's gendisk and rq */

	char			name[DEV_NAME_LEN]; /* blkdev name, e.g. ubbd3 */

	spinlock_t		lock;		/* open_count */
	struct list_head	dev_node;	/* ubbd_dev_list */
	struct mutex		state_lock;

	/* Block layer tags. */
	struct blk_mq_tag_set	tag_set;

	struct dentry		*dev_debugfs_d;
	struct dentry		*dev_debugfs_queues_d;

	unsigned long		open_count;	/* protected by lock */

	uint32_t		num_queues;
	struct ubbd_queue	*queues;
	struct workqueue_struct	*task_wq;

	u8			status;
	struct kref		kref;
};

struct ubbd_dev_add_opts {
	u32	data_pages;
	u64	device_size;
	u64	dev_features;
	u32	num_queues;
};

extern struct list_head ubbd_dev_list;
extern int ubbd_total_devs;
extern struct mutex ubbd_dev_list_mutex;

static inline int ubbd_dev_id_to_minor(int dev_id)
{
	return dev_id << UBBD_SINGLE_MAJOR_PART_SHIFT;
}

static inline int minor_to_ubbd_dev_id(int minor)
{
	return minor >> UBBD_SINGLE_MAJOR_PART_SHIFT;
}

void ubbd_dev_get(struct ubbd_device *ubbd_dev);
int ubbd_dev_get_unless_zero(struct ubbd_device *ubbd_dev);
void ubbd_dev_put(struct ubbd_device *ubbd_dev);
extern struct device *ubbd_uio_root_device;
static int ubbd_open(struct block_device *bdev, fmode_t mode)
{
	struct ubbd_device *ubbd_dev = bdev->bd_disk->private_data;

	ubbd_dev_get(ubbd_dev);
	spin_lock_irq(&ubbd_dev->lock);
	ubbd_dev->open_count++;
	spin_unlock_irq(&ubbd_dev->lock);

	return 0;
}

static void ubbd_release(struct gendisk *disk, fmode_t mode)
{
	struct ubbd_device *ubbd_dev = disk->private_data;

	spin_lock_irq(&ubbd_dev->lock);
	ubbd_dev->open_count--;
	spin_unlock_irq(&ubbd_dev->lock);
	ubbd_dev_put(ubbd_dev);
}

static const struct block_device_operations ubbd_bd_ops = {
	.owner			= THIS_MODULE,
	.open			= ubbd_open,
	.release		= ubbd_release,
};


#define UBBD_REQ_INLINE_PI_MAX	4

struct ubbd_request {
	struct ubbd_queue	*ubbd_q;

	struct ubbd_se		*se;
	struct ubbd_ce		*ce;
	struct request		*req;

	enum ubbd_op		op;
	u64			req_tid;
	struct list_head	inflight_reqs_node;
	uint32_t		pi_cnt;
	uint32_t		inline_pi[UBBD_REQ_INLINE_PI_MAX];
	uint32_t		*pi;
	struct work_struct	work;

#ifdef	UBBD_REQUEST_STATS
	ktime_t			start_kt;

	ktime_t			start_to_prepare;
	ktime_t			start_to_submit;

	ktime_t			start_to_complete;
	ktime_t			start_to_release;
#endif
};

#define UPDATE_CMDR_HEAD(head, used, size) smp_store_release(&head, ((head % size) + used) % size)
#define UPDATE_CMDR_TAIL(tail, used, size) smp_store_release(&tail, ((tail % size) + used) % size)

#define UPDATE_COMPR_TAIL(tail, used, size) smp_store_release(&tail, ((tail % size) + used) % size)

static inline void ubbd_flush_dcache_range(void *vaddr, size_t size)
{
        unsigned long offset = offset_in_page(vaddr);
        void *start = vaddr - offset;

        size = round_up(size+offset, PAGE_SIZE);

        while (size) {
                flush_dcache_page(vmalloc_to_page(start));
                start += PAGE_SIZE;
                size -= PAGE_SIZE;
        }
}
extern struct genl_family ubbd_genl_family;
void complete_work_fn(struct work_struct *work);
blk_status_t ubbd_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd);
void ubbd_end_inflight_reqs(struct ubbd_device *ubbd_dev, int ret);
void ubbd_queue_end_inflight_reqs(struct ubbd_queue *ubbd_q, int ret);
enum blk_eh_timer_return ubbd_timeout(struct request *req, bool reserved);
struct ubbd_device *ubbd_dev_add_dev(struct ubbd_dev_add_opts *);
void ubbd_dev_remove_dev(struct ubbd_device *ubbd_dev);
void ubbd_dev_remove_disk(struct ubbd_device *ubbd_dev, bool force);
void ubbd_dev_stop_disk(struct ubbd_device *ubbd_dev, bool force);
int ubbd_add_disk(struct ubbd_device *ubbd_dev);
int ubbd_queue_uio_init(struct ubbd_queue *ubbd_q);
void ubbd_queue_uio_destroy(struct ubbd_queue *ubbd_q);

/* debugfs */
void ubbd_debugfs_add_dev(struct ubbd_device *ubbd_dev);
void ubbd_debugfs_remove_dev(struct ubbd_device *ubbd_dev);
void ubbd_debugfs_cleanup(void);
void __init ubbd_debugfs_init(void);

#undef UBBD_FAULT_INJECT

#ifdef UBBD_FAULT_INJECT
#define UBBD_REQ_FAULT_MASK	0x0fff	/* 1/4096 */
#define UBBD_MGMT_FAULT_MASK	0x000f	/* 1/16 */

#include <linux/random.h>

static inline bool ubbd_req_need_fault(void)
{
	return ((get_random_u32() & UBBD_REQ_FAULT_MASK) == 1);
}

static inline bool ubbd_mgmt_need_fault(void)
{
	return ((get_random_u32() & UBBD_MGMT_FAULT_MASK) == 1);
}
#else
static inline bool ubbd_req_need_fault(void)
{
	return false;
}

static inline bool ubbd_mgmt_need_fault(void)
{
	return false;
}
#endif /* UBBD_FAULT_INJECT */

/* debug messages */
#define ubbd_err(fmt, ...)						\
	pr_err("ubbd: " fmt, ##__VA_ARGS__)
#define ubbd_info(fmt, ...)						\
	pr_info("ubbd: " fmt, ##__VA_ARGS__)
#define ubbd_debug(fmt, ...)						\
	pr_debug("ubbd: " fmt, ##__VA_ARGS__)

#define ubbd_dev_err(dev, fmt, ...)					\
	ubbd_err("ubbd%d: " fmt,					\
		 dev->dev_id, ##__VA_ARGS__)

#define ubbd_dev_info(dev, fmt, ...)					\
	ubbd_info("ubbd%d: " fmt,					\
		 dev->dev_id, ##__VA_ARGS__)

#define ubbd_dev_debug(dev, fmt, ...)					\
	ubbd_debug("ubbd%d: " fmt,					\
		 dev->dev_id, ##__VA_ARGS__)

#endif /* UBBD_INTERNAL_H */
