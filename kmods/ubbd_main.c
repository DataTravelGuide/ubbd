/*
 * Userspace Backend Block Device
 */

#include "ubbd_internal.h"
#include <linux/blkdev.h>

LIST_HEAD(ubbd_dev_list);    /* devices */
int ubbd_total_devs = 0;
DEFINE_MUTEX(ubbd_dev_list_mutex);

struct workqueue_struct *ubbd_wq;
static int ubbd_major;
static DEFINE_IDA(ubbd_dev_id_ida);
struct device *ubbd_uio_root_device;

static int ubbd_init_hctx(struct blk_mq_hw_ctx *hctx, void *driver_data,
			unsigned int hctx_idx)
{
	struct ubbd_device *ubbd_dev = driver_data;
	struct ubbd_queue *ubbd_q;

	ubbd_q = &ubbd_dev->queues[hctx_idx];
	hctx->driver_data = ubbd_q;

	return 0;
}

static const struct blk_mq_ops ubbd_mq_ops = {
	.queue_rq	= ubbd_queue_rq,
	.timeout	= ubbd_timeout,
	.init_hctx	= ubbd_init_hctx,
};

int ubbd_queue_sb_init(struct ubbd_queue *ubbd_q)
{
	struct ubbd_sb *sb;

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault()) {
		return -ENOMEM;
	}
#endif
	sb = vzalloc(RING_SIZE);
	if (!sb) {
		return -ENOMEM;
	}

	ubbd_q->sb_addr = sb;
	ubbd_q->cmdr = (void *)sb + CMDR_OFF;
	ubbd_q->compr = (void *)sb + COMPR_OFF;
	ubbd_q->data_off = RING_SIZE;
	ubbd_q->mmap_pages = (ubbd_q->data_pages + (RING_SIZE >> PAGE_SHIFT));

	/* Initialise the sb of the ring buffer */
	sb->version = UBBD_SB_VERSION;
	sb->info_off = UBBD_INFO_OFF;
	sb->info_size = UBBD_INFO_SIZE;
	sb->cmdr_off = CMDR_OFF;
	sb->cmdr_size = CMDR_SIZE;
	sb->compr_off = COMPR_OFF;
	sb->compr_size = COMPR_SIZE;
	pr_debug("info_off: %u, info_size: %u, cmdr_off: %u, cmdr_size: %u, \
			compr_off: %u, compr_size: %u, data_off: %lu",
			sb->info_off, sb->info_size, sb->cmdr_off,
			sb->cmdr_size, sb->compr_off, sb->compr_size,
			ubbd_q->data_off);

	return 0;
}

void ubbd_queue_sb_destroy(struct ubbd_queue *ubbd_q)
{
	vfree(ubbd_q->sb_addr);
}

static void ubbd_page_release(struct ubbd_queue *ubbd_q);
static void ubbd_queue_destroy(struct ubbd_queue *ubbd_q)
{
	ubbd_queue_uio_destroy(ubbd_q);
	ubbd_queue_sb_destroy(ubbd_q);

	ubbd_page_release(ubbd_q);

	xa_destroy(&ubbd_q->data_pages_array);

	if (ubbd_q->data_bitmap)
		bitmap_free(ubbd_q->data_bitmap);
}

static int ubbd_queue_create(struct ubbd_queue *ubbd_q, u32 data_pages)
{
	int ret;

	ubbd_q->data_pages = data_pages;
	ubbd_q->data_pages_reserve = \
		ubbd_q->data_pages * UBBD_UIO_DATA_RESERVE_PERCENT / 100;

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault())
		return -ENOMEM;
#endif
	ubbd_q->data_bitmap = bitmap_zalloc(ubbd_q->data_pages, GFP_KERNEL);
	if (!ubbd_q->data_bitmap) {
		return -ENOMEM;
	}

	xa_init(&ubbd_q->data_pages_array);

	ret = ubbd_queue_sb_init(ubbd_q);
	if (ret) {
		pr_err("failed to init dev sb: %d.", ret);
		goto err;
	}

	ret = ubbd_queue_uio_init(ubbd_q);
	if (ret) {
		pr_debug("failed to init uio: %d.", ret);
		goto err;
	}


	mutex_init(&ubbd_q->req_lock);
	spin_lock_init(&ubbd_q->state_lock);
	INIT_LIST_HEAD(&ubbd_q->inflight_reqs);
	spin_lock_init(&ubbd_q->inflight_reqs_lock);
	ubbd_q->req_tid = 0;
	INIT_WORK(&ubbd_q->complete_work, complete_work_fn);
	cpumask_clear(&ubbd_q->cpumask);

	return 0;
err:
	return ret;
}

static void ubbd_dev_destroy_queues(struct ubbd_device *ubbd_dev)
{
	int i;

	for (i = 0; i < ubbd_dev->num_queues; i++) {
		ubbd_queue_destroy(&ubbd_dev->queues[i]);
	}

	kfree(ubbd_dev->queues);
}

static int ubbd_dev_create_queues(struct ubbd_device *ubbd_dev, int num_queues, u32 data_pages)
{
	int i;
	int ret;
	struct ubbd_queue *ubbd_q;

	ubbd_dev->num_queues = num_queues;
	ubbd_dev->queues = kcalloc(ubbd_dev->num_queues, sizeof(struct ubbd_queue), GFP_KERNEL);
	if (!ubbd_dev->queues) {
		return -ENOMEM;
	}

	for (i = 0; i < num_queues; i++) {
		ubbd_q = &ubbd_dev->queues[i];
		ubbd_q->ubbd_dev = ubbd_dev;
		ubbd_q->index = i;
		ret = ubbd_queue_create(ubbd_q, data_pages);
		if (ret)
			goto err;
	}

	return 0;
err:
	ubbd_dev_destroy_queues(ubbd_dev);
	return ret;
}

/* ubbd_dev lifecycle */
static struct ubbd_device *__ubbd_dev_create(u32 data_pages)
{
	struct ubbd_device *ubbd_dev;

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault())
		goto err;
#endif
	ubbd_dev = kzalloc(sizeof(*ubbd_dev), GFP_KERNEL);
	if (!ubbd_dev)
		goto err;

	ubbd_dev->status = UBBD_DEV_STATUS_INIT;

	spin_lock_init(&ubbd_dev->lock);
	mutex_init(&ubbd_dev->state_lock);
	INIT_LIST_HEAD(&ubbd_dev->dev_node);
	kref_init(&ubbd_dev->kref);

	return ubbd_dev;

err:
	return NULL;
}

static void __ubbd_dev_free(struct ubbd_device *ubbd_dev)
{
	kfree(ubbd_dev);
}

static void ubbd_page_release(struct ubbd_queue *ubbd_q)
{
	XA_STATE(xas, &ubbd_q->data_pages_array, 0);
	struct page *page;

	xas_lock(&xas);
	xas_for_each(&xas, page, ubbd_q->data_pages) {
		xas_store(&xas, NULL);
		__free_page(page);
	}
	xas_unlock(&xas);
}

struct ubbd_device *ubbd_dev_create(struct ubbd_dev_add_opts *add_opts)
{
	struct ubbd_device *ubbd_dev;
	int ret;

	ubbd_dev = __ubbd_dev_create(add_opts->data_pages);
	if (!ubbd_dev)
		return NULL;

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault())
		goto fail_ubbd_dev;
#endif
	ubbd_dev->dev_id = ida_simple_get(&ubbd_dev_id_ida, 0,
					 minor_to_ubbd_dev_id(1 << MINORBITS),
					 GFP_KERNEL);
	if (ubbd_dev->dev_id < 0)
		goto fail_ubbd_dev;

	sprintf(ubbd_dev->name, UBBD_DRV_NAME "%d", ubbd_dev->dev_id);

	ret = ubbd_dev_create_queues(ubbd_dev, add_opts->num_queues, add_opts->data_pages);
	if (ret)
		goto err_remove_id;

	ubbd_dev->task_wq = alloc_workqueue("ubbd-tasks", WQ_MEM_RECLAIM, 0);
	if (!ubbd_dev->task_wq) {
		goto err_destroy_queues;
	}

	__module_get(THIS_MODULE);

	pr_debug("%s ubbd_dev %p dev_id %d\n", __func__, ubbd_dev, ubbd_dev->dev_id);
	return ubbd_dev;

err_destroy_queues:
	ubbd_dev_destroy_queues(ubbd_dev);
err_remove_id:
	ida_simple_remove(&ubbd_dev_id_ida, ubbd_dev->dev_id);
fail_ubbd_dev:
	__ubbd_dev_free(ubbd_dev);
	return NULL;
}

void ubbd_dev_destroy(struct ubbd_device *ubbd_dev)
{
	destroy_workqueue(ubbd_dev->task_wq);
	ubbd_dev_destroy_queues(ubbd_dev);
	ida_simple_remove(&ubbd_dev_id_ida, ubbd_dev->dev_id);
	__ubbd_dev_free(ubbd_dev);
	module_put(THIS_MODULE);
}

static void ubbd_init_queue_cpumask(struct ubbd_device *ubbd_dev, struct blk_mq_tag_set *tag_set)
{
	struct ubbd_queue *ubbd_q;
	int cpu;
	unsigned int *map = tag_set->map[HCTX_TYPE_DEFAULT].mq_map;

	for_each_present_cpu(cpu) {
		ubbd_q = &ubbd_dev->queues[map[cpu]];
		cpumask_set_cpu(cpu, &ubbd_q->cpumask);
	}
}

#ifdef HAVE_ALLOC_DISK
static int ubbd_init_disk(struct ubbd_device *ubbd_dev)
{
	struct gendisk *disk;
	struct request_queue *q;
	int err;

        /* create gendisk info */
#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault()) {
		return -ENOMEM;
	}
#endif
        disk = alloc_disk(1 << UBBD_SINGLE_MAJOR_PART_SHIFT);
        if (!disk)
                return -ENOMEM;
 
        snprintf(disk->disk_name, sizeof(disk->disk_name), UBBD_DRV_NAME "%d",
                 ubbd_dev->dev_id);
	disk->major = ubbd_dev->major;
	disk->first_minor = ubbd_dev->minor;
	disk->minors = (1 << UBBD_SINGLE_MAJOR_PART_SHIFT);
	disk->flags |= GENHD_FL_EXT_DEVT;
	disk->fops = &ubbd_bd_ops;
	disk->private_data = ubbd_dev;

	memset(&ubbd_dev->tag_set, 0, sizeof(ubbd_dev->tag_set));
	ubbd_dev->tag_set.ops = &ubbd_mq_ops;
	ubbd_dev->tag_set.queue_depth = 128;
	ubbd_dev->tag_set.numa_node = NUMA_NO_NODE;
	ubbd_dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	ubbd_dev->tag_set.nr_hw_queues = ubbd_dev->num_queues;
	ubbd_dev->tag_set.cmd_size = sizeof(struct ubbd_request);
	ubbd_dev->tag_set.timeout = UINT_MAX;
	ubbd_dev->tag_set.driver_data = ubbd_dev;

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault()) {
		err = -ENOMEM;
		goto err_disk;
	}
#endif
	err = blk_mq_alloc_tag_set(&ubbd_dev->tag_set);
	if (err)
		goto err_disk;

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault()) {
		err = -ENOMEM;
		goto out_tag_set;
	}
#endif
        q = blk_mq_init_queue(&ubbd_dev->tag_set);
        if (IS_ERR(q)) {
                err = PTR_ERR(q);
		goto out_tag_set;
	}

	ubbd_init_queue_cpumask(ubbd_dev, &ubbd_dev->tag_set);
 
	blk_queue_flag_set(QUEUE_FLAG_NONROT, q);

	blk_queue_max_hw_sectors(q, 128);
	q->limits.max_sectors = queue_max_hw_sectors(q);
	blk_queue_max_segments(q, USHRT_MAX);
	blk_queue_max_segment_size(q, UINT_MAX);
	blk_queue_io_min(q, 4096);
	blk_queue_io_opt(q, 4096);

	blk_queue_flag_clear(QUEUE_FLAG_DISCARD, q);
	q->limits.discard_granularity = 0;
	blk_queue_max_discard_sectors(q, 0);
	blk_queue_max_write_zeroes_sectors(q, 0);

        WARN_ON(!blk_get_queue(q));
        disk->queue = q;
        q->queuedata = ubbd_dev;

	ubbd_dev->disk = disk;

	return 0;
out_tag_set:
	blk_mq_free_tag_set(&ubbd_dev->tag_set);
err_disk:
	put_disk(disk);
	return err;
}

void ubbd_free_disk(struct ubbd_device *ubbd_dev)
{
	blk_cleanup_queue(ubbd_dev->disk->queue);
	blk_mq_free_tag_set(&ubbd_dev->tag_set);
	put_disk(ubbd_dev->disk);
	ubbd_dev->disk = NULL;
}

int ubbd_add_disk(struct ubbd_device *ubbd_dev)
{
	add_disk(ubbd_dev->disk);
	blk_put_queue(ubbd_dev->disk->queue);

	return 0;
}
#else /* HAVE_ALLOC_DISK */
static int ubbd_init_disk(struct ubbd_device *ubbd_dev)
{
	struct gendisk *disk;
	struct request_queue *q;
	int err;

	memset(&ubbd_dev->tag_set, 0, sizeof(ubbd_dev->tag_set));
	ubbd_dev->tag_set.ops = &ubbd_mq_ops;
	ubbd_dev->tag_set.queue_depth = 128;
	ubbd_dev->tag_set.numa_node = NUMA_NO_NODE;
	ubbd_dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	ubbd_dev->tag_set.nr_hw_queues = ubbd_dev->num_queues;
	ubbd_dev->tag_set.cmd_size = sizeof(struct ubbd_request);
	ubbd_dev->tag_set.timeout = UINT_MAX;
	ubbd_dev->tag_set.driver_data = ubbd_dev;

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault()) {
		err = -ENOMEM;
		goto err;
	}
#endif
	err = blk_mq_alloc_tag_set(&ubbd_dev->tag_set);
	if (err)
		goto err;

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault()) {
		err = -ENOMEM;
		goto out_tag_set;
	}
#endif
	disk = blk_mq_alloc_disk(&ubbd_dev->tag_set, ubbd_dev);
	if (IS_ERR(disk)) {
		err = PTR_ERR(disk);
		goto out_tag_set;
	}
	q = disk->queue;

	ubbd_init_queue_cpumask(ubbd_dev, &ubbd_dev->tag_set);

        snprintf(disk->disk_name, sizeof(disk->disk_name), UBBD_DRV_NAME "%d",
                 ubbd_dev->dev_id);
	disk->major = ubbd_dev->major;
	disk->first_minor = ubbd_dev->minor;
	disk->minors = (1 << UBBD_SINGLE_MAJOR_PART_SHIFT);
	disk->flags |= GENHD_FL_EXT_DEVT;
	disk->fops = &ubbd_bd_ops;
	disk->private_data = ubbd_dev;
 
	blk_queue_flag_set(QUEUE_FLAG_NONROT, q);

	blk_queue_max_hw_sectors(q, 128);
	q->limits.max_sectors = queue_max_hw_sectors(q);
	blk_queue_max_segments(q, USHRT_MAX);
	blk_queue_max_segment_size(q, UINT_MAX);
	blk_queue_io_min(q, 4096);
	blk_queue_io_opt(q, 4096);

	blk_queue_flag_clear(QUEUE_FLAG_DISCARD, q);
	q->limits.discard_granularity = 0;
	blk_queue_max_discard_sectors(q, 0);
	blk_queue_max_write_zeroes_sectors(q, 0);

	ubbd_dev->disk = disk;

	return 0;
out_tag_set:
	blk_mq_free_tag_set(&ubbd_dev->tag_set);
err:
	return err;
}

void ubbd_free_disk(struct ubbd_device *ubbd_dev)
{
	blk_cleanup_disk(ubbd_dev->disk);
	blk_mq_free_tag_set(&ubbd_dev->tag_set);
	ubbd_dev->disk = NULL;
}

int ubbd_add_disk(struct ubbd_device *ubbd_dev)
{
	int ret;

	ret = add_disk(ubbd_dev->disk);

	return ret;
}
#endif /* HAVE_ALLOC_DISK */

int ubbd_dev_device_setup(struct ubbd_device *ubbd_dev,
			u64 device_size,
			u64 dev_features)
{
	int ret;

	ubbd_dev->major = ubbd_major;
	ubbd_dev->minor = ubbd_dev_id_to_minor(ubbd_dev->dev_id);

	ret = ubbd_init_disk(ubbd_dev);
	if (ret)
		return ret;

	set_capacity(ubbd_dev->disk, device_size / SECTOR_SIZE);
	set_disk_ro(ubbd_dev->disk, 0);

	if (dev_features & UBBD_ATTR_FLAGS_ADD_WRITECACHE) {
		if (dev_features & UBBD_ATTR_FLAGS_ADD_FUA)
			blk_queue_write_cache(ubbd_dev->disk->queue, true, true);
		else
			blk_queue_write_cache(ubbd_dev->disk->queue, true, false);
	} else {
		blk_queue_write_cache(ubbd_dev->disk->queue, false, false);
	}

	if (dev_features & UBBD_ATTR_FLAGS_ADD_DISCARD) {
		blk_queue_flag_set(QUEUE_FLAG_DISCARD, ubbd_dev->disk->queue);
		ubbd_dev->disk->queue->limits.discard_granularity = 4096;
		blk_queue_max_discard_sectors(ubbd_dev->disk->queue, 8 * 1024);
	}

	if (dev_features & UBBD_ATTR_FLAGS_ADD_WRITE_ZEROS) {
		blk_queue_max_write_zeroes_sectors(ubbd_dev->disk->queue, 8 * 1024);
	}

	return 0;
}


struct ubbd_device *ubbd_dev_add_dev(struct ubbd_dev_add_opts *add_opts)
{
	int ret;
	struct ubbd_device *ubbd_dev;

	ubbd_dev = ubbd_dev_create(add_opts);
	if (!ubbd_dev) {
		ret = -ENOMEM;
		goto out;
	}

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault()) {
		ret = -ENOMEM;
		goto err_dev_put;
	}
#endif
	ret = ubbd_dev_device_setup(ubbd_dev, add_opts->device_size, add_opts->dev_features);
	if (ret) {
		ret = -EINVAL;
		goto err_dev_put;
	}

	mutex_lock(&ubbd_dev_list_mutex);
	ubbd_total_devs++;
	list_add_tail(&ubbd_dev->dev_node, &ubbd_dev_list);
	mutex_unlock(&ubbd_dev_list_mutex);

	return ubbd_dev;

err_dev_put:
	ubbd_dev_put(ubbd_dev);
out:
	return ERR_PTR(ret);
}

void ubbd_dev_remove_dev(struct ubbd_device *ubbd_dev)
{
	mutex_lock(&ubbd_dev_list_mutex);
	ubbd_total_devs--;
	list_del_init(&ubbd_dev->dev_node);
	mutex_unlock(&ubbd_dev_list_mutex);

	ubbd_free_disk(ubbd_dev);
	ubbd_dev_put(ubbd_dev);
}

void ubbd_dev_stop_disk(struct ubbd_device *ubbd_dev, bool force)
{
	int i;

	for (i = 0; i < ubbd_dev->num_queues; i++) {
		struct ubbd_queue *ubbd_q;

		ubbd_q = &ubbd_dev->queues[i];
		set_bit(UBBD_QUEUE_FLAGS_REMOVING, &ubbd_q->flags);
		/*
		 * flush the task_wq, to avoid race with complete_work.
		 *
		 * after the flush_workqueue, all other work will return
		 * directly as UBBD_QUEUE_FLAGS_REMOVING is already set.
		 * Then we can end the inflight requests safely.
		 * */
		flush_workqueue(ubbd_dev->task_wq);
		if (force) {
			ubbd_end_inflight_reqs(ubbd_dev, -EIO);
		}
	}
}

void ubbd_dev_remove_disk(struct ubbd_device *ubbd_dev, bool force)
{
	bool disk_is_running;

	mutex_lock(&ubbd_dev->state_lock);
	disk_is_running = (ubbd_dev->status == UBBD_DEV_STATUS_RUNNING);
	ubbd_dev->status = UBBD_DEV_STATUS_REMOVING;
	mutex_unlock(&ubbd_dev->state_lock);

	ubbd_dev_stop_disk(ubbd_dev, force);

	if (disk_is_running) {
		del_gendisk(ubbd_dev->disk);
	}
}

void ubbd_dev_get(struct ubbd_device *ubbd_dev)
{
	kref_get(&ubbd_dev->kref);
}

static void __dev_release(struct kref *kref)
{
	struct ubbd_device *ubbd_dev = container_of(kref, struct ubbd_device, kref);

	ubbd_dev_destroy(ubbd_dev);
}

void ubbd_dev_put(struct ubbd_device *ubbd_dev)
{
	kref_put(&ubbd_dev->kref, &__dev_release);
}

static int __init ubbd_init(void)
{
	int rc;

	ubbd_wq = alloc_workqueue(UBBD_DRV_NAME, WQ_MEM_RECLAIM, 0);
	if (!ubbd_wq) {
		rc = -ENOMEM;
		goto err_out_slab;
	}

	ubbd_major = register_blkdev(0, UBBD_DRV_NAME);
	if (ubbd_major < 0) {
		rc = ubbd_major;
		goto err_out_wq;
	}

	rc = genl_register_family(&ubbd_genl_family);
	if (rc < 0) {
		goto err_out_blkdev;
	}

	ubbd_uio_root_device = root_device_register("ubbd_uio");
	if (IS_ERR(ubbd_uio_root_device)) {
		rc = PTR_ERR(ubbd_uio_root_device);
		goto err_out_genl;
	}

	return 0;
err_out_genl:
	genl_unregister_family(&ubbd_genl_family);
err_out_blkdev:
	unregister_blkdev(ubbd_major, UBBD_DRV_NAME);
err_out_wq:
err_out_slab:
	return rc;
}

static void __exit ubbd_exit(void)
{
	ida_destroy(&ubbd_dev_id_ida);
	genl_unregister_family(&ubbd_genl_family);
	root_device_unregister(ubbd_uio_root_device);
	unregister_blkdev(ubbd_major, UBBD_DRV_NAME);
	destroy_workqueue(ubbd_wq);
}

module_init(ubbd_init);
module_exit(ubbd_exit);

MODULE_AUTHOR("Dongsheng Yang <dongsheng.yang@easystack.com>");
MODULE_DESCRIPTION("Userspace Backend Block Device (UBBD) driver");
MODULE_LICENSE("GPL");
