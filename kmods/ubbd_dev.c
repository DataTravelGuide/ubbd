#include "ubbd_internal.h"
#include <linux/blkdev.h>

LIST_HEAD(ubbd_dev_list);    /* devices */
int ubbd_total_devs = 0;
DEFINE_MUTEX(ubbd_dev_list_mutex);

int ubbd_major;
struct workqueue_struct *ubbd_wq;
struct device *ubbd_uio_root_device;
DEFINE_IDA(ubbd_dev_id_ida);

void ubbd_dev_destroy(struct ubbd_device *ubbd_dev);
void ubbd_dev_get(struct ubbd_device *ubbd_dev)
{
	kref_get(&ubbd_dev->kref);
}

int ubbd_dev_get_unless_zero(struct ubbd_device *ubbd_dev)
{
	return kref_get_unless_zero(&ubbd_dev->kref);
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

static int ubbd_init_hctx(struct blk_mq_hw_ctx *hctx, void *driver_data,
			unsigned int hctx_idx)
{
	struct ubbd_device *ubbd_dev = driver_data;
	struct ubbd_queue *ubbd_q;

	ubbd_q = &ubbd_dev->queues[hctx_idx];
	ubbd_q->mq_hctx = hctx;
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

	if (ubbd_mgmt_need_fault()) {
		return -ENOMEM;
	}

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
	sb->magic = UBBD_MAGIC;
	sb->version = UBBD_SB_VERSION;
	sb->info_off = UBBD_INFO_OFF;
	sb->info_size = UBBD_INFO_SIZE;
	sb->cmdr_off = CMDR_OFF;
	sb->cmdr_size = CMDR_SIZE;
	sb->compr_off = COMPR_OFF;
	sb->compr_size = COMPR_SIZE;
	ubbd_dev_debug(ubbd_q->ubbd_dev, "info_off: %u, info_size: %u, cmdr_off: %u, cmdr_size: %u, \
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

	if (ubbd_q->data_bitmap) {
		ubbd_page_release(ubbd_q);
		xa_destroy(&ubbd_q->data_pages_array);
		bitmap_free(ubbd_q->data_bitmap);
	}
}

static int ubbd_queue_create(struct ubbd_queue *ubbd_q, u32 data_pages)
{
	int ret;

	ubbd_q->data_pages = data_pages;
	ubbd_q->data_pages_reserve_percnt = \
		ubbd_q->data_pages * UBBD_UIO_DATA_RESERVE_PERCENT / 100;

	if (ubbd_mgmt_need_fault())
		return -ENOMEM;

	xa_init(&ubbd_q->data_pages_array);

	ubbd_q->data_bitmap = bitmap_zalloc(ubbd_q->data_pages, GFP_KERNEL);
	if (!ubbd_q->data_bitmap) {
		return -ENOMEM;
	}

	ret = ubbd_queue_sb_init(ubbd_q);
	if (ret) {
		ubbd_dev_err(ubbd_q->ubbd_dev, "failed to init dev sb: %d.", ret);
		goto err;
	}

	ret = ubbd_queue_uio_init(ubbd_q);
	if (ret) {
		ubbd_dev_err(ubbd_q->ubbd_dev, "failed to init uio: %d.", ret);
		goto err;
	}

	mutex_init(&ubbd_q->req_lock);
	mutex_init(&ubbd_q->state_lock);
	INIT_LIST_HEAD(&ubbd_q->inflight_reqs);
	spin_lock_init(&ubbd_q->inflight_reqs_lock);
	ubbd_q->req_tid = 0;
	INIT_WORK(&ubbd_q->complete_work, complete_work_fn);
	cpumask_clear(&ubbd_q->cpumask);
	atomic_set(&ubbd_q->status, UBBD_QUEUE_KSTATUS_RUNNING);

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

	if (ubbd_mgmt_need_fault())
		goto err;

	ubbd_dev = kzalloc(sizeof(*ubbd_dev), GFP_KERNEL);
	if (!ubbd_dev)
		goto err;

	ubbd_dev->status = UBBD_DEV_KSTATUS_INIT;

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

	if (ubbd_mgmt_need_fault())
		goto fail_ubbd_dev;

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
	ubbd_debugfs_add_dev(ubbd_dev);

	ubbd_dev_debug(ubbd_dev, "dev is created.");

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
	ubbd_debugfs_remove_dev(ubbd_dev);
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
	if (ubbd_mgmt_need_fault()) {
		return -ENOMEM;
	}

        disk = alloc_disk(1 << UBBD_SINGLE_MAJOR_PART_SHIFT);
        if (!disk)
                return -ENOMEM;
 
        snprintf(disk->disk_name, sizeof(disk->disk_name), UBBD_DRV_NAME "%d",
                 ubbd_dev->dev_id);
	disk->major = ubbd_dev->major;
	disk->first_minor = ubbd_dev->minor;
	disk->minors = (1 << UBBD_SINGLE_MAJOR_PART_SHIFT);
#ifdef HAVE_EXT_DEVT
	disk->flags |= GENHD_FL_EXT_DEVT;
#endif
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

	if (ubbd_mgmt_need_fault()) {
		err = -ENOMEM;
		goto err_disk;
	}

	err = blk_mq_alloc_tag_set(&ubbd_dev->tag_set);
	if (err)
		goto err_disk;

	if (ubbd_mgmt_need_fault()) {
		err = -ENOMEM;
		goto out_tag_set;
	}

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

#ifdef HVAE_FLAG_DISCARD
	blk_queue_flag_clear(QUEUE_FLAG_DISCARD, q);
#endif
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

	if (ubbd_mgmt_need_fault()) {
		err = -ENOMEM;
		goto err;
	}

	err = blk_mq_alloc_tag_set(&ubbd_dev->tag_set);
	if (err)
		goto err;

	if (ubbd_mgmt_need_fault()) {
		err = -ENOMEM;
		goto out_tag_set;
	}
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
#ifdef HAVE_EXT_DEVT
	disk->flags |= GENHD_FL_EXT_DEVT;
#endif
	disk->fops = &ubbd_bd_ops;
	disk->private_data = ubbd_dev;
 
	blk_queue_flag_set(QUEUE_FLAG_NONROT, q);

	blk_queue_max_hw_sectors(q, 128);
	q->limits.max_sectors = queue_max_hw_sectors(q);
	blk_queue_max_segments(q, USHRT_MAX);
	blk_queue_max_segment_size(q, UINT_MAX);
	blk_queue_io_min(q, 4096);
	blk_queue_io_opt(q, 4096);

#ifdef HVAE_FLAG_DISCARD
	blk_queue_flag_clear(QUEUE_FLAG_DISCARD, q);
#endif
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

static void ubbd_add_disk_fn(struct work_struct *work)
{
	struct ubbd_device *ubbd_dev =
		container_of(work, struct ubbd_device, work);
	int ret;

	mutex_lock(&ubbd_dev->state_lock);
	if (ubbd_dev->status != UBBD_DEV_KSTATUS_PREPARED) {
		ret = -EINVAL;
		ubbd_dev_err(ubbd_dev, "add_disk_fn expected status is UBBD_DEV_KSTATUS_PREPARED, \
				but current status is: %d.", ubbd_dev->status);
		goto out;
	}

	ret = ubbd_add_disk(ubbd_dev);
	if (ret) {
		ubbd_dev_err(ubbd_dev, "failed to add disk.");
		goto out;
	}
	ubbd_dev->status = UBBD_DEV_KSTATUS_RUNNING;
out:
	mutex_unlock(&ubbd_dev->state_lock);
	ubbd_dev_put(ubbd_dev);
}

int ubbd_dev_add_disk(struct ubbd_device *ubbd_dev)
{
	int ret = 0;

	if (ubbd_dev->status != UBBD_DEV_KSTATUS_PREPARED) {
		ret = -EINVAL;
		ubbd_dev_err(ubbd_dev, "add_disk expected status is UBBD_DEV_KSTATUS_PREPARED, \
				but current status is: %d.", ubbd_dev->status);
		goto out;
	}

	ubbd_dev_get(ubbd_dev);
	INIT_WORK(&ubbd_dev->work, ubbd_add_disk_fn);
	queue_work(ubbd_wq, &ubbd_dev->work);

out:
	return ret;
}

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
#ifdef HVAE_FLAG_DISCARD
		blk_queue_flag_set(QUEUE_FLAG_DISCARD, ubbd_dev->disk->queue);
#endif
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

	if (ubbd_mgmt_need_fault()) {
		ret = -ENOMEM;
		goto err_dev_put;
	}

	ret = ubbd_dev_device_setup(ubbd_dev, add_opts->device_size, add_opts->dev_features);
	if (ret) {
		ret = -EINVAL;
		goto err_dev_put;
	}

	ubbd_dev->status = UBBD_DEV_KSTATUS_PREPARED;

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

int ubbd_dev_remove_dev(struct ubbd_device *ubbd_dev)
{
	int ret = 0;

	mutex_lock(&ubbd_dev->state_lock);
	if (ubbd_dev->status != UBBD_DEV_KSTATUS_REMOVING &&
			ubbd_dev->status != UBBD_DEV_KSTATUS_PREPARED) {
		ubbd_dev_err(ubbd_dev, "remove dev is not allowed in current status: %d.",
				ubbd_dev->status);
		ret = -EINVAL;
		mutex_unlock(&ubbd_dev->state_lock);
		goto out;
	}

	mutex_lock(&ubbd_dev_list_mutex);
	ubbd_total_devs--;
	list_del_init(&ubbd_dev->dev_node);
	mutex_unlock(&ubbd_dev_list_mutex);

	ubbd_free_disk(ubbd_dev);
	mutex_unlock(&ubbd_dev->state_lock);
	ubbd_dev_put(ubbd_dev);
out:
	return ret;
}

int ubbd_dev_config(struct ubbd_device *ubbd_dev, struct ubbd_dev_config_opts *opts)
{
	int ret = 0;

	mutex_lock(&ubbd_dev->state_lock);
	if (ubbd_dev->status != UBBD_DEV_KSTATUS_RUNNING) {
		ubbd_dev_err(ubbd_dev, "config cmd expected ubbd dev status is running, \
				but current status is: %d.", ubbd_dev->status);
		ret = -EINVAL;
		goto out;
	}

	if (opts->flags & UBBD_DEV_CONFIG_FLAG_DP_RESERVE) {
		int i;

		if (opts->config_dp_reserve > 100) {
			ret = -EINVAL;
			ubbd_dev_err(ubbd_dev, "config_dp_reserve is not valide: %u", opts->config_dp_reserve);
			goto out;
		}

		for (i = 0; i < ubbd_dev->num_queues; i++) {
			ubbd_dev->queues[i].data_pages_reserve_percnt = opts->config_dp_reserve * ubbd_dev->queues[i].data_pages / 100;
		}
	}

out:
	mutex_unlock(&ubbd_dev->state_lock);
	return ret;
}

static struct ubbd_queue *find_running_queue(struct ubbd_device *ubbd_dev)
{
	int i;
	struct ubbd_queue *ubbd_q = NULL;

	for (i = 0; i < ubbd_dev->num_queues; i++) {
		if (atomic_read(&ubbd_dev->queues[i].status) == UBBD_QUEUE_KSTATUS_RUNNING) {
			ubbd_q = &ubbd_dev->queues[i];
			break;
		}
	}

	return ubbd_q;
}

static int queue_stop(struct ubbd_device *ubbd_dev, struct ubbd_queue *ubbd_q)
{
	struct blk_mq_hw_ctx *hctx;
	struct ubbd_queue *running_q;
	int status;
	int ret = 0;

	mutex_lock(&ubbd_q->state_lock);
	status = atomic_read(&ubbd_q->status);
	if (status == UBBD_QUEUE_KSTATUS_STOPPING ||
			status == UBBD_QUEUE_KSTATUS_STOPPED)
		goto out;

	if (status != UBBD_QUEUE_KSTATUS_RUNNING) {
		ubbd_queue_err(ubbd_q, "stop queue expected status running, but \
				current status is %d.", status);
		ret = -EINVAL;
		goto out;
	}

	hctx = ubbd_q->mq_hctx;	
	if (hctx) {
		running_q = find_running_queue(ubbd_dev);
		if (running_q)
			hctx->driver_data = running_q;
	}

	atomic_set(&ubbd_q->status, UBBD_QUEUE_KSTATUS_STOPPING);
	flush_workqueue(ubbd_dev->task_wq);

	mutex_lock(&ubbd_q->req_lock);
	if (list_empty(&ubbd_q->inflight_reqs)) {
		atomic_set(&ubbd_q->status, UBBD_QUEUE_KSTATUS_STOPPED);
	}
	mutex_unlock(&ubbd_q->req_lock);

out:
	mutex_unlock(&ubbd_q->state_lock);
	return ret;
}

int ubbd_dev_stop_queue(struct ubbd_device *ubbd_dev, int queue_id)
{
	int ret = 0;
	struct ubbd_queue *ubbd_q;

	mutex_lock(&ubbd_dev->state_lock);
	if (ubbd_dev->status != UBBD_DEV_KSTATUS_RUNNING) {
		ubbd_dev_err(ubbd_dev, "stop_queue cmd expected ubbd dev status is running, \
				but current status is: %d.", ubbd_dev->status);
		ret = -EINVAL;
		goto out;
	}

	if (queue_id >= ubbd_dev->num_queues) {
		ubbd_dev_err(ubbd_dev, "invalid queue_id: %d.", queue_id);
		ret = -EINVAL;
		goto out;
	}

	ubbd_q = &ubbd_dev->queues[queue_id];

	ret = queue_stop(ubbd_dev, ubbd_q);
out:
	mutex_unlock(&ubbd_dev->state_lock);
	return ret;
}

static int queue_start(struct ubbd_queue *ubbd_q)
{
	int ret= 0;
	int status;

	mutex_lock(&ubbd_q->state_lock);
	status = atomic_read(&ubbd_q->status);
	if (status == UBBD_QUEUE_KSTATUS_RUNNING)
		goto out;

	if (status == UBBD_QUEUE_KSTATUS_REMOVING) {
		ubbd_queue_err(ubbd_q, "cant start queue in removing status.");
		ret = -EINVAL;
		goto out;
	}

	atomic_set(&ubbd_q->status, UBBD_QUEUE_KSTATUS_RUNNING);

	if (ubbd_q->mq_hctx && ubbd_q->mq_hctx->driver_data != ubbd_q) {
		ubbd_q->mq_hctx->driver_data = ubbd_q;
	}
out:
	mutex_unlock(&ubbd_q->state_lock);
	return ret;
}

int ubbd_dev_start_queue(struct ubbd_device *ubbd_dev, int queue_id)
{
	int ret = 0;
	struct ubbd_queue *ubbd_q;

	mutex_lock(&ubbd_dev->state_lock);
	if (ubbd_dev->status != UBBD_DEV_KSTATUS_RUNNING) {
		ubbd_dev_err(ubbd_dev, "start_queue cmd expected ubbd dev status is running, \
				but current status is: %d.", ubbd_dev->status);
		ret = -EINVAL;
		goto out;
	}

	if (queue_id >= ubbd_dev->num_queues) {
		ubbd_dev_err(ubbd_dev, "invalid queue_id: %d.", queue_id);
		ret = -EINVAL;
		goto out;
	}

	ubbd_q = &ubbd_dev->queues[queue_id];

	ret = queue_start(ubbd_q);
out:
	mutex_unlock(&ubbd_dev->state_lock);
	return ret;
}

static void ubbd_dev_remove_queues(struct ubbd_device *ubbd_dev, bool force)
{
	int i;

	for (i = 0; i < ubbd_dev->num_queues; i++) {
		struct ubbd_queue *ubbd_q;

		ubbd_q = &ubbd_dev->queues[i];
		mutex_lock(&ubbd_q->state_lock);
		atomic_set(&ubbd_q->status, UBBD_QUEUE_KSTATUS_REMOVING);
		mutex_unlock(&ubbd_q->state_lock);
		/*
		 * flush the task_wq, to avoid race with complete_work.
		 *
		 * after the flush_workqueue, all other work will return
		 * directly as UBBD_QUEUE_KSTATUS_REMOVING is already set.
		 * Then we can end the inflight requests safely.
		 * */
		flush_workqueue(ubbd_dev->task_wq);
		if (force) {
			ubbd_queue_end_inflight_reqs(ubbd_q, -EIO);
		}
	}
}

void ubbd_dev_remove_disk(struct ubbd_device *ubbd_dev, bool force)
{
	bool disk_is_running;

	mutex_lock(&ubbd_dev->state_lock);
	ubbd_dev_debug(ubbd_dev, "remove disk status is: %d, force: %d", ubbd_dev->status, force);
	disk_is_running = (ubbd_dev->status == UBBD_DEV_KSTATUS_RUNNING);
	ubbd_dev->status = UBBD_DEV_KSTATUS_REMOVING;
	mutex_unlock(&ubbd_dev->state_lock);

	ubbd_dev_remove_queues(ubbd_dev, force);

	if (disk_is_running) {
		del_gendisk(ubbd_dev->disk);
	}
}
