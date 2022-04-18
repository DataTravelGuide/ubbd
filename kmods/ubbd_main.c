/*
 * Userspace Backend Block Device
 */

#include "ubbd_internal.h"

LIST_HEAD(ubbd_dev_list);    /* devices */
int ubbd_total_devs = 0;
DEFINE_MUTEX(ubbd_dev_list_mutex);

struct workqueue_struct *ubbd_wq;
static int ubbd_major;
static DEFINE_IDA(ubbd_dev_id_ida);
struct device *ubbd_uio_root_device;

static const struct blk_mq_ops ubbd_mq_ops = {
	.queue_rq	= ubbd_queue_rq,
	.timeout	= ubbd_timeout,
};

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

	ubbd_dev->data_pages = data_pages;
	ubbd_dev->data_pages_reserve = \
		ubbd_dev->data_pages * UBBD_UIO_DATA_RESERVE_PERCENT / 100;

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault())
		goto err_free_dev;
#endif
	ubbd_dev->data_bitmap = bitmap_zalloc(ubbd_dev->data_pages, GFP_KERNEL);
	if (!ubbd_dev->data_bitmap) {
		goto err_free_dev;
	}

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault())
		goto err_bitmap_free;
#endif
	ubbd_dev->task_wq = alloc_workqueue("ubbd-tasks", WQ_MEM_RECLAIM, 0);
	if (!ubbd_dev->task_wq) {
		goto err_bitmap_free;
	}

	INIT_WORK(&ubbd_dev->complete_work, complete_work_fn);
	ubbd_dev->status = UBBD_DEV_STATUS_INIT;
	xa_init(&ubbd_dev->data_pages_array);

	spin_lock_init(&ubbd_dev->lock);
	mutex_init(&ubbd_dev->req_lock);
	INIT_LIST_HEAD(&ubbd_dev->dev_node);
	INIT_LIST_HEAD(&ubbd_dev->inflight_reqs);
	spin_lock_init(&ubbd_dev->inflight_reqs_lock);
	ubbd_dev->req_tid = 0;

	kref_init(&ubbd_dev->kref);

	return ubbd_dev;

err_bitmap_free:
	bitmap_free(ubbd_dev->data_bitmap);
err_free_dev:
	kfree(ubbd_dev);
err:
	return NULL;
}

static void __ubbd_dev_free(struct ubbd_device *ubbd_dev)
{
	destroy_workqueue(ubbd_dev->task_wq);
	bitmap_free(ubbd_dev->data_bitmap);
	kfree(ubbd_dev);
}

static void ubbd_page_release(struct ubbd_device *ubbd_dev)
{
	XA_STATE(xas, &ubbd_dev->data_pages_array, 0);
	struct page *page;

	xas_lock(&xas);
	xas_for_each(&xas, page, ubbd_dev->data_pages) {
		xas_store(&xas, NULL);
		__free_page(page);
	}
	xas_unlock(&xas);
}

struct ubbd_device *ubbd_dev_create(u32 data_pages)
{
	struct ubbd_device *ubbd_dev;

	ubbd_dev = __ubbd_dev_create(data_pages);
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

	__module_get(THIS_MODULE);

	pr_debug("%s ubbd_dev %p dev_id %d\n", __func__, ubbd_dev, ubbd_dev->dev_id);
	return ubbd_dev;

fail_ubbd_dev:
	__ubbd_dev_free(ubbd_dev);
	return NULL;
}

void ubbd_dev_destroy(struct ubbd_device *ubbd_dev)
{
	ubbd_page_release(ubbd_dev);
	xa_destroy(&ubbd_dev->data_pages_array);
	ida_simple_remove(&ubbd_dev_id_ida, ubbd_dev->dev_id);
	__ubbd_dev_free(ubbd_dev);
	module_put(THIS_MODULE);
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
	ubbd_dev->tag_set.nr_hw_queues = num_present_cpus();
	ubbd_dev->tag_set.cmd_size = sizeof(struct ubbd_request);
	ubbd_dev->tag_set.timeout = UINT_MAX;

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
	ubbd_dev->tag_set.nr_hw_queues = num_present_cpus();
	ubbd_dev->tag_set.cmd_size = sizeof(struct ubbd_request);
	ubbd_dev->tag_set.timeout = UINT_MAX;

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


int ubbd_dev_sb_init(struct ubbd_device *ubbd_dev)
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

	ubbd_dev->sb_addr = sb;
	ubbd_dev->cmdr = (void *)sb + CMDR_OFF;
	ubbd_dev->compr = (void *)sb + COMPR_OFF;
	ubbd_dev->data_off = RING_SIZE;
	ubbd_dev->mmap_pages = (ubbd_dev->data_pages + (RING_SIZE >> PAGE_SHIFT));

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
			ubbd_dev->data_off);

	return 0;
}

void ubbd_dev_sb_destroy(struct ubbd_device *ubbd_dev)
{
	vfree(ubbd_dev->sb_addr);
}

struct ubbd_device *ubbd_dev_add_dev(struct ubbd_dev_add_opts *add_opts)
{
	int ret;
	struct ubbd_device *ubbd_dev;

	ubbd_dev = ubbd_dev_create(add_opts->data_pages);
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
	ret = ubbd_dev_sb_init(ubbd_dev);
	if (ret) {
		pr_err("failed to init dev sb: %d.", ret);
		goto err_dev_put;
	}

	ret = ubbd_dev_uio_init(ubbd_dev);
	if (ret) {
		pr_debug("failed to init uio: %d.", ret);
		goto err_dev_put;
	}

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

void ubbd_dev_get(struct ubbd_device *ubbd_dev)
{
	kref_get(&ubbd_dev->kref);
}

static void __dev_release(struct kref *kref)
{
	struct ubbd_device *ubbd_dev = container_of(kref, struct ubbd_device, kref);

	ubbd_dev_uio_destroy(ubbd_dev);
	ubbd_dev_sb_destroy(ubbd_dev);
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
