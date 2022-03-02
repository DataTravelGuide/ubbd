/*
 * Userspace Backend Block Device
 */

#include "ubbd_internal.h"

struct workqueue_struct *ubbd_wq;
atomic_t ubbd_inflight;
static int ubbd_major;
static DEFINE_IDA(ubbd_dev_id_ida);
struct device *ubbd_uio_root_device;

static const struct blk_mq_ops ubbd_mq_ops = {
	.queue_rq	= ubbd_queue_rq,
};

/* ubbd_dev lifecycle */
static struct ubbd_device *__ubbd_dev_create(u32 data_pages)
{
	struct ubbd_device *ubbd_dev;

	ubbd_dev = kzalloc(sizeof(*ubbd_dev), GFP_KERNEL);
	if (!ubbd_dev)
		return NULL;

	ubbd_dev->data_pages = data_pages;
	ubbd_dev->data_bitmap = bitmap_zalloc(ubbd_dev->data_pages, GFP_KERNEL);
	if (!ubbd_dev->data_bitmap) {
		kfree(ubbd_dev);
		return NULL;
	}

	ubbd_dev->task_wq = alloc_workqueue("ubbd-tasks", WQ_MEM_RECLAIM, 0);
	if (!ubbd_dev->task_wq) {
		bitmap_free(ubbd_dev->data_bitmap);
		kfree(ubbd_dev);
		return NULL;
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

static int ubbd_init_disk(struct ubbd_device *ubbd_dev)
{
	struct gendisk *disk;
	struct request_queue *q;
	int err;

        /* create gendisk info */
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

	err = blk_mq_alloc_tag_set(&ubbd_dev->tag_set);
	if (err)
		goto err_disk;

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

int ubbd_dev_device_setup(struct ubbd_device *ubbd_dev, u64 device_size)
{
	int ret;

	ubbd_dev->major = ubbd_major;
	ubbd_dev->minor = ubbd_dev_id_to_minor(ubbd_dev->dev_id);

	ret = ubbd_init_disk(ubbd_dev);
	if (ret)
		goto err_out_blkdev;

	set_capacity(ubbd_dev->disk, device_size / SECTOR_SIZE);
	set_disk_ro(ubbd_dev->disk, 0);

	return 0;
err_out_blkdev:
	return ret;
}


int ubbd_dev_sb_init(struct ubbd_device *ubbd_dev)
{
	struct ubbd_sb *sb;

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


static int __init ubbd_init(void)
{
	int rc;

	atomic_set(&ubbd_inflight, 0);
	
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
