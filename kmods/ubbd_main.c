/*
 * Userspace Backend Block Device
 */

#include "ubbd_internal.h"

extern int ubbd_major;
extern struct workqueue_struct *ubbd_wq;
extern struct ida ubbd_dev_id_ida;
extern struct device *ubbd_uio_root_device;

static int __init ubbd_init(void)
{
	int rc;

	ubbd_wq = alloc_workqueue(UBBD_DRV_NAME, WQ_MEM_RECLAIM, 0);
	if (!ubbd_wq) {
		rc = -ENOMEM;
		goto err;
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

	ubbd_debugfs_init();

	return 0;
err_out_genl:
	genl_unregister_family(&ubbd_genl_family);
err_out_blkdev:
	unregister_blkdev(ubbd_major, UBBD_DRV_NAME);
err_out_wq:
	destroy_workqueue(ubbd_wq);
err:
	return rc;
}

static void __exit ubbd_exit(void)
{
	ubbd_debugfs_cleanup();
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
