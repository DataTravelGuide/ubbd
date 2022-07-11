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
	return __ubbd_init();
}

static void __exit ubbd_exit(void)
{
	__ubbd_exit();
}

module_init(ubbd_init);
module_exit(ubbd_exit);

MODULE_AUTHOR("Dongsheng Yang <dongsheng.yang.linux@gmail.com>");
MODULE_DESCRIPTION("Userspace Backend Block Device (UBBD) driver");
MODULE_LICENSE("GPL");
