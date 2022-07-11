
#include <linux/module.h>
#include "ktf.h"
#include "ubbd_internal.h"

KTF_INIT();

struct ubbd_device ubbd_dev = { 0 };
struct ubbd_queue ubbd_q = { 0 };
struct ubbd_sb sb = { 0 };

extern struct ubbd_se *get_submit_entry(struct ubbd_queue *ubbd_q);
TEST(ubbd_req, test_get_submit_entry)
{
	struct ubbd_se *se;

	// empty submittion queue
	ubbd_dev.dev_id = 0;
	sb.cmd_head = sb.cmd_tail = 0;
	ubbd_q.ubbd_dev = &ubbd_dev;
	ubbd_q.sb_addr = &sb;
	ubbd_q.cmdr = (void *)1024;

	se = get_submit_entry(&ubbd_q);
	EXPECT_ADDR_EQ(se, 1024);

	// one entry
	sb.cmd_head = CMDR_RESERVED;
	se = get_submit_entry(&ubbd_q);
	EXPECT_ADDR_EQ(se, 1024 + CMDR_RESERVED);
}

KTF_OVERRIDE(ubbd_add_disk, mock_ubbd_add_disk)
{
	KTF_SET_RETURN_VALUE(0);
	KTF_OVERRIDE_RETURN;
}

KTF_OVERRIDE(ubbd_free_disk, mock_ubbd_free_disk)
{
	KTF_SET_RETURN_VALUE(0);
	KTF_OVERRIDE_RETURN;
}

KTF_OVERRIDE(del_gendisk, mock_del_gendisk)
{
	KTF_SET_RETURN_VALUE(0);
	KTF_OVERRIDE_RETURN;
}

static int wait_for_ubbd_dev_running(struct ubbd_device *ubbd_dev)
{
	int i;

	for (i = 0; i < 1000; i++) {
		if (ubbd_dev->status == UBBD_DEV_KSTATUS_RUNNING) {
			return 0;
		}
		msleep(100);
	}

	return -1;
}


TEST(ubbd_dev, test_ubbd_dev_lifecycle)
{
	struct ubbd_dev_add_opts add_opts = { 0 };
	struct ubbd_dev_config_opts config_opts = { 0 };
	struct ubbd_device *ubbd_dev;

	KTF_REGISTER_OVERRIDE(ubbd_add_disk, mock_ubbd_add_disk);
	KTF_REGISTER_OVERRIDE(ubbd_free_disk, mock_ubbd_free_disk);
	KTF_REGISTER_OVERRIDE(del_gendisk, mock_del_gendisk);

	add_opts.device_size = 1;
	add_opts.num_queues = 1;
	add_opts.data_pages = UBBD_UIO_DATA_PAGES;
	add_opts.dev_features = 0;

	/* Case 1: add_dev and remove_dev */
	/* 1.1. ubbd_dev_add_dev */
	ubbd_dev = ubbd_dev_add_dev(&add_opts);
	if (IS_ERR_OR_NULL(ubbd_dev)) {
		EXPECT_FALSE("failed to add dev.");
		goto out;
	}

	/* 1.2. PREPARED status, config stop|start_queue are not allowed */
	EXPECT_INT_EQ(-EINVAL, ubbd_dev_config(ubbd_dev, &config_opts));
	EXPECT_INT_EQ(-EINVAL, ubbd_dev_stop_queue(ubbd_dev, 0));
	EXPECT_INT_EQ(-EINVAL, ubbd_dev_start_queue(ubbd_dev, 0));

	/* 1.3. PREPARED status, remove_disk will into REMOVING */
	ubbd_dev_remove_disk(ubbd_dev, false);
	EXPECT_INT_EQ(UBBD_DEV_KSTATUS_REMOVING, ubbd_dev->status);

	EXPECT_INT_EQ(-EINVAL, ubbd_dev_add_disk(ubbd_dev));
	EXPECT_INT_EQ(-EINVAL, ubbd_dev_config(ubbd_dev, &config_opts));
	EXPECT_INT_EQ(-EINVAL, ubbd_dev_stop_queue(ubbd_dev, 0));
	EXPECT_INT_EQ(-EINVAL, ubbd_dev_start_queue(ubbd_dev, 0));

	/* 1.4. REMOVING status, remove_dev will destroy ubbd_dev */
	EXPECT_INT_EQ(0, ubbd_dev_remove_dev(ubbd_dev));



	/* Case 2: add_dev, add_disk, remove_disk, remove_dev */
	/* 2.1 ubbd_dev_add_dev into PREPARED */
	ubbd_dev = ubbd_dev_add_dev(&add_opts);
	if (IS_ERR_OR_NULL(ubbd_dev)) {
		EXPECT_FALSE("failed to add dev.");
		goto out;
	}
	/* 2.2 PREPARED status, add_disk into RUNNING */
	EXPECT_INT_EQ(0, ubbd_dev_add_disk(ubbd_dev));
	EXPECT_INT_EQ(0, wait_for_ubbd_dev_running(ubbd_dev));

	/* 2.4 RUNNING status, stop queue and start queue */
	EXPECT_INT_EQ(UBBD_QUEUE_KSTATUS_RUNNING, atomic_read(&ubbd_dev->queues[0].status));
	EXPECT_INT_EQ(0, ubbd_dev_stop_queue(ubbd_dev, 0));
	EXPECT_INT_EQ(UBBD_QUEUE_KSTATUS_STOPPED, atomic_read(&ubbd_dev->queues[0].status));
	EXPECT_INT_EQ(0, ubbd_dev_stop_queue(ubbd_dev, 0));
	EXPECT_INT_EQ(UBBD_QUEUE_KSTATUS_STOPPED, atomic_read(&ubbd_dev->queues[0].status));

	EXPECT_INT_EQ(0, ubbd_dev_start_queue(ubbd_dev, 0));
	EXPECT_INT_EQ(UBBD_QUEUE_KSTATUS_RUNNING, atomic_read(&ubbd_dev->queues[0].status));
	EXPECT_INT_EQ(0, ubbd_dev_start_queue(ubbd_dev, 0));

	/* 2.3 RUNNING status, remove disk into REMOVING */
	ubbd_dev_remove_disk(ubbd_dev, false);
	EXPECT_INT_EQ(UBBD_DEV_KSTATUS_REMOVING, ubbd_dev->status);

	/* 2.4 REMOVING status, remove dev to destroy ubbd_dev */
	EXPECT_INT_EQ(0, ubbd_dev_remove_dev(ubbd_dev));



	/* Case 3: add_dev, remove_disk, remove_dev */
	/* 3.1 ubbd_dev_add_dev into PREPARED */
	ubbd_dev = ubbd_dev_add_dev(&add_opts);
	if (IS_ERR_OR_NULL(ubbd_dev)) {
		EXPECT_FALSE("failed to add dev.");
		goto out;
	}
	/* 3.2 PREPARED status, remove_disk into REMOVING */
	ubbd_dev_remove_disk(ubbd_dev, false);
	EXPECT_INT_EQ(UBBD_DEV_KSTATUS_REMOVING, ubbd_dev->status);

	/* 3.3 REMOVING status, remove dev to destroy ubbd_dev */
	EXPECT_INT_EQ(0, ubbd_dev_remove_dev(ubbd_dev));



out:
	KTF_UNREGISTER_OVERRIDE(ubbd_add_disk, mock_ubbd_add_disk);
	KTF_UNREGISTER_OVERRIDE(ubbd_free_disk, mock_ubbd_free_disk);
	KTF_UNREGISTER_OVERRIDE(del_gendisk, mock_del_gendisk);

	return;
}

static void add_tests(void)
{
	ADD_TEST(test_get_submit_entry);
	ADD_TEST(test_ubbd_dev_lifecycle);
}

int __init ubbd_init(void);
void __exit ubbd_exit(void);
static int __init ubbd_kmod_unittest_init(void)
{
	int ret;

	ret = __ubbd_init();
	if (ret) {
		pr_err("ubbd_init failed.");
		return 0;
	}
	add_tests();
	return 0;
}
static void __exit ubbd_kmod_unittest_exit(void)
{
	__ubbd_exit();
	KTF_CLEANUP();
}

module_init(ubbd_kmod_unittest_init);
module_exit(ubbd_kmod_unittest_exit);

MODULE_AUTHOR("Dongsheng Yang <dongsheng.yang.linux@gmail.com>");
MODULE_DESCRIPTION("Unittest for UBBD");
MODULE_LICENSE("GPL");
