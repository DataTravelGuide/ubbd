
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

static void add_tests(void)
{
	ADD_TEST(test_get_submit_entry);
}

static int __init ubbd_kmod_unittest_init(void)
{
	add_tests();
	return 0;
}
static void __exit ubbd_kmod_unittest_exit(void)
{
	KTF_CLEANUP();
}

module_init(ubbd_kmod_unittest_init);
module_exit(ubbd_kmod_unittest_exit);

MODULE_AUTHOR("Dongsheng Yang <dongsheng.yang@easystack.com>");
MODULE_DESCRIPTION("Unittest for UBBD");
MODULE_LICENSE("GPL");
