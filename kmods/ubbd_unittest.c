
#include <linux/module.h>
#include "ktf.h"

KTF_INIT();

TEST(simple, t1)
{
	EXPECT_TRUE(true);
}

static void add_tests(void)
{
	ADD_TEST(t1);
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
