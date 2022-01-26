#include <linux/blk-mq.h>

int main(void)
{
	struct blk_mq_tag_set tag_set;

	blk_mq_alloc_disk(&tag_set, NULL);
	return 0;
}
