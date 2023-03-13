#define _GNU_SOURCE
#include "ubbd_uio.h"
#include "ubbd_dev.h"

#define MEM_DEV(ubbd_dev) ((struct ubbd_mem_device *)container_of(ubbd_dev, struct ubbd_mem_device, ubbd_dev))

struct ubbd_dev_ops mem_dev_ops;

static struct ubbd_device *mem_dev_create(struct __ubbd_dev_info *info)
{
	struct ubbd_mem_device *mem_dev;
	struct ubbd_device *ubbd_dev;

	mem_dev = calloc(1, sizeof(*mem_dev));
	if (!mem_dev)
		return NULL;

	ubbd_dev = &mem_dev->ubbd_dev;
	ubbd_dev->dev_type = UBBD_DEV_TYPE_MEM;
	ubbd_dev->dev_ops = &mem_dev_ops;

	return ubbd_dev;
}

static int mem_dev_init(struct ubbd_device *ubbd_dev, bool reopen)
{
	if (ubbd_dev->dev_size > ((uint64_t)UBBD_MEM_BLK_SIZE * UBBD_MEM_BLK_COUNT)) {
		ubbd_err("dev size for mem type is too large: %lu (max %lu)\n",
				ubbd_dev->dev_size, ((uint64_t)UBBD_MEM_BLK_SIZE * UBBD_MEM_BLK_COUNT));
		return -E2BIG;
	}

	ubbd_dev->dev_features.write_cache = false;
	ubbd_dev->dev_features.fua = false;
	ubbd_dev->dev_features.discard = false;
	ubbd_dev->dev_features.write_zeros = false;

	return 0;
}

static void mem_dev_release(struct ubbd_device *ubbd_dev)
{
	struct ubbd_mem_device *mem_dev = MEM_DEV(ubbd_dev);

	free(mem_dev);
}

struct ubbd_dev_ops mem_dev_ops = {
	.create = mem_dev_create,
	.init = mem_dev_init,
	.release = mem_dev_release,
};
