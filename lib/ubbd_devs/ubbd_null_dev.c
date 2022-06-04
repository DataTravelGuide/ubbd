#define _GNU_SOURCE
#include "ubbd_uio.h"
#include "ubbd_dev.h"

#define NULL_DEV(ubbd_dev) ((struct ubbd_null_device *)container_of(ubbd_dev, struct ubbd_null_device, ubbd_dev))

static int null_dev_init(struct ubbd_device *ubbd_dev)
{
	ubbd_dev->dev_features.write_cache = false;
	ubbd_dev->dev_features.fua = false;
	ubbd_dev->dev_features.discard = false;
	ubbd_dev->dev_features.write_zeros = false;

	return 0;
}

static void null_dev_release(struct ubbd_device *ubbd_dev)
{
	struct ubbd_null_device *null_dev = NULL_DEV(ubbd_dev);

	free(null_dev);
}

struct ubbd_dev_ops null_dev_ops = {
	.init = null_dev_init,
	.release = null_dev_release,
};
