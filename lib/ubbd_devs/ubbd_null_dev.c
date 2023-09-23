#define _GNU_SOURCE
#include "ubbd_kring.h"
#include "ubbd_dev.h"

#define NULL_DEV(ubbd_dev) ((struct ubbd_null_device *)container_of(ubbd_dev, struct ubbd_null_device, ubbd_dev))

struct ubbd_dev_ops null_dev_ops;

static struct ubbd_device *null_dev_create(struct __ubbd_dev_info *info)
{
	struct ubbd_null_device *null_dev;
	struct ubbd_device *ubbd_dev;

	null_dev = calloc(1, sizeof(*null_dev));
	if (!null_dev)
		return NULL;

	ubbd_dev = &null_dev->ubbd_dev;
	ubbd_dev->dev_type = UBBD_DEV_TYPE_NULL;
	ubbd_dev->dev_ops = &null_dev_ops;

	return ubbd_dev;
}

static int null_dev_init(struct ubbd_device *ubbd_dev, bool reopen)
{
	ubbd_dev->dev_features.write_cache = false;
	ubbd_dev->dev_features.fua = false;
	ubbd_dev->dev_features.discard = false;
	ubbd_dev->dev_features.write_zeros = false;

	ubbd_dev->dev_features.queue_restart = true;

	return 0;
}

static void null_dev_release(struct ubbd_device *ubbd_dev)
{
	struct ubbd_null_device *null_dev = NULL_DEV(ubbd_dev);

	free(null_dev);
}

struct ubbd_dev_ops null_dev_ops = {
	.create = null_dev_create,
	.init = null_dev_init,
	.release = null_dev_release,
};
