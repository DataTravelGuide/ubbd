#include "ubbd_dev.h"
#include "ubbd_uio.h"

// cache ops

static int cache_dev_init(struct ubbd_device *ubbd_dev, bool reopen)
{
	struct ubbd_cache_device *cache_dev = CACHE_DEV(ubbd_dev);
	int ret;

	ret = ubbd_dev_init(cache_dev->backing_device, reopen);
	if (ret)
		return ret;

	ret = ubbd_dev_init(cache_dev->cache_device, reopen);
	if (ret)
		return ret;

	ubbd_dev->dev_size = cache_dev->backing_device->dev_size;

	ubbd_dev->dev_features.write_cache = false;
	ubbd_dev->dev_features.fua = false;
	ubbd_dev->dev_features.discard = false;
	ubbd_dev->dev_features.write_zeros = false;

	return 0;
}

static void cache_dev_release(struct ubbd_device *ubbd_dev)
{
	struct ubbd_cache_device *cache_dev = CACHE_DEV(ubbd_dev);

	free(cache_dev);
}

struct ubbd_dev_ops cache_dev_ops = {
	.init = cache_dev_init,
	.release = cache_dev_release,
};


