#define _GNU_SOURCE
#include "ubbd_uio.h"
#include "ubbd_dev.h"

#define FILE_DEV(ubbd_dev) ((struct ubbd_file_device *)container_of(ubbd_dev, struct ubbd_file_device, ubbd_dev))

static int file_dev_init(struct ubbd_device *ubbd_dev)
{
	ubbd_dev->dev_features.write_cache = false;
	ubbd_dev->dev_features.fua = false;
	ubbd_dev->dev_features.discard = false;
	ubbd_dev->dev_features.write_zeros = false;

	return 0;
}

static void file_dev_release(struct ubbd_device *ubbd_dev)
{
	struct ubbd_file_device *file_dev = FILE_DEV(ubbd_dev);

	free(file_dev);
}

struct ubbd_dev_ops file_dev_ops = {
	.init = file_dev_init,
	.release = file_dev_release,
};
