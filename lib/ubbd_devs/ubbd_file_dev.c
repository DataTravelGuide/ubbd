#define _GNU_SOURCE
#include "ubbd_uio.h"
#include "ubbd_dev.h"

#define FILE_DEV(ubbd_dev) ((struct ubbd_file_device *)container_of(ubbd_dev, struct ubbd_file_device, ubbd_dev))

struct ubbd_dev_ops file_dev_ops;

static struct ubbd_device *file_dev_create(struct ubbd_dev_info *info)
{
	struct ubbd_file_device *file_dev;
	struct ubbd_device *ubbd_dev;

	file_dev = calloc(1, sizeof(*file_dev));
	if (!file_dev)
		return NULL;

	ubbd_dev = &file_dev->ubbd_dev;
	ubbd_dev->dev_type = UBBD_DEV_TYPE_FILE;
	ubbd_dev->dev_ops = &file_dev_ops;
	strcpy(file_dev->filepath, info->generic_dev.info.file.path);
	ubbd_dev->dev_size = info->generic_dev.info.file.size;

	return ubbd_dev;
}

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
	.create = file_dev_create,
	.init = file_dev_init,
	.release = file_dev_release,
};
