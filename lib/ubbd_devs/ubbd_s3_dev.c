#define _GNU_SOURCE
#include "ubbd_uio.h"
#include "ubbd_dev.h"

#define S3_DEV(ubbd_dev) ((struct ubbd_s3_device *)container_of(ubbd_dev, struct ubbd_s3_device, ubbd_dev))

static int s3_dev_init(struct ubbd_device *ubbd_dev)
{
	ubbd_dev->dev_features.write_cache = false;
	ubbd_dev->dev_features.fua = false;
	ubbd_dev->dev_features.discard = false;
	ubbd_dev->dev_features.write_zeros = false;

	return 0;
}

static void s3_dev_release(struct ubbd_device *ubbd_dev)
{
	struct ubbd_s3_device *s3_dev = S3_DEV(ubbd_dev);

	free(s3_dev);
}

struct ubbd_dev_ops s3_dev_ops = {
	.init = s3_dev_init,
	.release = s3_dev_release,
};
