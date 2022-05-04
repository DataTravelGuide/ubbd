#define _GNU_SOURCE
#include "ubbd_uio.h"
#include "ubbd_dev.h"

#define NULL_DEV(ubbd_dev) ((struct ubbd_null_device *)container_of(ubbd_dev, struct ubbd_null_device, ubbd_dev))

static int null_dev_open(struct ubbd_device *ubbd_dev)
{
	ubbd_dev->dev_features.write_cache = false;
	ubbd_dev->dev_features.fua = false;
	ubbd_dev->dev_features.discard = false;
	ubbd_dev->dev_features.write_zeros = false;

	return 0;
}

static void null_dev_close(struct ubbd_device *ubbd_dev)
{
	return;
}

static void null_dev_release(struct ubbd_device *ubbd_dev)
{
	struct ubbd_null_device *null_dev = NULL_DEV(ubbd_dev);

	free(null_dev);
}

static int null_dev_writev(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	ubbd_dev_add_ce(ubbd_q, se->priv_data, 0);

	return 0;
}

static int null_dev_readv(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	ubbd_dev_add_ce(ubbd_q, se->priv_data, 0);

	return 0;
}

static int null_dev_flush(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	ubbd_dev_add_ce(ubbd_q, se->priv_data, 0);

	return 0;
}

struct ubbd_dev_ops null_dev_ops = {
	.open = null_dev_open,
	.close = null_dev_close,
	.release = null_dev_release,
	.writev = null_dev_writev,
	.readv = null_dev_readv,
	.flush = null_dev_flush,
};
