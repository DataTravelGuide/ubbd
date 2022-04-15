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

static int null_dev_writev(struct ubbd_device *ubbd_dev, struct ubbd_se *se)
{
	struct ubbd_ce *ce;
	struct ubbd_sb *sb = ubbd_dev->uio_info.map;

	pthread_mutex_lock(&ubbd_dev->req_lock);
	ce = get_available_ce(ubbd_dev);
	ce->priv_data = se->priv_data;
	ce->flags = 0;

	ce->result = 0;
	ubbd_dbg("finish se id: %p\n", se);
	ubbd_dbg("append ce: %llu\n", ce->priv_data);
	UBBD_UPDATE_DEV_COMP_HEAD(ubbd_dev, sb, ce);
	pthread_mutex_unlock(&ubbd_dev->req_lock);
	ubbdlib_processing_complete(ubbd_dev);

	return 0;
}

static int null_dev_readv(struct ubbd_device *ubbd_dev, struct ubbd_se *se)
{
	struct ubbd_ce *ce;
	struct ubbd_sb *sb = ubbd_dev->uio_info.map;

	pthread_mutex_lock(&ubbd_dev->req_lock);
	ce = get_available_ce(ubbd_dev);
	ce->priv_data = se->priv_data;
	ce->flags = 0;

	ce->result = 0;
	ubbd_dbg("finish se id: %p\n", se);
	ubbd_dbg("append ce: %llu\n", ce->priv_data);
	UBBD_UPDATE_DEV_COMP_HEAD(ubbd_dev, sb, ce);
	pthread_mutex_unlock(&ubbd_dev->req_lock);
	ubbdlib_processing_complete(ubbd_dev);

	return 0;
}

static int null_dev_flush(struct ubbd_device *ubbd_dev, struct ubbd_se *se)
{
	struct ubbd_ce *ce;
	struct ubbd_sb *sb = ubbd_dev->uio_info.map;

	pthread_mutex_lock(&ubbd_dev->req_lock);
	ce = get_available_ce(ubbd_dev);
	ce->priv_data = se->priv_data;
	ce->flags = 0;

	ce->result = 0;
	ubbd_dbg("finish se id: %p\n", se);
	ubbd_dbg("append ce: %llu\n", ce->priv_data);
	UBBD_UPDATE_DEV_COMP_HEAD(ubbd_dev, sb, ce);
	pthread_mutex_unlock(&ubbd_dev->req_lock);
	ubbdlib_processing_complete(ubbd_dev);

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
