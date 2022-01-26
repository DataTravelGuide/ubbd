#define _GNU_SOURCE
#include "ubbd_uio.h"
#include "ubbd_dev.h"

#define FILE_DEV(ubbd_dev) ((struct ubbd_file_device *)container_of(ubbd_dev, struct ubbd_file_device, ubbd_dev))

static int file_dev_open(struct ubbd_device *ubbd_dev)
{
	struct ubbd_file_device *file_dev = FILE_DEV(ubbd_dev);

	file_dev->fd = open(file_dev->filepath, O_RDWR | O_DIRECT);
	ubbd_dev->dev_features.write_cache = true;
	ubbd_dev->dev_features.fua = false;
	return 0;
}


static int file_dev_writev(struct ubbd_device *ubbd_dev, struct ubbd_se *se)
{
	struct ubbd_file_device *file_dev = FILE_DEV(ubbd_dev);
	ssize_t ret;
	struct ubbd_ce *ce;
	struct ubbd_sb *sb = ubbd_dev->map;
	struct iovec *iov;
	int i;

	iov = malloc(sizeof(struct iovec) * se->iov_cnt);
	for (i = 0; i < se->iov_cnt; i++) {
		ubbd_err("iov_base: %lu", (size_t)se->iov[i].iov_base);
		iov[i].iov_base = (void*)ubbd_dev->map + (size_t)se->iov[i].iov_base;
		iov[i].iov_len = se->iov[i].iov_len;
	}

	ret = pwritev(file_dev->fd, iov, se->iov_cnt, se->offset);
	ubbd_err("result of pwritev: %lu\n", ret);

	pthread_mutex_lock(&ubbd_dev->lock);
	ce = get_available_ce(ubbd_dev);
	ce->priv_data = se->priv_data;
	ce->flags = 0;

	ce->result = (ret == se->len? 0 : ret);
	ubbd_err("finish se id: %p\n", se);
	ubbd_err("append ce: %llu\n", ce->priv_data);
	UBBD_UPDATE_DEV_COMP_HEAD(ubbd_dev, sb, ce);
	pthread_mutex_unlock(&ubbd_dev->lock);
	ubbdlib_processing_complete(ubbd_dev);

	return 0;
}

static int file_dev_readv(struct ubbd_device *ubbd_dev, struct ubbd_se *se)
{
	struct ubbd_file_device *file_dev = FILE_DEV(ubbd_dev);
	ssize_t ret;
	struct ubbd_ce *ce;
	struct ubbd_sb *sb = ubbd_dev->map;
	struct iovec *iov;
	int i;

	iov = malloc(sizeof(struct iovec) * se->iov_cnt);
	for (i = 0; i < se->iov_cnt; i++) {
		ubbd_err("iov_base: %lu", (size_t)se->iov[i].iov_base);
		iov[i].iov_base = (void*)ubbd_dev->map + (size_t)se->iov[i].iov_base;
		iov[i].iov_len = se->iov[i].iov_len;
	}

	ret = preadv(file_dev->fd, iov, se->iov_cnt, se->offset);
	ubbd_err("result of preadv: %lu\n", ret);
	
	pthread_mutex_lock(&ubbd_dev->lock);
	ce = get_available_ce(ubbd_dev);
	ce->priv_data = se->priv_data;
	ce->flags = 0;

	ce->result = (ret == se->len? 0 : ret);
	ubbd_err("finish se id: %p\n", se);
	ubbd_err("append ce: %llu\n", ce->priv_data);
	UBBD_UPDATE_DEV_COMP_HEAD(ubbd_dev, sb, ce);
	pthread_mutex_unlock(&ubbd_dev->lock);
	ubbdlib_processing_complete(ubbd_dev);

	return 0;
}

static void file_dev_release(struct ubbd_device *ubbd_dev)
{
	struct ubbd_file_device *file_dev = FILE_DEV(ubbd_dev);

	free(file_dev);
}

static int file_dev_flush(struct ubbd_device *ubbd_dev, struct ubbd_se *se)
{
	struct ubbd_file_device *file_dev = FILE_DEV(ubbd_dev);
	struct ubbd_ce *ce;
	struct ubbd_sb *sb = ubbd_dev->map;
	int ret;

	ret = fsync(file_dev->fd);
	pthread_mutex_lock(&ubbd_dev->lock);
	ce = get_available_ce(ubbd_dev);
	ce->priv_data = se->priv_data;
	ce->flags = 0;

	ce->result = ret;
	ubbd_err("finish se id: %p\n", se);
	ubbd_err("append ce: %llu\n", ce->priv_data);
	UBBD_UPDATE_DEV_COMP_HEAD(ubbd_dev, sb, ce);
	pthread_mutex_unlock(&ubbd_dev->lock);
	ubbdlib_processing_complete(ubbd_dev);

	return 0;
}

struct ubbd_dev_ops file_dev_ops = {
	.open = file_dev_open,
	.writev = file_dev_writev,
	.readv = file_dev_readv,
	.release = file_dev_release,
	.flush = file_dev_flush,
};
