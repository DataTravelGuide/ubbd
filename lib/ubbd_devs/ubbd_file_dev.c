#define _GNU_SOURCE
#include "ubbd_uio.h"
#include "ubbd_dev.h"

#define FILE_DEV(ubbd_dev) ((struct ubbd_file_device *)container_of(ubbd_dev, struct ubbd_file_device, ubbd_dev))

static int file_dev_open(struct ubbd_device *ubbd_dev)
{
	struct ubbd_file_device *file_dev = FILE_DEV(ubbd_dev);

	file_dev->fd = open(file_dev->filepath, O_RDWR | O_DIRECT);
	ubbd_dev->dev_features.write_cache = false;
	ubbd_dev->dev_features.fua = false;
	ubbd_dev->dev_features.discard = false;
	ubbd_dev->dev_features.write_zeros = false;

	return 0;
}

static void file_dev_close(struct ubbd_device *ubbd_dev)
{
	struct ubbd_file_device *file_dev = FILE_DEV(ubbd_dev);

	close(file_dev->fd);
}

static void file_dev_release(struct ubbd_device *ubbd_dev)
{
	struct ubbd_file_device *file_dev = FILE_DEV(ubbd_dev);

	free(file_dev);
}

static int file_dev_writev(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	struct ubbd_device *ubbd_dev = ubbd_q->ubbd_dev;
	struct ubbd_file_device *file_dev = FILE_DEV(ubbd_dev);
	ssize_t ret;
	struct iovec *iov;
	int i;

	iov = malloc(sizeof(struct iovec) * se->iov_cnt);
	for (i = 0; i < se->iov_cnt; i++) {
		ubbd_dbg("iov_base: %lu", (size_t)se->iov[i].iov_base);
		iov[i].iov_base = (void*)ubbd_q->uio_info.map + (size_t)se->iov[i].iov_base;
		iov[i].iov_len = se->iov[i].iov_len;
	}

	ret = pwritev(file_dev->fd, iov, se->iov_cnt, se->offset);
	ubbd_dbg("result of pwritev: %lu\n", ret);
	free(iov);

	ubbd_dev_add_ce(ubbd_q, se->priv_data, (ret == se->len? 0 : ret));

	return 0;
}

static int file_dev_readv(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	struct ubbd_device *ubbd_dev = ubbd_q->ubbd_dev;
	struct ubbd_file_device *file_dev = FILE_DEV(ubbd_dev);
	ssize_t ret;
	struct iovec *iov;
	int i;

	iov = malloc(sizeof(struct iovec) * se->iov_cnt);
	for (i = 0; i < se->iov_cnt; i++) {
		ubbd_dbg("iov_base: %lu", (size_t)se->iov[i].iov_base);
		iov[i].iov_base = (void*)ubbd_q->uio_info.map + (size_t)se->iov[i].iov_base;
		iov[i].iov_len = se->iov[i].iov_len;
	}

	ret = preadv(file_dev->fd, iov, se->iov_cnt, se->offset);
	ubbd_dbg("result of preadv: %lu\n", ret);
	free(iov);
	
	ubbd_dev_add_ce(ubbd_q, se->priv_data, (ret == se->len? 0 : ret));

	return 0;
}

static int file_dev_flush(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	struct ubbd_device *ubbd_dev = ubbd_q->ubbd_dev;
	struct ubbd_file_device *file_dev = FILE_DEV(ubbd_dev);
	int ret;

	ret = fsync(file_dev->fd);

	ubbd_dev_add_ce(ubbd_q, se->priv_data, ret);

	return 0;
}

struct ubbd_dev_ops file_dev_ops = {
	.open = file_dev_open,
	.close = file_dev_close,
	.release = file_dev_release,
	.writev = file_dev_writev,
	.readv = file_dev_readv,
	.flush = file_dev_flush,
};
