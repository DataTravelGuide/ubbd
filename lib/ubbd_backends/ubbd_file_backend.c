#define _GNU_SOURCE
#include "ubbd_uio.h"
#include "ubbd_backend.h"

#define FILE_DEV(ubbd_b) ((struct ubbd_file_backend *)container_of(ubbd_b, struct ubbd_file_backend, ubbd_b))

static int file_backend_open(struct ubbd_backend *ubbd_b)
{
	struct ubbd_file_backend *file_b = FILE_DEV(ubbd_b);

	file_b->fd = open(file_b->filepath, O_RDWR | O_DIRECT);

	return 0;
}

static void file_backend_close(struct ubbd_backend *ubbd_b)
{
	struct ubbd_file_backend *file_b = FILE_DEV(ubbd_b);

	close(file_b->fd);
}

static void file_backend_release(struct ubbd_backend *ubbd_b)
{
	struct ubbd_file_backend *file_b = FILE_DEV(ubbd_b);
	if (file_b)
		free(file_b);
}

static int file_backend_writev(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	struct ubbd_backend *ubbd_b = ubbd_q->ubbd_b;
	struct ubbd_file_backend *file_b = FILE_DEV(ubbd_b);
	ssize_t ret;
	struct iovec *iov;
	int i;

	iov = malloc(sizeof(struct iovec) * se->iov_cnt);
	for (i = 0; i < se->iov_cnt; i++) {
		ubbd_dbg("iov_base: %lu", (size_t)se->iov[i].iov_base);
		iov[i].iov_base = (void*)ubbd_q->uio_info.map + (size_t)se->iov[i].iov_base;
		iov[i].iov_len = se->iov[i].iov_len;
	}

	ret = pwritev(file_b->fd, iov, se->iov_cnt, se->offset);
	ubbd_dbg("result of pwritev: %lu\n", ret);
	free(iov);

	ubbd_queue_add_ce(ubbd_q, se->priv_data, (ret == se->len? 0 : ret));

	return 0;
}

static int file_backend_readv(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	struct ubbd_backend *ubbd_b = ubbd_q->ubbd_b;
	struct ubbd_file_backend *file_b = FILE_DEV(ubbd_b);
	ssize_t ret;
	struct iovec *iov;
	int i;

	iov = malloc(sizeof(struct iovec) * se->iov_cnt);
	for (i = 0; i < se->iov_cnt; i++) {
		ubbd_dbg("iov_base: %lu", (size_t)se->iov[i].iov_base);
		iov[i].iov_base = (void*)ubbd_q->uio_info.map + (size_t)se->iov[i].iov_base;
		iov[i].iov_len = se->iov[i].iov_len;
	}

	ret = preadv(file_b->fd, iov, se->iov_cnt, se->offset);
	ubbd_dbg("result of preadv: %lu\n", ret);
	free(iov);
	
	ubbd_queue_add_ce(ubbd_q, se->priv_data, (ret == se->len? 0 : ret));

	return 0;
}

static int file_backend_flush(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	struct ubbd_backend *ubbd_b = ubbd_q->ubbd_b;
	struct ubbd_file_backend *file_b = FILE_DEV(ubbd_b);
	int ret;

	ret = fsync(file_b->fd);

	ubbd_queue_add_ce(ubbd_q, se->priv_data, ret);

	return 0;
}

struct ubbd_backend_ops file_backend_ops = {
	.open = file_backend_open,
	.close = file_backend_close,
	.release = file_backend_release,
	.writev = file_backend_writev,
	.readv = file_backend_readv,
	.flush = file_backend_flush,
};
