#include <rados/librados.h>
#include <pthread.h>

#include "ubbd_backend.h"
#include "ubbd_uio.h"

// rbd ops
#define RBD_BACKEND(ubbd_b) ((struct ubbd_rbd_backend *)container_of(ubbd_b, struct ubbd_rbd_backend, ubbd_b))
static int rbd_backend_open(struct ubbd_backend *ubbd_b)
{
	struct ubbd_rbd_backend *rbd_b = RBD_BACKEND(ubbd_b);
	struct ubbd_rbd_conn *rbd_conn = &rbd_b->rbd_conn;

	return ubbd_rbd_conn_open(rbd_conn);
}

static void rbd_backend_close(struct ubbd_backend *ubbd_b)
{
	struct ubbd_rbd_backend *rbd_b = RBD_BACKEND(ubbd_b);
	struct ubbd_rbd_conn *rbd_conn = &rbd_b->rbd_conn;

	ubbd_rbd_conn_close(rbd_conn);
}

static void rbd_backend_release(struct ubbd_backend *ubbd_b)
{
	struct ubbd_rbd_backend *rbd_b = RBD_BACKEND(ubbd_b);

	free(rbd_b);
}

static void rbd_finish_aio_generic(rbd_completion_t completion,
				   struct ubbd_backend_io *io)
{
	int64_t ret;

	ret = rbd_aio_get_return_value(completion);

	if (io->io_type == UBBD_BACKEND_IO_WRITE ||
			io->io_type == UBBD_BACKEND_IO_READ)
		ret = (ret == io->len? 0 : ret);

	rbd_aio_release(completion);
	ubbd_backend_io_finish(io, ret);
}

static int rbd_backend_writev(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct ubbd_rbd_backend *rbd_b = RBD_BACKEND(ubbd_b);
	struct ubbd_rbd_conn *rbd_conn = &rbd_b->rbd_conn;
	rbd_completion_t completion;
	int ret;

	ret = rbd_aio_create_completion
		(io, (rbd_callback_t) rbd_finish_aio_generic, &completion);
	if (ret < 0) {
		ubbd_err("create completion failed\n");
		return -1;
	}
	ret = rbd_aio_writev(rbd_conn->image, io->iov, io->iov_cnt, io->offset, completion);

	return ret;
}

static int rbd_backend_readv(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct ubbd_rbd_backend *rbd_b = RBD_BACKEND(ubbd_b);
	struct ubbd_rbd_conn *rbd_conn = &rbd_b->rbd_conn;
	rbd_completion_t completion;
	ssize_t ret;

	ret = rbd_aio_create_completion
		(io, (rbd_callback_t) rbd_finish_aio_generic, &completion);
	if (ret < 0) {
		ubbd_err("create completion failed\n");
		return -1;
	}
	ret = rbd_aio_readv(rbd_conn->image, io->iov, io->iov_cnt, io->offset, completion);

	return ret;
}

static int rbd_backend_flush(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct ubbd_rbd_backend *rbd_b = RBD_BACKEND(ubbd_b);
	struct ubbd_rbd_conn *rbd_conn = &rbd_b->rbd_conn;
	rbd_completion_t completion;
	ssize_t ret;

	ret = rbd_aio_create_completion
		(io, (rbd_callback_t) rbd_finish_aio_generic, &completion);
	if (ret < 0) {
		ubbd_err("create completion failed\n");
		return -1;
	}
	ret = rbd_aio_flush(rbd_conn->image, completion);

	return ret;
}

static int rbd_backend_discard(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct ubbd_rbd_backend *rbd_b = RBD_BACKEND(ubbd_b);
	struct ubbd_rbd_conn *rbd_conn = &rbd_b->rbd_conn;
	rbd_completion_t completion;
	ssize_t ret;

	ret = rbd_aio_create_completion
		(io, (rbd_callback_t) rbd_finish_aio_generic, &completion);
	if (ret < 0) {
		ubbd_err("create completion failed\n");
		return -1;
	}
	ret = rbd_aio_discard(rbd_conn->image, io->offset, io->len, completion);

	return ret;
}

#ifdef LIBRBD_SUPPORTS_WRITE_ZEROES
static int rbd_backend_write_zeros(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct ubbd_rbd_backend *rbd_b = RBD_BACKEND(ubbd_b);
	struct ubbd_rbd_conn *rbd_conn = &rbd_b->rbd_conn;
	rbd_completion_t completion;
	ssize_t ret;

	ret = rbd_aio_create_completion
		(io, (rbd_callback_t) rbd_finish_aio_generic, &completion);
	if (ret < 0) {
		ubbd_err("create completion failed\n");
		return -1;
	}
	ret = rbd_aio_write_zeroes(rbd_conn->image, io->offset, io->len, completion, 0, 0);

	return ret;
}
#else
static int rbd_backend_write_zeros(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	ubbd_err("write_zeros is not supported\n");

	return -1;
}
#endif

struct ubbd_backend_ops rbd_backend_ops = {
	.open = rbd_backend_open,
	.close = rbd_backend_close,
	.release = rbd_backend_release,
	.writev = rbd_backend_writev,
	.readv = rbd_backend_readv,
	.flush = rbd_backend_flush,
	.discard = rbd_backend_discard,
	.write_zeros = rbd_backend_write_zeros,
};
