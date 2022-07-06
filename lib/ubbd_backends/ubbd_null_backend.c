#define _GNU_SOURCE
#include "ubbd_uio.h"
#include "ubbd_backend.h"
#include "ubbd_queue.h"

#define NULL_BACKEND(ubbd_b) ((struct ubbd_null_backend *)container_of(ubbd_b, struct ubbd_null_backend, ubbd_b))

static int null_backend_open(struct ubbd_backend *ubbd_b)
{
	return 0;
}

static void null_backend_close(struct ubbd_backend *ubbd_b)
{
	return;
}

static void null_backend_release(struct ubbd_backend *ubbd_b)
{
	struct ubbd_null_backend *null_backend = NULL_BACKEND(ubbd_b);

	if (null_backend)
		free(null_backend);
}

static int null_backend_writev(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	ubbd_backend_io_finish(io, 0);

	return 0;
}

static int null_backend_readv(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	ubbd_backend_io_finish(io, 0);

	return 0;
}

static int null_backend_flush(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	ubbd_backend_io_finish(io, 0);

	return 0;
}

struct ubbd_backend_ops null_backend_ops = {
	.open = null_backend_open,
	.close = null_backend_close,
	.release = null_backend_release,
	.writev = null_backend_writev,
	.readv = null_backend_readv,
	.flush = null_backend_flush,
};
