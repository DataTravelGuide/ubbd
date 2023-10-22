#define _GNU_SOURCE
#include "ubbd_kring.h"
#include "ubbd_backend.h"
#include "ubbd_queue.h"
#include "ubbd_backend.h"

#define NULL_BACKEND(ubbd_b) ((struct ubbd_null_backend *)container_of(ubbd_b, struct ubbd_null_backend, ubbd_b))

struct ubbd_backend_ops null_backend_ops;

static struct ubbd_backend* null_backend_create(struct ubbd_dev_info *dev_info)
{
	struct ubbd_null_backend *null_backend;
	struct ubbd_backend *ubbd_b;
	struct __ubbd_dev_info *info = &dev_info->generic_dev.info;

	null_backend = calloc(1, sizeof(*null_backend));
	if (!null_backend)
		return NULL;

	ubbd_b = &null_backend->ubbd_b;
	ubbd_b->dev_type = UBBD_DEV_TYPE_NULL;
	ubbd_b->backend_ops = &null_backend_ops;
	ubbd_b = &null_backend->ubbd_b;
	ubbd_b->dev_size = info->size;

	return ubbd_b;
}

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
	.create = null_backend_create,
	.open = null_backend_open,
	.close = null_backend_close,
	.release = null_backend_release,
	.writev = null_backend_writev,
	.readv = null_backend_readv,
	.flush = null_backend_flush,
};
