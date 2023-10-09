#define _GNU_SOURCE
#include <rados/librados.h>
#include <pthread.h>

#include "ubbd_backend.h"
#include "ubbd_kring.h"
#include "ubbd_compat.h"

// rbd ops
#define RBD_BACKEND(ubbd_b) ((struct ubbd_rbd_backend *)container_of(ubbd_b, struct ubbd_rbd_backend, ubbd_b))

struct ubbd_backend_ops rbd_backend_ops;

static struct ubbd_backend* rbd_backend_create(struct __ubbd_dev_info *info)
{
	struct ubbd_rbd_backend *rbd_backend;
	struct ubbd_rbd_conn *rbd_conn;
	struct ubbd_backend *ubbd_b;

	rbd_backend = calloc(1, sizeof(*rbd_backend));
	if (!rbd_backend)
		return NULL;

	ubbd_b = &rbd_backend->ubbd_b;
	ubbd_b->dev_type = UBBD_DEV_TYPE_RBD;
	ubbd_b->backend_ops = &rbd_backend_ops;
	rbd_conn = &rbd_backend->rbd_conn;

	strcpy(rbd_conn->pool, info->rbd.pool);
	strcpy(rbd_conn->ns, info->rbd.ns);
	strcpy(rbd_conn->imagename, info->rbd.image);
	if (info->rbd.flags & UBBD_DEV_INFO_RBD_FLAGS_SNAP) {
		rbd_conn->flags |= UBBD_DEV_INFO_RBD_FLAGS_SNAP;
		strcpy(rbd_conn->snap, info->rbd.snap);
	}
	strcpy(rbd_conn->ceph_conf, info->rbd.ceph_conf);
	strcpy(rbd_conn->user_name, info->rbd.user_name);
	strcpy(rbd_conn->cluster_name, info->rbd.cluster_name);
	rbd_conn->io_timeout = info->io_timeout;

	if (info->rbd.flags & UBBD_DEV_INFO_RBD_FLAGS_EXCLUSIVE) {
		rbd_conn->flags |= UBBD_DEV_INFO_RBD_FLAGS_EXCLUSIVE;
	}

	if (info->header.version >= 1) {
		if (info->rbd.flags & UBBD_DEV_INFO_RBD_FLAGS_QUIESCE) {
			rbd_conn->flags |= UBBD_DEV_INFO_RBD_FLAGS_QUIESCE;
			strcpy(rbd_conn->quiesce_hook, info->rbd.quiesce_hook);
		}
	}

	return ubbd_b;
}

#ifdef HAVE_RBD_QUIESCE
static void rbd_backend_quiesce_cb(void *arg)
{
	struct ubbd_rbd_backend *rbd_b = (struct ubbd_rbd_backend *)arg;
	struct ubbd_backend *ubbd_b = &rbd_b->ubbd_b;
	struct ubbd_rbd_conn *rbd_conn = &rbd_b->rbd_conn;
	char *dev_str;
	int ret = 0;

	ubbd_info("quiesce /dev/ubbd%d : %s: %lu\n", ubbd_b->dev_id,
			rbd_conn->quiesce_hook, rbd_conn->quiesce_handle);

	if (asprintf(&dev_str, "/dev/ubbd%d", ubbd_b->dev_id) == -1) {
		ubbd_err("cont init dev_str\n");
		ret = -1;
		goto out;
	}

	char *arg_list[] = {
		rbd_conn->quiesce_hook,
		dev_str,
		"quiesce",
		NULL
	};

	ret = execute(rbd_conn->quiesce_hook, arg_list);
	free(dev_str);
out:
	ubbd_info("quiesce complete: %d\n", ret);
	if (ret > 0) {
		ret = -1;
	}
	rbd_quiesce_complete(rbd_conn->image, rbd_conn->quiesce_handle, ret);
}

static void rbd_backend_unquiesce_cb(void *arg)
{
	struct ubbd_rbd_backend *rbd_b = (struct ubbd_rbd_backend *)arg;
	struct ubbd_backend *ubbd_b = &rbd_b->ubbd_b;
	struct ubbd_rbd_conn *rbd_conn = &rbd_b->rbd_conn;
	char *dev_str;

	ubbd_info("unquiesce /dev/ubbd%d : %s: %lu\n", ubbd_b->dev_id,
			rbd_conn->quiesce_hook, rbd_conn->quiesce_handle);

	if (asprintf(&dev_str, "/dev/ubbd%d", ubbd_b->dev_id) == -1) {
		ubbd_err("cont init dev_str for unquiesce\n");
		return;
	}

	char *arg_list[] = {
		rbd_conn->quiesce_hook,
		dev_str,
		"unquiesce",
		NULL
	};

	execute(rbd_conn->quiesce_hook, arg_list);
	free(dev_str);
}
#endif /* HAVE_RBD_QUIESCE */

static int rbd_backend_open(struct ubbd_backend *ubbd_b)
{
	struct ubbd_rbd_backend *rbd_b = RBD_BACKEND(ubbd_b);
	struct ubbd_rbd_conn *rbd_conn = &rbd_b->rbd_conn;
	int ret;

	ret = ubbd_rbd_conn_open(rbd_conn);
	if (ret) {
		ubbd_err("failed to open rbd connection: %d\n", ret);
		return ret;
	}

	ret = ubbd_rbd_get_size(rbd_conn, &ubbd_b->dev_size);
	if (ret < 0) {
		ubbd_err("failed to get size of ubbd in backend open.\n");
		goto close_rbd;
	}

	if (rbd_conn->flags & UBBD_DEV_INFO_RBD_FLAGS_EXCLUSIVE) {
		ret = rbd_lock_acquire(rbd_conn->image, RBD_LOCK_MODE_EXCLUSIVE);
		if (ret) {
			ubbd_err("failed to get exclusive lock: %d\n", ret);
			goto close_rbd;
		}
	}

#ifdef HAVE_RBD_QUIESCE
	if (rbd_conn->flags & UBBD_DEV_INFO_RBD_FLAGS_QUIESCE) {
		ret = rbd_quiesce_watch(rbd_conn->image, rbd_backend_quiesce_cb,
				rbd_backend_unquiesce_cb, ubbd_b,
				&rbd_conn->quiesce_handle);
		if (ret) {
			ubbd_err("failed to register quiesce watcher: %d\n", ret);
			rbd_lock_release(rbd_conn->image);
			goto close_rbd;
		}
	}
#endif

	return 0;

close_rbd:
	ubbd_rbd_conn_close(rbd_conn);
	return ret;
}

static void rbd_backend_close(struct ubbd_backend *ubbd_b)
{
	struct ubbd_rbd_backend *rbd_b = RBD_BACKEND(ubbd_b);
	struct ubbd_rbd_conn *rbd_conn = &rbd_b->rbd_conn;

#ifdef HAVE_RBD_QUIESCE
	rbd_quiesce_unwatch(rbd_conn->image, rbd_conn->quiesce_handle);
#endif
	rbd_lock_release(rbd_conn->image);
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
	.create = rbd_backend_create,
	.open = rbd_backend_open,
	.close = rbd_backend_close,
	.release = rbd_backend_release,
	.writev = rbd_backend_writev,
	.readv = rbd_backend_readv,
	.flush = rbd_backend_flush,
	.discard = rbd_backend_discard,
	.write_zeros = rbd_backend_write_zeros,
};
