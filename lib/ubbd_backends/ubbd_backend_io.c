#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <pthread.h>

#include "utils.h"
#include "list.h"
#include "ubbd_backend.h"
#include "ubbd_uio.h"
#include "ubbd_netlink.h"
#include "ubbd_queue.h"

/* backend sync IO */
struct backend_io_ctx_data {
	bool done;
	int ret;
};

static void backend_wait_io_done(struct backend_io_ctx_data *data)
{
	/* FIXME use condition to wait and wakeup */
	while (true) {
		if (data->done) {
			return;
		}
		usleep(100000);
	}
}

static int backend_io_finish(struct context *ctx, int ret)
{
	struct backend_io_ctx_data *data = (struct backend_io_ctx_data *)ctx->extra_data;

	if (ret) {
		ubbd_err("ret of backend_io: %s\n", strerror(-ret));
	}

	data->ret = ret;
	data->done = true;

	return 0;
}

static struct ubbd_backend_io *backend_prepare_io(struct ubbd_backend *ubbd_b,
		enum ubbd_backend_io_type type, uint64_t off, uint32_t len, void *buf,
		struct backend_io_ctx_data *io_data)
{
	struct ubbd_backend_io *io;
	struct context *ctx;

	io = calloc(1, sizeof(struct ubbd_backend_io) + sizeof(struct iovec));
	if (!io) {
		ubbd_err("failed to calloc for backend io\n");
		return NULL;
	}

	ctx = context_alloc(0);
	if (!ctx) {
		ubbd_err("failed to calloc for backend_io_ctx\n");
		goto free_io;
	}

	ctx->extra_data = io_data;
	ctx->parent = NULL;
	ctx->finish = backend_io_finish;

	io->ctx = ctx;
	io->io_type = type;
	io->offset = off;
	io->len = len;
	io->iov_cnt = 1;
	io->iov[0].iov_base = buf;
	io->iov[0].iov_len = len;

	return io;
free_io:
	free(io);

	return NULL;
}

int backend_rw(struct ubbd_backend *ubbd_b, uint64_t off, uint64_t size, char *buf,
		enum ubbd_backend_io_type type)
{
	struct ubbd_backend_io *io;
	struct backend_io_ctx_data *data;
	int ret;

	data = calloc(1, sizeof(struct backend_io_ctx_data));
	if (!data) {
		return -ENOMEM;
	}

	io = backend_prepare_io(ubbd_b, type, off, size, buf, data);
	if (!io) {
		ret = -ENOMEM;
		goto free_data;
	}

	if (type == UBBD_BACKEND_IO_READ) {
		ret = ubbd_b->backend_ops->readv(ubbd_b, io);
	} else {
		ret = ubbd_b->backend_ops->writev(ubbd_b, io);
	}

	if (ret) {
		goto free_io;
	}

	backend_wait_io_done(data);
	ret = data->ret;
free_io:
	free(io);
free_data:
	free(data);
	return ret;
}

int ubbd_backend_read(struct ubbd_backend *ubbd_b, uint64_t off, uint64_t size, char *buf)
{
	return backend_rw(ubbd_b, off, size, buf, UBBD_BACKEND_IO_READ);
}

int ubbd_backend_write(struct ubbd_backend *ubbd_b, uint64_t off, uint64_t size, char *buf)
{
	return backend_rw(ubbd_b, off, size, buf, UBBD_BACKEND_IO_WRITE);
}

static int find_vec(struct ubbd_backend_io *io, uint32_t off, uint32_t *off_in_vec,
		bool tail_mode)
{
	int i;
	uint32_t advanced = 0;

	if (off > io->len) {
		ubbd_err("find_vec overflowed: len: %u, off: %u.\n", io->len, off);
		return -1;
	}

	for (i = 0; i < io->iov_cnt; i++) {
		if (advanced + io->iov[i].iov_len > off) {
			*off_in_vec = off - advanced;
			return i;
		}
		if (tail_mode && advanced + io->iov[i].iov_len == off) {
			/* off is the tail of this iov */
			*off_in_vec = off - advanced;
			return i;
		}
		advanced += io->iov[i].iov_len;
	}

	return -1;
}

struct ubbd_backend_io *ubbd_backend_io_clone(struct ubbd_backend_io *io, uint32_t off, uint32_t size)
{
	struct ubbd_backend_io *clone_io;
	int start_vec, end_vec, vec_count;
	uint32_t start_vec_off, end_vec_off;

	if (size > io->len) {
		ubbd_err("IO advance overflowed: len: %u, size: %u.\n", io->len, size);
		return NULL;
	}

	start_vec = find_vec(io, off, &start_vec_off, false);
	if (start_vec < 0) {
		ubbd_err("cant find start_vec for off: %u\n", off);
		return NULL;
	}

	end_vec = find_vec(io, off + size, &end_vec_off, true);
	if (end_vec < 0) {
		ubbd_err("cant find end_vec for off: %u\n", off + size);
		return NULL;
	}

	vec_count = end_vec - start_vec + 1;

	clone_io = calloc(1, sizeof(struct ubbd_backend_io) + (sizeof(struct iovec) * vec_count));
	if (!clone_io) {
		return NULL;
	}

	clone_io->io_type = io->io_type;
	clone_io->offset = io->offset + off;
	clone_io->len = size;
	clone_io->iov_cnt = vec_count;
	memcpy(clone_io->iov, io->iov + start_vec, sizeof(struct iovec) * vec_count);
	if (start_vec_off) {
		clone_io->iov[0].iov_base += start_vec_off;
		clone_io->iov[0].iov_len -= start_vec_off;
	}

	if (start_vec == end_vec) {
		clone_io->iov[end_vec - start_vec].iov_len = end_vec_off - start_vec_off;
	} else {
		clone_io->iov[end_vec - start_vec].iov_len = end_vec_off;
	}

	return clone_io;
}
