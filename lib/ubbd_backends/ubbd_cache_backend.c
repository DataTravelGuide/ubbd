#define _GNU_SOURCE
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ocf/ocf.h>
#include <ocf_def_priv.h>

#include "ocf_env.h"
#include "ocf/ocf_volume.h"
#include "ubbd_uio.h"
#include "ubbd_backend.h"

#define VOL_TYPE 1

ctx_data_t *ctx_data_alloc(uint32_t pages);
void ctx_data_free(ctx_data_t *ctx_data);

int ctx_init(ocf_ctx_t *ocf_ctx);
void ctx_cleanup(ocf_ctx_t ctx);

struct io_ctx_data {
	struct ubbd_backend_io *backend_io;
	struct iovec *iov;
	int iov_cnt;
	uint32_t size;
	uint32_t seek;
};

struct volume_io_ctx {
	struct io_ctx_data *data;
	uint32_t offset;
	int rq_cnt;
	int error;
};

#define PAGE_SIZE 4096

ctx_data_t *ctx_data_alloc(uint32_t pages)
{
	struct io_ctx_data *data;
	void *buf;

	data = calloc(1, sizeof(*data));
	if (!data) {
		ubbd_err("malloc failed\n");
		return NULL;
	}

	posix_memalign((void**)&buf, PAGE_SIZE, PAGE_SIZE * pages);
	if (!buf) {
		ubbd_err("malloc buf failed.\n");
		free(data);
		return NULL;
	}

	data->iov_cnt = 1;
	data->iov = calloc(data->iov_cnt, sizeof(struct iovec));
	if (!data->iov) {
		free(buf);
		free(data);
		return NULL;
	}

	data->iov[0].iov_base = buf;
	data->iov[0].iov_len = pages * PAGE_SIZE;

	data->size = pages * PAGE_SIZE;
	data->seek = 0;

	return data;
}

/*
 * Free data structure.
 */
void ctx_data_free(ctx_data_t *ctx_data)
{
	struct io_ctx_data *data = ctx_data;
	int i;

	if (!data)
		return;

	for (i = 0; i < data->iov_cnt; i++) {
		free(data->iov[i].iov_base);
	}

	free(data->iov);
	free(data);
}

/*
 * This function is supposed to set protection of data pages against swapping.
 * Can be non-implemented if not needed.
 */
static int ctx_data_mlock(ctx_data_t *ctx_data)
{
	return 0;
}

/*
 * Stop protecting data pages against swapping.
 */
static void ctx_data_munlock(ctx_data_t *ctx_data)
{
}

/* queue thread main function */
static void* run(void *);

/* helper class to store all synchronization related objects */
struct queue_thread
{
	/* thread running the queue */
	pthread_t thread;
	/* kick sets true, queue thread sets to false */
	bool signalled;
	/* request thread to exit */
	bool stop;
	/* conditional variable to sync queue thread and kick thread */
	pthread_cond_t cv;
	/* mutex for variables shared across threads */
	pthread_mutex_t mutex;
	/* associated OCF queue */
	struct ocf_queue *queue;
};

struct queue_thread *queue_thread_init(struct ocf_queue *q)
{
	struct queue_thread *qt = malloc(sizeof(*qt));
	int ret;

	if (!qt)
		return NULL;

	ret = pthread_cond_init(&qt->cv, NULL);
	if (ret)
		goto err_mem;

	ret = pthread_mutex_init(&qt->mutex, NULL);
	if (ret)
		goto err_cond;

	qt->signalled = false;
	qt->stop = false;
	qt->queue = q;

	ret = pthread_create(&qt->thread, NULL, run, qt);
	if (ret)
		goto err_mutex;

	return qt;

err_mutex:
	pthread_mutex_destroy(&qt->mutex);
err_cond:
	pthread_cond_destroy(&qt->cv);
err_mem:
	free(qt);

	return NULL;
}

void queue_thread_signal(struct queue_thread *qt, bool stop)
{
	pthread_mutex_lock(&qt->mutex);
	qt->signalled = true;
	qt->stop = stop;
	pthread_cond_signal(&qt->cv);
	pthread_mutex_unlock(&qt->mutex);
}

void queue_thread_destroy(struct queue_thread *qt)
{
	if (!qt)
		return;

	queue_thread_signal(qt, true);
	pthread_join(qt->thread, NULL);

	pthread_mutex_destroy(&qt->mutex);
	pthread_cond_destroy(&qt->cv);
	free(qt);
}

/* queue thread main function */
static void* run(void *arg)
{
	struct queue_thread *qt = arg;
	struct ocf_queue *q = qt->queue;

	pthread_mutex_lock(&qt->mutex);

	while (!qt->stop) {
		if (qt->signalled) {
			qt->signalled = false;
			pthread_mutex_unlock(&qt->mutex);

			/* execute items on the queue */
			ocf_queue_run(q);

			pthread_mutex_lock(&qt->mutex);
		}

		if (!qt->stop && !qt->signalled) 
			pthread_cond_wait(&qt->cv, &qt->mutex);
	}

	pthread_mutex_unlock(&qt->mutex);

	pthread_exit(0);
}

/* initialize I/O queue and management queue thread */
int initialize_threads(struct ocf_queue *mngt_queue, struct ocf_queue *io_queue)
{
	int ret = 0;

	struct queue_thread* mngt_queue_thread = queue_thread_init(mngt_queue);
	struct queue_thread* io_queue_thread = queue_thread_init(io_queue);

	if (!mngt_queue_thread || !io_queue_thread) {
		queue_thread_destroy(io_queue_thread);
		queue_thread_destroy(mngt_queue_thread);
		return 1;
	}

	ocf_queue_set_priv(mngt_queue, mngt_queue_thread);
	ocf_queue_set_priv(io_queue, io_queue_thread);

	return ret;
}

/* callback for OCF to kick the queue thread */
void queue_thread_kick(ocf_queue_t q)
{
	struct queue_thread *qt = ocf_queue_get_priv(q);

	queue_thread_signal(qt, false);
}

/* callback for OCF to stop the queue thread */
void queue_thread_stop(ocf_queue_t q)
{
	struct queue_thread *qt = ocf_queue_get_priv(q);

	queue_thread_destroy(qt);
}

static size_t
iovec_flatten(struct iovec *iov, size_t iovcnt, void *buf, size_t size, size_t offset)
{
	size_t i, len, done = 0;

	for (i = 0; i < iovcnt; i++) {
		if (offset >= iov[i].iov_len) {
			offset -= iov[i].iov_len;
			continue;
		}

		if (iov[i].iov_base == NULL) {
			continue;
		}

		if (done >= size) {
			break;
		}

		len = MIN(size - done, iov[i].iov_len - offset);
		memcpy(buf, iov[i].iov_base + offset, len);
		buf += len;
		done += len;
		offset = 0;
	}

	return done;
}

/*
 * Read data into flat memory buffer.
 */
static uint32_t ctx_data_read(void *dst, ctx_data_t *src, uint32_t size)
{
	struct io_ctx_data *data = src;
	uint32_t copied;

	copied = iovec_flatten(data->iov, data->iov_cnt, dst, size, data->seek);
	data->seek += copied;

	return copied;
}

static size_t
buf_to_iovec(const void *buf, size_t size, struct iovec *iov, size_t iovcnt, size_t offset)
{
	size_t i, len, done = 0;

	for (i = 0; i < iovcnt; i++) {
		if (offset >= iov[i].iov_len) {
			offset -= iov[i].iov_len;
			continue;
		}

		if (iov[i].iov_base == NULL) {
			continue;
		}

		if (done >= size) {
			break;
		}

		len = MIN(size - done, iov[i].iov_len - offset);
		memcpy(iov[i].iov_base + offset, buf, len);
		buf += len;
		done += len;
		offset = 0;
	}

	return done;
}

/*
 * Write data from flat memory buffer.
 */
static uint32_t ctx_data_write(ctx_data_t *dst, const void *src, uint32_t size)
{
	struct io_ctx_data *data = dst;
	uint32_t copied;

	copied = buf_to_iovec(src, size, data->iov, data->iov_cnt, data->seek);
	data->seek += copied;

	return copied;
}

/*
 * Fill data with zeros.
 */
static size_t
iovset(struct iovec *iov, size_t iovcnt, int byte, size_t size, size_t offset)
{
	size_t i, len, done = 0;

	for (i = 0; i < iovcnt; i++) {
		if (offset >= iov[i].iov_len) {
			offset -= iov[i].iov_len;
			continue;
		}

		if (iov[i].iov_base == NULL) {
			continue;
		}

		if (done >= size) {
			break;
		}

		len = MIN(size - done, iov[i].iov_len - offset);
		memset(iov[i].iov_base + offset, byte, len);
		done += len;
		offset = 0;
	}

	return done;
}

static uint32_t ctx_data_zero(ctx_data_t *dst, uint32_t size)
{
	struct io_ctx_data *data = dst;
	uint32_t copied;

	copied = iovset(data->iov, data->iov_cnt, 0, size, data->seek);
	data->seek += copied;

	return copied;
}

/*
 * Perform seek operation on data.
 */
static uint32_t ctx_data_seek(ctx_data_t *dst, ctx_data_seek_t seek,
		uint32_t offset)
{
	struct io_ctx_data *data = dst;
	uint32_t off = 0;

	switch (seek) {
	case ctx_data_seek_begin:
		off = MIN(offset, data->size);
		data->seek = off;
		break;
	case ctx_data_seek_current:
		off = MIN(offset, data->size - data->seek);
		data->seek += off;
		break;
	}

	return off;
}

/*
 * Copy data from one structure to another.
 */
static uint64_t ctx_data_copy(ctx_data_t *dst, ctx_data_t *src,
		uint64_t to, uint64_t from, uint64_t bytes)
{
	struct io_ctx_data *s = src;
	struct io_ctx_data *d = dst;
	uint32_t it_iov = 0;
	uint32_t it_off = 0;
	uint32_t n, sz;

	bytes = MIN(bytes, s->size - from);
	bytes = MIN(bytes, d->size - to);
	sz = bytes;

	while (from || bytes) {
		if (s->iov[it_iov].iov_len == it_off) {
			it_iov++;
			it_off = 0;
			continue;
		}

		if (from) {
			n = MIN(from, s->iov[it_iov].iov_len);
			from -= n;
		} else {
			n = MIN(bytes, s->iov[it_iov].iov_len);
			buf_to_iovec(s->iov[it_iov].iov_base + it_off, n, d->iov, d->iov_cnt, to);
			bytes -= n;
			to += n;
		}

		it_off += n;
	}

	return sz;
}

/*
 * Perform secure erase of data (e.g. fill pages with zeros).
 * Can be left non-implemented if not needed.
 */
static void ctx_data_secure_erase(ctx_data_t *ctx_data)
{
}

/*
 * Initialize cleaner thread. Cleaner thread is left non-implemented,
 * to keep this example as simple as possible.
 */
static int ctx_cleaner_init(ocf_cleaner_t c)
{
	return 0;
}

/*
 * Kick cleaner thread. Cleaner thread is left non-implemented,
 * to keep this example as simple as possible.
 */
static void ctx_cleaner_kick(ocf_cleaner_t c)
{
}

/*
 * Stop cleaner thread. Cleaner thread is left non-implemented, to keep
 * this example as simple as possible.
 */
static void ctx_cleaner_stop(ocf_cleaner_t c)
{
}

/*
 * Function prividing interface for printing to log used by OCF internals.
 * It can handle differently messages at varous log levels.
 */
static int ctx_logger_print(ocf_logger_t logger, ocf_logger_lvl_t lvl,
		const char *fmt, va_list args)
{
	if (lvl > log_info)
		return 0;

	return vfprintf(stderr, fmt, args);
}

#define CTX_LOG_TRACE_DEPTH	16

/*
 * Function prividing interface for printing current stack. Used for debugging,
 * and for providing additional information in log in case of errors.
 */
static int ctx_logger_dump_stack(ocf_logger_t logger)
{
	void *trace[CTX_LOG_TRACE_DEPTH];
	char **messages = NULL;
	int i, size;

	size = backtrace(trace, CTX_LOG_TRACE_DEPTH);
	messages = backtrace_symbols(trace, size);
	ubbd_err("[stack trace]>>>\n");
	for (i = 0; i < size; ++i)
		ubbd_err("%s\n", messages[i]);
	ubbd_err("<<<[stack trace]\n");
	free(messages);

	return 0;
}

static const struct ocf_ctx_config ctx_cfg = {
	.name = "UBBD ocf",
	.ops = {
		.data = {
			.alloc = ctx_data_alloc,
			.free = ctx_data_free,
			.mlock = ctx_data_mlock,
			.munlock = ctx_data_munlock,
			.read = ctx_data_read,
			.write = ctx_data_write,
			.zero = ctx_data_zero,
			.seek = ctx_data_seek,
			.copy = ctx_data_copy,
			.secure_erase = ctx_data_secure_erase,
		},

		.cleaner = {
			.init = ctx_cleaner_init,
			.kick = ctx_cleaner_kick,
			.stop = ctx_cleaner_stop,
		},

		.logger = {
			.print = ctx_logger_print,
			.dump_stack = ctx_logger_dump_stack,
		},
	},
};


/*
 * Function initializing context. Prepares context, sets logger and
 * registers volume type.
 */
int volume_init(ocf_ctx_t ocf_ctx);
int ctx_init(ocf_ctx_t *ctx)
{
	int ret;

	ret = ocf_ctx_create(ctx, &ctx_cfg);
	if (ret)
		return ret;

	ret = volume_init(*ctx);
	if (ret) {
		ocf_ctx_put(*ctx);
		return ret;
	}

	return 0;
}

/*
 * Function cleaning up context. Unregisters volume type and
 * deinitializes context.
 */
void volume_cleanup(ocf_ctx_t ocf_ctx);
void ctx_cleanup(ocf_ctx_t ctx)
{
	volume_cleanup(ctx);
	ocf_ctx_put(ctx);
}




#include <ocf/ocf.h>

#define VOL_SIZE 200*1024*1024

struct ubbd_backend *cache_backend;
struct ubbd_backend *backing_backend;

static int volume_open(ocf_volume_t volume, void *volume_params)
{
	const struct ocf_volume_uuid *uuid = ocf_volume_get_uuid(volume);
	struct ubbd_backend **priv = ocf_volume_get_priv(volume);

	if (!strcmp(ocf_uuid_to_str(uuid), "cache")) {
		*priv = cache_backend;
	} else {
		*priv = backing_backend;
	}

	ubbd_dbg("VOL open\n");

	return 0;
}

static void volume_close(ocf_volume_t volume)
{
	ubbd_dbg("VOL CLOSE\n");
}

static int
get_vec_index(struct iovec *iovs, int iovcnt, int offset, int *vec_index, int *off_in_vec)
{
	int i;

	for (i = 0; i < iovcnt; i++) {
		if (offset < iovs[i].iov_len) {
			*off_in_vec = offset;
			*vec_index = i;
			return 0;
		}
		offset -= iovs[i].iov_len;
	}

	return -1;
}

static void
initialize_cpy_vector(struct iovec *cpy_vec, struct iovec *orig_vec,
		      size_t offset, size_t bytes)
{
	void *curr_base;
	int len, i;

	i = 0;

	while (bytes > 0) {
		curr_base = orig_vec[i].iov_base + offset;
		len = MIN(bytes, orig_vec[i].iov_len - offset);

		cpy_vec[i].iov_base = curr_base;
		cpy_vec[i].iov_len = len;

		bytes -= len;
		offset = 0;
		i++;
	}
}

/* Prefix of cb means cache backend */
struct cb_backend_io_ctx_data {
	struct ubbd_backend_io *backend_io;
	struct ocf_io *io;
};

static void volume_io_ctx_finish(struct ocf_io *io, int ret)
{
	struct volume_io_ctx *volume_io_ctx = ocf_io_get_priv(io);

	if (ret) {
		ubbd_err("volume io failed: %d\n", ret);
		if (!volume_io_ctx->error) {
			volume_io_ctx->error = ret;
		}
	}

	if (--volume_io_ctx->rq_cnt == 0) {
		io->end(io, volume_io_ctx->error);
	}
}

static int cb_backend_io_finish(struct context *ctx, int ret)
{
	struct cb_backend_io_ctx_data *data = (struct cb_backend_io_ctx_data *)ctx->data;
	struct ubbd_backend_io *backend_io = data->backend_io;
	struct ocf_io *io = data->io;

	volume_io_ctx_finish(io, ret);

	free(backend_io);

	return 0;
}

static struct ubbd_backend_io *cb_prepare_backend_io(struct ocf_io *io,
		struct iovec *iov,
		int iov_cnt,
		int off_in_start,
		uint64_t addr_in_volume,
		int len)
{
	struct ubbd_backend_io *backend_io;
	struct context *ctx;
	struct cb_backend_io_ctx_data *data;

	backend_io = calloc(1, sizeof(struct ubbd_backend_io) + sizeof(struct iovec) * iov_cnt);
	if (!backend_io) {
		ubbd_err("failed to calloc for backend io\n");
		return NULL;
	}

	ctx = context_alloc(sizeof(struct cb_backend_io_ctx_data));
	if (!ctx) {
		ubbd_err("failed to calloc for backend_io_ctx\n");
		free(io);
		return NULL;
	}

	data = (struct cb_backend_io_ctx_data *)ctx->data;
	data->backend_io = backend_io;
	data->io = io;

	ctx->parent = NULL;
	ctx->finish = cb_backend_io_finish;

	backend_io->ctx = ctx;
	backend_io->offset = addr_in_volume;
	backend_io->len = len;
	backend_io->iov_cnt = iov_cnt;

	if (iov_cnt)
		initialize_cpy_vector(backend_io->iov, iov, off_in_start, len);

	return backend_io;
}

static struct ubbd_backend_io *prepare_submit(struct ocf_io *io)
{
	struct io_ctx_data *data;
	struct ubbd_backend_io *backend_io;
	struct volume_io_ctx *volume_io_ctx = ocf_io_get_priv(io);
	uint64_t addr, len;
	int start_vec, end_vec, off_in_start, off_in_end;
	int offset;
	int ret;

	volume_io_ctx->rq_cnt++;
	addr = io->addr;
	len = io->bytes;
	offset = volume_io_ctx->offset;

	data = ocf_io_get_data(io);
	ret = get_vec_index(data->iov, data->iov_cnt, offset, &start_vec, &off_in_start);
	if (ret) {
		ubbd_err("failed to get vec index of start vec.\n");
		return NULL;
	}
	ret = get_vec_index(data->iov, data->iov_cnt, offset + len - 1, &end_vec, &off_in_end);
	if (ret) {
		ubbd_err("failed to get vec index of end vec.\n");
		return NULL;
	}

	backend_io = cb_prepare_backend_io(io, &data->iov[start_vec], end_vec - start_vec + 1, off_in_start, addr, len);

	return backend_io;
}

static struct ubbd_backend_io *prepare_submit_nodata(struct ocf_io *io)
{
	struct ubbd_backend_io *backend_io;
	struct volume_io_ctx *volume_io_ctx = ocf_io_get_priv(io);
	uint64_t addr, len;

	volume_io_ctx->rq_cnt++;
	addr = io->addr;
	len = io->bytes;

	backend_io = cb_prepare_backend_io(io, NULL, 0, 0, addr, len);

	return backend_io;
}

static void volume_submit_io(struct ocf_io *io)
{
	struct ubbd_backend *ubbd_b;
	struct ubbd_backend_io *backend_io;
	const struct ocf_volume_uuid *uuid = ocf_volume_get_uuid(ocf_io_get_volume(io));

	backend_io = prepare_submit(io);
	if (!backend_io) {
		volume_io_ctx_finish(io, -EIO);
		return;
	}

	ubbd_b = *(struct ubbd_backend **)ocf_volume_get_priv(ocf_io_get_volume(io));

	if (io->dir == OCF_WRITE) {
		ubbd_dbg("%s write %lu %u\n", ocf_uuid_to_str(uuid), io->addr, io->bytes);
		ubbd_b->backend_ops->writev(ubbd_b, backend_io);
	} else {
		ubbd_dbg("%s read %lu %u\n", ocf_uuid_to_str(uuid), io->addr, io->bytes);
		ubbd_b->backend_ops->readv(ubbd_b, backend_io);
	}

	return;
}

/*
 * We don't need to implement submit_flush(). Just complete io with success.
 */
static void volume_submit_flush(struct ocf_io *io)
{
	struct ubbd_backend *ubbd_b;
	struct ubbd_backend_io *backend_io;

	ubbd_b = *(struct ubbd_backend **)ocf_volume_get_priv(ocf_io_get_volume(io));

	backend_io = prepare_submit_nodata(io);
	if (!backend_io) {
		volume_io_ctx_finish(io, -EIO);
		return;
	}

	ubbd_b->backend_ops->flush(ubbd_b, backend_io);

	return;
}

/*
 * We don't need to implement submit_discard(). Just complete io with success.
 */
static void volume_submit_discard(struct ocf_io *io)
{
	struct ubbd_backend *ubbd_b;
	struct ubbd_backend_io *backend_io;

	ubbd_b = *(struct ubbd_backend **)ocf_volume_get_priv(ocf_io_get_volume(io));
	if (!ubbd_b->backend_ops->discard) {
		io->end(io, -ENOTSUP);
		return;
	}

	backend_io = prepare_submit_nodata(io);
	if (!backend_io) {
		volume_io_ctx_finish(io, -EIO);
		return;
	}

	ubbd_b->backend_ops->discard(ubbd_b, backend_io);

	return;
}

/*
 * Let's set maximum io size to 128 KiB.
 */
static unsigned int volume_get_max_io_size(ocf_volume_t volume)
{
	return 128 * 1024;
}

/*
 * Return volume size.
 */
static uint64_t volume_get_length(ocf_volume_t volume)
{
	struct ubbd_backend *ubbd_b;

	ubbd_b = *(struct ubbd_backend **)ocf_volume_get_priv(volume);

	return ubbd_b->dev_size;
}

/*
 * In set_data() we just assing data and offset to io.
 */
static int volume_io_ctx_set_data(struct ocf_io *io, ctx_data_t *data,
		uint32_t offset)
{
	struct volume_io_ctx *volume_io_ctx = ocf_io_get_priv(io);

	volume_io_ctx->data = data;
	volume_io_ctx->offset = offset;

	return 0;
}

/*
 * In get_data() return data stored in io.
 */
static ctx_data_t *volume_io_ctx_get_data(struct ocf_io *io)
{
	struct volume_io_ctx *volume_io_ctx = ocf_io_get_priv(io);

	return volume_io_ctx->data;
}

/*
 * This structure contains volume properties. It describes volume
 * type, which can be later instantiated as backend storage for cache
 * or core.
 */
const struct ocf_volume_properties volume_properties = {
	.name = "UBBD volume",
	.io_priv_size = sizeof(struct volume_io_ctx),
	.volume_priv_size = sizeof(struct ubbd_backend *),
	.caps = {
		.atomic_writes = 0,
	},
	.ops = {
		.open = volume_open,
		.close = volume_close,
		.submit_io = volume_submit_io,
		.submit_flush = volume_submit_flush,
		.submit_discard = volume_submit_discard,
		.get_max_io_size = volume_get_max_io_size,
		.get_length = volume_get_length,
	},
	.io_ops = {
		.set_data = volume_io_ctx_set_data,
		.get_data = volume_io_ctx_get_data,
	},
};

/*
 * This function registers volume type in OCF context.
 * It should be called just after context initialization.
 */
int volume_init(ocf_ctx_t ocf_ctx)
{
	return ocf_ctx_register_volume_type(ocf_ctx, VOL_TYPE,
			&volume_properties);
}

/*
 * This function unregisters volume type in OCF context.
 * It should be called just before context cleanup.
 */
void volume_cleanup(ocf_ctx_t ocf_ctx)
{
	ocf_ctx_unregister_volume_type(ocf_ctx, VOL_TYPE);
}


/*
 * Cache private data. Used to share information between async contexts.
 */
struct cache_priv {
	ocf_queue_t mngt_queue;
	ocf_queue_t io_queue;
};

/*
 * Helper function for error handling.
 */
void error(char *msg)
{
	ubbd_err("ERROR: %s", msg);
	exit(1);
}

/*
 * Queue ops providing interface for running queue thread in both synchronous
 * and asynchronous way. The stop() operation in called just before queue is
 * being destroyed.
 */
const struct ocf_queue_ops queue_ops = {
	.kick = queue_thread_kick,
	.stop = queue_thread_stop,
};

/*
 * Simple completion context. As lots of OCF API functions work asynchronously
 * and call completion callback when job is done, we need some structure to
 * share program state with completion callback. In this case we have single
 * variable pointer to propagate error code.
 */
struct simple_context {
	int *error;
	sem_t sem;
};

/*
 * Basic asynchronous completion callback. Just propagate error code.
 */
static void simple_complete(ocf_cache_t cache, void *priv, int error)
{
	struct simple_context *context= priv;

	*context->error = error;
	sem_post(&context->sem);
}

static void purge_cb(ocf_core_t core, void *priv, int error)
{
	struct simple_context *context= priv;

	*context->error = error;
	sem_post(&context->sem);
}

/*
 * Function starting cache and attaching cache device.
 */
int initialize_cache(ocf_ctx_t ctx, ocf_cache_t *cache, bool cache_exist, int cache_mode)
{
	struct ocf_mngt_cache_config cache_cfg = { .name = "cache1" };
	struct ocf_mngt_cache_attach_config attach_cfg = { };
	ocf_volume_t volume;
	ocf_volume_type_t type;
	struct ocf_volume_uuid uuid;
	struct cache_priv *cache_priv;
	struct simple_context context;
	int ret, err;

	/* Initialize completion semaphore */
	ret = sem_init(&context.sem, 0, 0);
	if (ret)
		return ret;

	/*
	 * Asynchronous callbacks will assign error code to ret. That
	 * way we have always the same variable holding last error code.
	 */
	context.error = &ret;

	/* Cache configuration */
	ocf_mngt_cache_config_set_default(&cache_cfg);
	cache_cfg.metadata_volatile = false;
	cache_cfg.cache_mode = cache_mode;

	/* Cache deivce (volume) configuration */
	type = ocf_ctx_get_volume_type(ctx, VOL_TYPE);
	ret = ocf_uuid_set_str(&uuid, "cache");
	if (ret)
		goto err_sem;

	ret = ocf_volume_create(&volume, type, &uuid);
	if (ret)
		goto err_sem;

	ocf_mngt_cache_attach_config_set_default(&attach_cfg);
	attach_cfg.device.volume = volume;
	attach_cfg.cache_line_size = ocf_cache_line_size_32;
	attach_cfg.open_cores = false;
	attach_cfg.discard_on_start = false;
	attach_cfg.device.perform_test = false;

	/*
	 * Allocate cache private structure. We can not initialize it
	 * on stack, as it may be used in various async contexts
	 * throughout the entire live span of cache object.
	 */
	cache_priv = malloc(sizeof(*cache_priv));
	if (!cache_priv) {
		ret = -ENOMEM;
		goto err_vol;
	}

	/* Start cache */
	ret = ocf_mngt_cache_start(ctx, cache, &cache_cfg, NULL);
	if (ret)
		goto err_priv;

	/* Assing cache priv structure to cache. */
	ocf_cache_set_priv(*cache, cache_priv);

	/*
	 * Create management queue. It will be used for performing various
	 * asynchronous management operations, such as attaching cache volume
	 * or adding core object.
	 */
	ret = ocf_queue_create(*cache, &cache_priv->mngt_queue, &queue_ops);
	if (ret) {
		err = ret;
		ocf_mngt_cache_stop(*cache, simple_complete, &context);
		goto err_priv;
	}

	/*
	 * Assign management queue to cache. This has to be done before any
	 * other management operation. Management queue is treated specially,
	 * and it may not be used for submitting IO requests. It also will not
	 * be put on the cache stop - we have to put it manually at the end.
	 */
	ocf_mngt_cache_set_mngt_queue(*cache, cache_priv->mngt_queue);

	/* Create queue which will be used for IO submission. */
	ret = ocf_queue_create(*cache, &cache_priv->io_queue, &queue_ops);
	if (ret)
		goto err_cache;

	ret = initialize_threads(cache_priv->mngt_queue, cache_priv->io_queue);
	if (ret)
		goto err_cache;

	/* Attach volume to cache */
	if (cache_exist) {
		ocf_mngt_cache_load(*cache, &attach_cfg, simple_complete, &context);
	} else {
		ocf_mngt_cache_attach(*cache, &attach_cfg, simple_complete, &context);
	}

	sem_wait(&context.sem);

	if (ret) {
		err = ret;
		goto err_cache;
	}

	return 0;

err_cache:
	ocf_mngt_cache_stop(*cache, simple_complete, &context);
	ocf_queue_put(cache_priv->mngt_queue);
err_priv:
	free(cache_priv);
err_vol:
	ocf_volume_destroy(volume);
err_sem:
	sem_destroy(&context.sem);
	return err;
}

struct add_core_context {
	ocf_core_t *core;
	int *error;
	sem_t sem;
};

/* Add core complete callback. Just rewrite args to context structure and
 * up the semaphore.
 */
static void add_core_complete(ocf_cache_t cache, ocf_core_t core,
		void *priv, int error)
{
	struct add_core_context *context = priv;

	*context->core = core;
	*context->error = error;
	sem_post(&context->sem);
}

/*
 * Function adding cache to core.
 */
int initialize_core(ocf_cache_t cache, ocf_core_t *core, bool cache_exist)
{
	struct ocf_mngt_core_config core_cfg = { };
	struct add_core_context context;
	int ret;

	ret = sem_init(&context.sem, 0, 0);
	if (ret)
		return ret;

	/*
	 * Asynchronous callback will assign core handle to core,
	 * and to error code to ret.
	 */
	context.core = core;
	context.error = &ret;

	/* Core configuration */
	ocf_mngt_core_config_set_default(&core_cfg);
	strcpy(core_cfg.name, "core1");
	core_cfg.volume_type = VOL_TYPE;
	if (cache_exist)
		core_cfg.try_add = true;
	ret = ocf_uuid_set_str(&core_cfg.uuid, "core");
	if (ret)
		return ret;

	/* Add core to cache */
	ocf_mngt_cache_add_core(cache, &core_cfg, add_core_complete, &context);
	sem_wait(&context.sem);

	return ret;
}

void cache_backend_io_cmpl(struct ocf_io *io, int error)
{
	struct io_ctx_data *data = ocf_io_get_data(io);
	struct ubbd_backend_io *backend_io = data->backend_io;

	ubbd_backend_io_finish(backend_io, error);

	ocf_io_put(io);
}

int submit_io(ocf_core_t core, struct io_ctx_data *data,
		uint64_t addr, uint64_t len, int dir)
{
	ocf_cache_t cache = ocf_core_get_cache(core);
	ocf_volume_t core_vol = ocf_core_get_front_volume(core);
	struct cache_priv *cache_priv = ocf_cache_get_priv(cache);
	struct ocf_io *io;

	/* Allocate new io */
	io = ocf_volume_new_io(core_vol, cache_priv->io_queue, addr, len, dir, 0, 0);
	if (!io)
		return -ENOMEM;

	/* Assign data to io */
	ocf_io_set_data(io, data, 0);
	/* Setup completion function */
	ocf_io_set_cmpl(io, NULL, NULL, cache_backend_io_cmpl);
	/* Submit io */
	ocf_core_submit_io(io);

	return 0;
}

static void stop_core_complete(void *priv, int error)
{
	struct simple_context *context = priv;

	*context->error = error;
}

ocf_ctx_t ctx = NULL;
ocf_cache_t cache1 = NULL;
ocf_core_t core1 = NULL;

#define CACHE_DEV(ubbd_b) ((struct ubbd_cache_backend *)container_of(ubbd_b, struct ubbd_cache_backend, ubbd_b))

struct probe_ctx {
	env_completion cmpl;
	int ret;
};

static void probe_cb(void *priv, int ret,
		struct ocf_metadata_probe_status *status)
{
	struct probe_ctx *ctx = priv;

	ctx->ret = ret;

	env_completion_complete(&ctx->cmpl);
}

static int cache_probe(ocf_ctx_t ctx)
{
	ocf_volume_t volume;
	struct probe_ctx probe_ctx;
	int ret;
	struct ocf_volume_uuid volume_uuid;

	ocf_uuid_set_str(&volume_uuid, "cache");
	ret = ocf_ctx_volume_create(ctx, &volume, &volume_uuid, VOL_TYPE);
	if (ret) {
		ubbd_err("failed to create cache volume.\n");
		return ret;
	}

	ret = ocf_volume_open(volume, NULL);
	if (ret) {
		ubbd_err("failed to open volume for cache.\n");
		return ret;
	}

	env_completion_init(&probe_ctx.cmpl);
	probe_ctx.ret = 0;
	ocf_metadata_probe(ctx, volume, probe_cb, &probe_ctx);

	env_completion_wait(&probe_ctx.cmpl);
	env_completion_destroy(&probe_ctx.cmpl);

	ocf_volume_close(volume);
	ocf_volume_destroy(volume);

	return probe_ctx.ret;
}


static int cache_backend_open(struct ubbd_backend *ubbd_b)
{
	int ret = 0;
	struct ubbd_cache_backend *cache_b = CACHE_DEV(ubbd_b);
	bool cache_exist;

	ret = ubbd_backend_open(cache_b->backing_backend);
	if (ret) {
		return ret;
	}

	ret = ubbd_backend_open(cache_b->cache_backend);
	if (ret) {
		ubbd_backend_close(cache_b->backing_backend);
		return ret;
	}

	cache_backend = cache_b->cache_backend;
	backing_backend = cache_b->backing_backend;

	/* Initialize OCF context */
	if (ctx_init(&ctx)) {
		error("Unable to initialize context\n");
		ret = -1;
		goto out;
	}

	ret = cache_probe(ctx);
	if (ret) {
		if (ret == -OCF_ERR_NO_METADATA)
			cache_exist = false;
		else {
			ubbd_err("probe failed : %d\n", ret);
			goto out;
		}
	} else {
		cache_exist = true;
	}

	/* Start cache */
	if (initialize_cache(ctx, &cache1, cache_exist, cache_b->cache_mode)) {
		error("Unable to start cache\n");
		ret = -1;
		goto out;
	}

	ocf_mngt_cache_set_mode(cache1, cache_b->cache_mode);

	/* Add core */
	if (initialize_core(cache1, &core1, cache_exist)) {
		error("Unable to add core\n");
		ret = -1;
		goto out;
	}
	ret = 0;

out:
	return ret;
}

static void cache_backend_close(struct ubbd_backend *ubbd_b)
{
	int ret = 0;
	struct ubbd_cache_backend *cache_b = CACHE_DEV(ubbd_b);
	struct cache_priv *cache_priv;
	struct simple_context context;

	if (cache_b->detach_on_close) {
		struct simple_context ctx = { 0 };

		ret = sem_init(&ctx.sem, 0, 0);
		if (ret)
			ubbd_err("failed to init sem\n");

		ctx.error = &ret;

		ocf_mngt_core_purge(core1, purge_cb, &ctx);

		sem_wait(&ctx.sem);

		if (*ctx.error) {
			ubbd_err("failed to purge cache data\n");
		}
	}


	context.error = &ret;

	ocf_mngt_cache_detach_core(core1, stop_core_complete, &context);
	if (ret)
		error("Unable to stop core\n");

	/* Stop cache */
	ocf_mngt_cache_stop(cache1, simple_complete, &context);
	if (ret)
		error("Unable to stop cache\n");

	cache_priv = ocf_cache_get_priv(cache1);

	/* Put the management queue */
	ocf_queue_put(cache_priv->mngt_queue);

	free(cache_priv);

	/* Deinitialize context */
	ctx_cleanup(ctx);

	ubbd_backend_close(cache_b->cache_backend);
	ubbd_backend_close(cache_b->backing_backend);
}

static void cache_backend_release(struct ubbd_backend *ubbd_b)
{
	struct ubbd_cache_backend *cache_b = CACHE_DEV(ubbd_b);

	if (!cache_b)
		return;

	if (cache_b->cache_backend)
		ubbd_backend_release(cache_b->cache_backend);

	if (cache_b->backing_backend)
		ubbd_backend_release(cache_b->backing_backend);

	free(cache_b);
}

static int cache_backend_writev(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct io_ctx_data *data1;

	/* Allocate data buffer and fill it with example data */
	data1 = ctx_data_alloc(BYTES_TO_PAGES(io->len));
	if (!data1)
		error("Unable to allocate data1\n");

	data1->iov = io->iov;
	data1->iov_cnt = io->iov_cnt;
	data1->size = io->len;
	data1->backend_io = io;

	/* Prepare and submit write IO to the core */
	submit_io(core1, data1, io->offset, io->len, OCF_WRITE);
	/* After write completes, complete_write() callback will be called. */

	return 0;
}

static int cache_backend_readv(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct io_ctx_data *data1;

	/* Allocate data buffer and fill it with example data */
	data1 = ctx_data_alloc(BYTES_TO_PAGES(io->len));
	if (!data1)
		error("Unable to allocate data1\n");

	data1->iov = io->iov;
	data1->iov_cnt = io->iov_cnt;
	data1->size = io->len;
	data1->backend_io = io;

	/* Prepare and submit write IO to the core */
	submit_io(core1, data1, io->offset, io->len, OCF_READ);
	/* After write completes, complete_write() callback will be called. */

	return 0;
}

static int cache_backend_flush(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	ubbd_backend_io_finish(io, 0);
	return 0;
}

static int cache_backend_set_opts(struct ubbd_backend *ubbd_b, struct ubbd_backend_opts *opts)
{
	struct ubbd_cache_backend *cache_b = CACHE_DEV(ubbd_b);

	cache_b->detach_on_close = opts->cache.detach_on_close;

	return 0;
}

struct ubbd_backend_ops cache_backend_ops = {
	.open = cache_backend_open,
	.close = cache_backend_close,
	.release = cache_backend_release,
	.writev = cache_backend_writev,
	.readv = cache_backend_readv,
	.flush = cache_backend_flush,
	.set_opts = cache_backend_set_opts,
};
