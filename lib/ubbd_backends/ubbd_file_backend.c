#define _GNU_SOURCE
#include "ubbd_kring.h"
#include "ubbd_backend.h"
#include "ubbd_mempool.h"

#define FILE_BACKEND(ubbd_b) ((struct ubbd_file_backend *)container_of(ubbd_b, struct ubbd_file_backend, ubbd_b))
#define FILE_IO(io) (container_of(io, struct file_backend_io, backend_io))

struct ubbd_backend_ops file_backend_ops;

struct file_backend_io {
	struct iocb cb;
	struct list_head node;
	int from_pool:1;
	int queue_id;
	struct ubbd_backend_io backend_io;
	/* backend_io must be the last member */
};

struct thread_info {
	struct ubbd_backend *ubbd_b;
	io_context_t io_ctx;
	pthread_t	comp_thread;
	pthread_t	submit_thread;

	struct list_head io_list;
	pthread_mutex_t	io_list_lock;
	pthread_cond_t io_submit_cond;

	struct ubbd_mempool *io_pool;

	bool thread_stop;
};


struct ubbd_file_backend {
	struct ubbd_backend ubbd_b;
	char filepath[UBBD_PATH_MAX];
	int fd;
	struct thread_info *io_threads;
};


static struct ubbd_backend *file_backend_create(struct __ubbd_dev_info *info)
{
	struct ubbd_backend *ubbd_b;
	struct ubbd_file_backend *file_backend;

	file_backend = calloc(1, sizeof(*file_backend));
	if (!file_backend)
		return NULL;

	ubbd_b = &file_backend->ubbd_b;
	ubbd_b->dev_type = UBBD_DEV_TYPE_FILE;
	ubbd_b->backend_ops = &file_backend_ops;
	strcpy(file_backend->filepath, info->file.path);

	return ubbd_b;
}

static void *io_complete_fn(void *arg)
{
	struct thread_info *info = (struct thread_info *)arg;
	struct io_event events[1024];
	struct iocb *cb;
	struct timespec timeout = {.tv_sec = 1, .tv_nsec = 0 };
	int ret;
	ssize_t res;
	int i;

	while (true) {
		if (info->thread_stop) {
			ret = 0;
			goto out;
		}

		ret = io_getevents(info->io_ctx, 1, 1024, events, &timeout);
		if (ret < 0) {
			ubbd_err("failed to get events: %d\n", ret);
			if (ret == -EINTR)
				continue;
			else
				goto out;
		} else if (ret == 0) {
			continue;
		}

		for (i = 0; i < ret; i++) {
			res = events[i].res;
			cb = events[i].obj;
			struct file_backend_io *file_io = container_of(cb, struct file_backend_io, cb);
			struct ubbd_backend_io *io = &file_io->backend_io;


			if (res != io->len)
				ubbd_err("result of file io: %ld, io->len: %u\n", res, io->len);

			ubbd_backend_io_finish(io, (res == io->len? 0 : res));
		}

	}

out:
	ubbd_err("io_complete thread exit with %d\n", ret);
	return NULL;
}

static void *io_submit_fn(void *arg)
{
	struct thread_info *info = (struct thread_info *)arg;
	struct iocb *cbs[1024];
	LIST_HEAD(tmp_list);
	struct file_backend_io *tmp_io, *next_io;
	int ret;
	int io_count;

	while (true) {
		if (info->thread_stop) {
			ret = 0;
			goto out;
		}

		pthread_mutex_lock(&info->io_list_lock);
		if (list_empty(&info->io_list)) {
			pthread_cond_wait(&info->io_submit_cond, &info->io_list_lock);
		}
		list_splice_init(&info->io_list, &tmp_list);
		pthread_mutex_unlock(&info->io_list_lock);

		io_count = 0;
		list_for_each_entry_safe(tmp_io, next_io, &tmp_list, node) {
			cbs[io_count++] = &tmp_io->cb;
			if (io_count >= 1024)
				break;
		}

		if (false && io_count > 1) {
			ubbd_err("io_count: %d\n", io_count);
		}
		ret = io_submit(info->io_ctx, io_count, cbs);
		if (ret < 0) {
			ubbd_err("failed to submit io:%d\n", ret);

			list_for_each_entry_safe(tmp_io, next_io, &tmp_list, node) {
				list_del_init(&tmp_io->node);
				ubbd_backend_io_finish(&tmp_io->backend_io, ret);
			}
		}

		INIT_LIST_HEAD(&tmp_list);
	}
out:
	ubbd_err("io_submit thread exit with %d\n", ret);
	return NULL;
}

static int file_backend_open(struct ubbd_backend *ubbd_b)
{
	struct ubbd_file_backend *file_b = FILE_BACKEND(ubbd_b);
	int i;
	int ret;

	ret = ubbd_util_get_file_size(file_b->filepath, &ubbd_b->dev_size);
	if (ret)
		return ret;

	file_b->fd = open(file_b->filepath, O_RDWR | O_DIRECT);
	if (file_b->fd < 0) {
		return file_b->fd;
	}

	file_b->io_threads = calloc(ubbd_b->num_queues, sizeof(struct thread_info));
	if (!file_b->io_threads) {
		ret = -ENOMEM;
		goto close_fd;
	}

	for (i = 0; i < ubbd_b->num_queues; i++) {
		struct thread_info *info = &file_b->io_threads[i];

		info->ubbd_b = ubbd_b;
		ret = io_setup(1024, &info->io_ctx);
		if (ret < 0) {
			ubbd_err("failed to setup io ctx\n");
			goto destroy_threads;
		}

		INIT_LIST_HEAD(&info->io_list);
		pthread_mutex_init(&info->io_list_lock, NULL);
		pthread_cond_init(&info->io_submit_cond, NULL);
		info->io_pool = ubbd_mempool_alloc(sizeof(struct file_backend_io), 1024);

		ret = pthread_create(&info->comp_thread, NULL, io_complete_fn, info);
		if (ret < 0) {
			ubbd_err("failed to create io complete thread: %d\n", ret);
			goto destroy_threads;
		}

		ret = pthread_create(&info->submit_thread, NULL, io_submit_fn, info);
		if (ret < 0) {
			ubbd_err("failed to create io submit thread: %d\n", ret);
			goto destroy_threads;
		}
	}

	return 0;

destroy_threads:
	for (i = 0; i < ubbd_b->num_queues; i++) {
		struct thread_info *info = &file_b->io_threads[i];

		info->thread_stop = true;

		pthread_join(info->comp_thread, NULL);
		pthread_join(info->submit_thread, NULL);
	}
	free(file_b->io_threads);
close_fd:
	close(file_b->fd);

	return ret;
}

static void file_backend_close(struct ubbd_backend *ubbd_b)
{
	struct ubbd_file_backend *file_b = FILE_BACKEND(ubbd_b);
	int i;

	for (i = 0; i < ubbd_b->num_queues; i++) {
		struct thread_info *info = &file_b->io_threads[i];

		info->thread_stop = true;
		ubbd_mempool_free(info->io_pool);
		pthread_cond_signal(&info->io_submit_cond);

		pthread_join(info->comp_thread, NULL);
		pthread_join(info->submit_thread, NULL);
	}

	if (file_b->io_threads)
		free(file_b->io_threads);

	close(file_b->fd);
}

static void file_backend_release(struct ubbd_backend *ubbd_b)
{
	struct ubbd_file_backend *file_b = FILE_BACKEND(ubbd_b);
	if (file_b)
		free(file_b);
}

static void queue_io(struct thread_info *info, struct file_backend_io *file_io)
{
	pthread_mutex_lock(&info->io_list_lock);
	list_add_tail(&file_io->node, &info->io_list);
	pthread_cond_signal(&info->io_submit_cond);
	pthread_mutex_unlock(&info->io_list_lock);
}

static int file_backend_writev(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct ubbd_file_backend *file_b = FILE_BACKEND(ubbd_b);

	if (io->sync) {
		ssize_t ret;

		ret = pwritev(file_b->fd, io->iov, io->iov_cnt, io->offset);
		if (ret != io->len)
			ubbd_err("result of pwritev: %ld\n", ret);
		ubbd_backend_io_finish(io, (ret == io->len? 0 : ret));
	} else {
		struct file_backend_io *file_io = FILE_IO(io);
		struct thread_info *info = &file_b->io_threads[io->queue_id % ubbd_b->num_queues];

		io_prep_pwritev(&file_io->cb, file_b->fd, io->iov, io->iov_cnt, io->offset);

		queue_io(info, file_io);
	}

	return 0;
}

static int file_backend_readv(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct ubbd_file_backend *file_b = FILE_BACKEND(ubbd_b);
	ssize_t ret;

	ret = preadv(file_b->fd, io->iov, io->iov_cnt, io->offset);
	if (ret != io->len)
		ubbd_err("result of preadv: %ld: %s\n", ret, strerror(errno));
	ubbd_backend_io_finish(io, (ret == io->len? 0 : ret));
	
	return 0;
}

static int file_backend_flush(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct ubbd_file_backend *file_b = FILE_BACKEND(ubbd_b);
	int ret;

	ret = fsync(file_b->fd);
	ubbd_backend_io_finish(io, ret);

	return 0;
}

static struct ubbd_backend_io *file_backend_create_backend_io(struct ubbd_backend *ubbd_b, uint32_t iov_cnt, int queue_id)
{
	struct ubbd_file_backend *file_b = FILE_BACKEND(ubbd_b);
	struct file_backend_io *file_io;
	int bit;

	if (iov_cnt <= 4) {
		bit = ubbd_mempool_get(file_b->io_threads[queue_id].io_pool, (void **)&file_io);
		if (bit == -1) {
			ubbd_err("failed to create backend_io\n");
			return NULL;
		}

		file_io->from_pool = 1;
		file_io->queue_id = queue_id;
	} else {
		file_io = calloc(1, sizeof(struct file_backend_io) + sizeof(struct iovec) * iov_cnt);
		file_io->from_pool = 0;
	}

	INIT_LIST_HEAD(&file_io->node);

	return &file_io->backend_io;
}

static void file_backend_free_backend_io(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct file_backend_io *file_io = container_of(io, struct file_backend_io, backend_io);

	if (file_io->from_pool) {
		ubbd_mempool_put(file_io);
	} else {
		free(file_io);
	}
}

struct ubbd_backend_ops file_backend_ops = {
	.create = file_backend_create,
	.open = file_backend_open,
	.close = file_backend_close,
	.release = file_backend_release,
	.writev = file_backend_writev,
	.readv = file_backend_readv,
	.flush = file_backend_flush,
	.create_backend_io = file_backend_create_backend_io,
	.free_backend_io = file_backend_free_backend_io,
};
