#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <pthread.h>

#include "utils.h"
#include "list.h"
#include "ubbd_backend.h"
#include "ubbd_kring.h"
#include "ubbd_netlink.h"
#include "ubbd_queue.h"

#ifdef CONFIG_RBD_BACKEND
extern struct ubbd_backend_ops rbd_backend_ops;
#endif
extern struct ubbd_backend_ops file_backend_ops;
extern struct ubbd_backend_ops null_backend_ops;
#ifdef CONFIG_SSH_BACKEND
extern struct ubbd_backend_ops ssh_backend_ops;
#endif
#ifdef CONFIG_CACHE_BACKEND
extern struct ubbd_backend_ops cache_backend_ops;
#endif
#ifdef CONFIG_S3_BACKEND
extern struct ubbd_backend_ops s3_backend_ops;
#endif
extern struct ubbd_backend_ops mem_backend_ops;

static int ubbd_backend_init(struct ubbd_backend *ubbd_b, struct ubbd_backend_conf *conf)
{
	int ret;
	struct ubbd_queue *ubbd_q;
	int i;

	ubbd_b->num_queues = conf->num_queues;
	ubbd_b->status = UBBD_BACKEND_STATUS_INIT;

	ubbd_b->queues = calloc(ubbd_b->num_queues, sizeof(struct ubbd_queue));
	if (!ubbd_b->queues) {
		ubbd_err("failed to alloc queues\n");
		ret = -ENOMEM;
		goto out;
	}


	for (i = 0; i < ubbd_b->num_queues; i++) {
		ubbd_q = &ubbd_b->queues[i];
		ubbd_q->ubbd_b = ubbd_b;
		ubbd_q->kring_info.kring_id = conf->queue_infos[i].kring_id;
		ubbd_q->kring_info.kring_map_size = conf->queue_infos[i].kring_map_size;
		ubbd_q->backend_pid = conf->queue_infos[i].backend_pid;
		ubbd_q->status = conf->queue_infos[i].status;
		memcpy(&ubbd_q->cpuset, &conf->queue_infos[i].cpuset, sizeof(cpu_set_t));
		ubbd_q->index = i;
	}

	return 0;

out:
	return ret;
}

struct ubbd_backend *backend_create(struct __ubbd_dev_info *info)
{
	struct ubbd_backend *ubbd_b;
	struct ubbd_backend_ops *backend_ops = NULL;

	if (info->header.magic != UBBD_DEV_INFO_MAGIC) {
		ubbd_err("bad magic in ubbd_dev_info: %llx.\n", info->header.magic);
		return NULL;
	}

	if (info->type == UBBD_DEV_TYPE_FILE) {
		backend_ops = &file_backend_ops;
#ifdef CONFIG_RBD_BACKEND
	} else if (info->type == UBBD_DEV_TYPE_RBD) {
		backend_ops = &rbd_backend_ops;
#endif
	} else if (info->type == UBBD_DEV_TYPE_NULL) {
		backend_ops = &null_backend_ops;
#ifdef CONFIG_SSH_BACKEND
	} else if (info->type == UBBD_DEV_TYPE_SSH) {
		backend_ops = &ssh_backend_ops;
#endif
#ifdef CONFIG_S3_BACKEND
	} else if (info->type == UBBD_DEV_TYPE_S3) {
		backend_ops = &s3_backend_ops;
#endif
	} else if (info->type == UBBD_DEV_TYPE_MEM) {
		backend_ops = &mem_backend_ops;
	}
	
	if (backend_ops == NULL) {
		ubbd_err("Unknown dev type: %d\n", info->type);

		return NULL;
	} else {
		if (!backend_ops->create) {
			ubbd_err("no create function support for this backend.\n");
			return NULL;
		}

		ubbd_b = backend_ops->create(info);
		if (ubbd_b == NULL) {
			return NULL;
		}
		ubbd_b->dev_size = info->size;
	}

	return ubbd_b;
}

struct ubbd_backend *cache_backend_create(struct ubbd_backend_conf *conf)
{
#ifdef CONFIG_CACHE_BACKEND
	struct ubbd_cache_backend *cache_b;
	struct ubbd_backend *ubbd_b;
	struct ubbd_dev_info *dev_info = &conf->dev_info;

	cache_b = calloc(1, sizeof(struct ubbd_cache_backend));
	if (!cache_b) {
		ubbd_err("failed to alloc cache_b.\n");
		return NULL;
	}

	cache_b->cache_backends[0] = backend_create(&dev_info->cache_dev.cache_info);
	if (!cache_b->cache_backends[0]) {
		goto free_cache_b;
	}

	if (0) {
	strcpy(dev_info->cache_dev.cache_info.file.path, "/dev/nvme0n1p1");
	//strcpy(dev_info->cache_dev.cache_info.file.path, "/root/ceph/ubbd_devs/cache1");
	cache_b->cache_backends[1] = backend_create(&dev_info->cache_dev.cache_info);
	if (!cache_b->cache_backends[1]) {
		goto free_cache_b;
	}

	strcpy(dev_info->cache_dev.cache_info.file.path, "/dev/nvme2n1p5");
	//strcpy(dev_info->cache_dev.cache_info.file.path, "/root/ceph/ubbd_devs/cache2");
	cache_b->cache_backends[2] = backend_create(&dev_info->cache_dev.cache_info);
	if (!cache_b->cache_backends[2]) {
		goto free_cache_b;
	}

	strcpy(dev_info->cache_dev.cache_info.file.path, "/dev/ram0");
	//strcpy(dev_info->cache_dev.cache_info.file.path, "/root/ceph/ubbd_devs/cache3");
	cache_b->cache_backends[3] = backend_create(&dev_info->cache_dev.cache_info);
	if (!cache_b->cache_backends[3]) {
		goto free_cache_b;
	}
	}

	cache_b->backing_backend = backend_create(&dev_info->cache_dev.backing_info);
	if (!cache_b->backing_backend) {
		goto free_cache_backend;
	}

	cache_b->cache_mode = conf->cache_mode;

	ubbd_b = &cache_b->ubbd_b;
	ubbd_b->dev_type = UBBD_DEV_TYPE_CACHE;
	ubbd_b->backend_ops = &cache_backend_ops;

	return &cache_b->ubbd_b;

free_cache_backend:
	free(cache_b->cache_backend);
free_cache_b:
	free(cache_b);

#endif
	return NULL;
}

struct ubbd_backend *ubbd_backend_create(struct ubbd_backend_conf *conf)
{
	struct ubbd_backend *ubbd_b;
	struct ubbd_dev_info *dev_info = &conf->dev_info;
	int ret;

	if (conf->dev_type == UBBD_DEV_TYPE_CACHE) {
		ubbd_b = cache_backend_create(conf);
	} else {
		ubbd_b = backend_create(&dev_info->generic_dev.info);
	}

	if (!ubbd_b)
		return NULL;

	ubbd_b->dev_id = conf->dev_id;
	ubbd_b->dev_size = conf->dev_size;
	memcpy(&ubbd_b->dev_info, dev_info, sizeof(struct ubbd_dev_info));

	ret = ubbd_backend_init(ubbd_b, conf);
	if (ret) {
		ubbd_err("failed to init backend\n");
		goto err_release;
	}

	return ubbd_b;

err_release:
	ubbd_backend_release(ubbd_b);

	return NULL;
}

int ubbd_backend_open(struct ubbd_backend *ubbd_b)
{
	return ubbd_b->backend_ops->open(ubbd_b);
}

void ubbd_backend_close(struct ubbd_backend *ubbd_b)
{
	ubbd_b->backend_ops->close(ubbd_b);
}

void ubbd_backend_release(struct ubbd_backend *ubbd_b)
{
	if (ubbd_b->queues)
		free(ubbd_b->queues);
	ubbd_b->backend_ops->release(ubbd_b);
}

int ubbd_backend_start(struct ubbd_backend *ubbd_b, bool start_queues)
{
	struct ubbd_queue *ubbd_q;
	int ret = 0;
	int i;

	if (start_queues) {
		for (i = 0; i < ubbd_b->num_queues; i++) {
			ubbd_q = &ubbd_b->queues[i];
			ubbd_q->ubbd_b = ubbd_b;
			pthread_mutex_init(&ubbd_q->req_lock, NULL);
			pthread_mutex_init(&ubbd_q->req_stats_lock, NULL);
			ret = ubbd_queue_setup(ubbd_q);
			if (ret)
				goto out;
		}
	}

	if (ubbd_b->status == UBBD_BACKEND_STATUS_INIT) {
		ubbd_b->status = UBBD_BACKEND_STATUS_RUNNING;
	}

out:
	return ret;
}

void ubbd_backend_stop(struct ubbd_backend *ubbd_b)
{
	struct ubbd_queue *ubbd_q;
	int i;

	for (i = 0; i < ubbd_b->num_queues; i++) {
		ubbd_q = &ubbd_b->queues[i];
		ubbd_queue_stop(ubbd_q);
	}
}

void ubbd_backend_wait_stopped(struct ubbd_backend *ubbd_b)
{
	struct ubbd_queue *ubbd_q;
	int i;

	for (i = 0; i < ubbd_b->num_queues; i++) {
		ubbd_q = &ubbd_b->queues[i];
		ubbd_queue_wait_stopped(ubbd_q);
	}
}

int ubbd_backend_stop_queue(struct ubbd_backend *ubbd_b, int queue_id)
{
	struct ubbd_queue *ubbd_q;

	if (queue_id >= ubbd_b->num_queues) {
		ubbd_err("queue_id is invalid: %d\n", queue_id);
		return -EINVAL;
	}
	ubbd_q = &ubbd_b->queues[queue_id];
	ubbd_queue_stop(ubbd_q);

	return ubbd_queue_wait_stopped(ubbd_q);
}

int ubbd_backend_start_queue(struct ubbd_backend *ubbd_b, int queue_id)
{
	struct ubbd_queue *ubbd_q;

	if (queue_id >= ubbd_b->num_queues) {
		ubbd_err("queue_id is invalid: %d\n", queue_id);
		return -EINVAL;
	}
	ubbd_q = &ubbd_b->queues[queue_id];
	ubbd_queue_setup(ubbd_q);

	return 0;
}

int ubbd_backend_set_opts(struct ubbd_backend *ubbd_b, struct ubbd_backend_opts *opts)
{
	if (!ubbd_b->backend_ops->set_opts)
		return 0;

	return ubbd_b->backend_ops->set_opts(ubbd_b, opts);
}

static char *get_backend_lock_path(int dev_id, int backend_id)
{
	char *path;

	if (asprintf(&path, "%s/ubbd%d_backend%d.lock", UBBD_LIB_DIR, dev_id, backend_id) == -1) {
		ubbd_err("failed to init backend config path.\n");
		return NULL;
	}

	return path;
}

int _backend_lock(int dev_id, int backend_id, int *fd, bool test) {
	char *lock_path;
	int ret = -ENOMEM;

	lock_path = get_backend_lock_path(dev_id, backend_id);
	if (!lock_path)
		goto out;

	*fd = open(lock_path, O_RDWR|O_CREAT, 0666);
	if (*fd < 0) {
		ubbd_err("failed to open lock_path %s\n", lock_path);
		ret = -errno;
		goto free_path;
	}

	if (!test) {
		ret = lockf(*fd, F_LOCK, 0);

		if (ret) {
			ubbd_err("failed to flock %s\n", lock_path);
		};
		goto close;
	}

	ret = lockf(*fd, F_TEST, 0);

close:
	close(*fd);
free_path:
	free(lock_path);
out:
	return ret;
}

int ubbd_backend_lock(int dev_id, int backend_id, int *fd)
{
	return _backend_lock(dev_id, backend_id, fd, false);
}

void ubbd_backend_unlock(int fd)
{
	int ret;

	ret = lockf(fd, F_ULOCK, 0);
	if (ret < 0) {
		ubbd_err("failed to unlock: %d\n", ret);
	}
	close(fd);
}

int ubbd_backend_testlock(int dev_id, int backend_id)
{
	int fd;

	return _backend_lock(dev_id, backend_id, &fd, true);
}

uint64_t ubbd_backend_size(struct ubbd_backend *ubbd_b)
{
	return ubbd_b->dev_size;
}

struct ubbd_backend_io *ubbd_backend_create_backend_io(struct ubbd_backend *ubbd_b, uint32_t iov_cnt, int queue_id)
{
	if (ubbd_b->backend_ops->create_backend_io) {
		return ubbd_b->backend_ops->create_backend_io(ubbd_b, iov_cnt, queue_id);
	}

	return calloc(1, sizeof(struct ubbd_backend_io) + sizeof(struct iovec) * iov_cnt);
}

void ubbd_backend_free_backend_io(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	if (ubbd_b->backend_ops->free_backend_io) {
		return ubbd_b->backend_ops->free_backend_io(ubbd_b, io);
	}

	free(io);
}
