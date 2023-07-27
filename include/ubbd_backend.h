#ifndef UBBD_BACKEND_H
#define UBBD_BACKEND_H

#include <ubbd_compat.h>
#include <libaio.h>

#ifdef CONFIG_SSH_BACKEND
#include <libssh/sftp.h>
#endif

#include "ubbd_dev.h"
#include "ubbd_queue.h"
#include "ubbd_config.h"

#ifdef CONFIG_RBD_BACKEND
#include "ubbd_rbd.h"
#endif

#include "libubbd.h"
#include "ubbd_compat.h"

enum ubbd_backend_io_type {
	UBBD_BACKEND_IO_WRITE = 0,
	UBBD_BACKEND_IO_READ,
	UBBD_BACKEND_IO_FLUSH,
	UBBD_BACKEND_IO_DISCARD,
	UBBD_BACKEND_IO_WRITEZEROS,
};

struct ubbd_backend_io {
	struct context *ctx;
	enum ubbd_backend_io_type io_type;
	uint64_t offset;
	uint32_t len;
	int queue_id;
	bool sync;
	uint32_t iov_cnt;
	struct iovec iov[0];
};

static inline void ubbd_backend_io_finish(struct ubbd_backend_io *io, int ret)
{
	context_finish(io->ctx, ret);
}

struct ubbd_backend_opts {
	union {
		struct {
			bool detach_on_close;
		} cache;
	};
};

struct ubbd_backend;
struct ubbd_backend_ops {
	struct ubbd_backend* (*create) (struct __ubbd_dev_info *info);
	int (*open) (struct ubbd_backend *ubbd_b);
	void (*close) (struct ubbd_backend *ubbd_b);
	void (*release) (struct ubbd_backend *ubbd_b);
	int (*set_opts) (struct ubbd_backend *ubbd_b, struct ubbd_backend_opts *opts);
	int (*writev) (struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io);
	int (*readv) (struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io);
	int (*flush) (struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io);
	int (*discard) (struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io);
	int (*write_zeros) (struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io);
	struct ubbd_backend_io* (*create_backend_io)(struct ubbd_backend *ubbd_b, uint32_t iov_cnt);
	void (*free_backend_io)(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io);
};

enum ubbd_backend_status {
	UBBD_BACKEND_STATUS_INIT = 0,
	UBBD_BACKEND_STATUS_RUNNING,
	UBBD_BACKEND_STATUS_ERROR,
};

struct ubbd_backend {
	enum ubbd_dev_type		dev_type;
	int				dev_id;
	int				backend_id;
	struct ubbd_dev_info		dev_info;

	int 				num_queues;
	struct ubbd_queue 		*queues;

	int				status;
	struct ubbd_backend_ops		*backend_ops;
	uint64_t			dev_size;
};

struct ubbd_null_backend {
	struct ubbd_backend ubbd_b;
};

struct ubbd_mem_backend {
	struct ubbd_backend ubbd_b;
};

struct ubbd_file_backend {
	struct ubbd_backend ubbd_b;
	char filepath[UBBD_PATH_MAX];
	int fd;
};

#ifdef CONFIG_RBD_BACKEND
struct ubbd_rbd_backend {
	struct ubbd_backend ubbd_b;
	struct ubbd_rbd_conn rbd_conn;
};
#endif

#ifdef CONFIG_SSH_BACKEND
struct ubbd_ssh_backend {
	struct ubbd_backend ubbd_b;
	char hostname[UBBD_NAME_MAX];
	char path[UBBD_PATH_MAX];
	struct sftp_file_struct *sftp_file;
	pthread_mutex_t			lock;
};
#endif

struct ubbd_cache_backend {
	struct ubbd_backend ubbd_b;
	struct ubbd_backend *cache_backend;
	struct ubbd_backend *backing_backend;
	int cache_mode;
	bool detach_on_close;
};

struct ubbd_s3_backend {
	struct ubbd_backend ubbd_b;
	uint32_t block_size;
	int port;
	char hostname[UBBD_NAME_MAX];
	char accessid[UBBD_NAME_MAX];
	char accesskey[UBBD_NAME_MAX];
	char volume_name[UBBD_NAME_MAX];
	char bucket_name[UBBD_NAME_MAX];
};

struct ubbd_backend *ubbd_backend_create(struct ubbd_backend_conf *backend_conf);
void ubbd_backend_release(struct ubbd_backend *ubbd_b);
int ubbd_backend_start(struct ubbd_backend *ubbd_b, bool start_queues);
void ubbd_backend_stop(struct ubbd_backend *ubbd_b);
int ubbd_backend_open(struct ubbd_backend *ubbd_b);
int ubbd_backend_set_opts(struct ubbd_backend *ubbd_b, struct ubbd_backend_opts *opts);
void ubbd_backend_close(struct ubbd_backend *ubbd_b);
void ubbd_backend_wait_stopped(struct ubbd_backend *ubbd_b);
int ubbd_backend_stop_queue(struct ubbd_backend *ubbd_b, int queue_id);
int ubbd_backend_start_queue(struct ubbd_backend *ubbd_b, int queue_id);
int ubbd_backend_lock(int dev_id, int backend_id, int *fd);
void ubbd_backend_unlock(int fd);
int ubbd_backend_testlock(int dev_id, int backend_id);

uint64_t ubbd_backend_size(struct ubbd_backend *ubbd_b);

int ubbd_backend_read(struct ubbd_backend *ubbd_b, uint64_t off, uint64_t size, char *buf);
int ubbd_backend_write(struct ubbd_backend *ubbd_b, uint64_t off, uint64_t size, char *buf);
struct ubbd_backend_io *ubbd_backend_io_clone(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io, uint32_t off, uint32_t size);

struct ubbd_backend_io *ubbd_backend_create_backend_io(struct ubbd_backend *ubbd_b, uint32_t iov_cnt);
void ubbd_backend_free_backend_io(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io);
#endif /* UBBD_BACKEND_H */
