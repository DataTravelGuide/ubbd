#ifndef UBBD_BACKEND_H
#define UBBD_BACKEND_H
#include <libssh/sftp.h>

#include "ubbd_dev.h"
#include "ubbd_queue.h"
#include "ubbd_config.h"

struct ubbd_backend;
struct ubbd_backend_ops {
	int (*open) (struct ubbd_backend *ubbd_b);
	void (*close) (struct ubbd_backend *ubbd_b);
	void (*release) (struct ubbd_backend *ubbd_b);
	int (*writev) (struct ubbd_queue *ubbd_q, struct ubbd_se *se);
	int (*readv) (struct ubbd_queue *ubbd_q, struct ubbd_se *se);
	int (*flush) (struct ubbd_queue *ubbd_q, struct ubbd_se *se);
	int (*discard) (struct ubbd_queue *ubbd_q, struct ubbd_se *se);
	int (*write_zeros) (struct ubbd_queue *ubbd_q, struct ubbd_se *se);
};

enum ubbd_backend_status {
	UBBD_BACKEND_STATUS_INIT = 0,
	UBBD_BACKEND_STATUS_RUNNING,
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
};

struct ubbd_null_backend {
	struct ubbd_backend ubbd_b;
};

struct ubbd_file_backend {
	struct ubbd_backend ubbd_b;
	char filepath[PATH_MAX];
	int fd;
};

struct ubbd_rbd_backend {
	struct ubbd_backend ubbd_b;
	char pool[PATH_MAX];
	char imagename[PATH_MAX];
        rados_t cluster;
        char cluster_name[PATH_MAX];
        char user_name[PATH_MAX];
	rados_ioctx_t io_ctx;
	rbd_image_t image;
	uint64_t flags;
};

struct ubbd_ssh_backend {
	struct ubbd_backend ubbd_b;
	char hostname[PATH_MAX];
	char path[PATH_MAX];
	struct sftp_file_struct *sftp_file;
	pthread_mutex_t			lock;
};

struct ubbd_backend *ubbd_backend_create(struct ubbd_backend_conf *backend_conf);
void ubbd_backend_release(struct ubbd_backend *ubbd_b);
int ubbd_backend_start(struct ubbd_backend *ubbd_b, bool start_queues);
void ubbd_backend_stop(struct ubbd_backend *ubbd_b);
int ubbd_backend_open(struct ubbd_backend *ubbd_b);
void ubbd_backend_close(struct ubbd_backend *ubbd_b);
void ubbd_backend_wait_stopped(struct ubbd_backend *ubbd_b);
int ubbd_backend_stop_queue(struct ubbd_backend *ubbd_b, int queue_id);
int ubbd_backend_start_queue(struct ubbd_backend *ubbd_b, int queue_id);

extern struct ubbd_backend_ops rbd_backend_ops;
extern struct ubbd_backend_ops file_backend_ops;
extern struct ubbd_backend_ops null_backend_ops;
extern struct ubbd_backend_ops ssh_backend_ops;
#endif /* UBBD_BACKEND_H */
