#ifndef UBBD_DEV_H
#define UBBD_DEV_H

#include <rbd/librbd.h>
#include <pthread.h>

#include "ubbd.h"
#include "ubbd_log.h"
#include "utils.h"
#include "list.h"

#define POOL_MAX	1024
#define IMAGE_MAX	1024

enum ubbd_dev_type {
	UBBD_DEV_TYPE_FILE,
	UBBD_DEV_TYPE_RBD,
	UBBD_DEV_TYPE_NULL
};

enum ubbd_dev_ustatus {
	UBBD_DEV_USTATUS_INIT,
	UBBD_DEV_USTATUS_OPENED,
	UBBD_DEV_USTATUS_PREPARED,
	UBBD_DEV_USTATUS_RUNNING,
	UBBD_DEV_USTATUS_STOPPING,
};

struct ubbd_dev_info {
	enum ubbd_dev_type type;
	uint32_t num_queues;
	union {
		struct {
			char path[PATH_MAX];
			uint64_t size;
		} file;
		struct {
			char pool[POOL_MAX];
			char image[IMAGE_MAX];
		} rbd;
		struct {
			uint64_t size;
		} null;
	};
};

struct ubbd_dev_features {
	bool	write_cache;
	bool	fua;
	bool	discard;
	bool	write_zeros;
};

struct ubbd_uio_info {
	int fd;
	uint32_t uio_id;
	uint64_t uio_map_size;
	struct ubbd_sb *map;
};

struct ubbd_queue {
	struct ubbd_device *ubbd_dev;
	uint32_t se_to_handle;

	struct ubbd_uio_info uio_info;
	pthread_t cmdproc_thread;

	pthread_mutex_t req_lock;

	cpu_set_t cpuset;
};

struct ubbd_device {
	int32_t dev_id;
	struct list_head dev_node;
	uint64_t dev_size;
	enum ubbd_dev_type dev_type;
	struct ubbd_dev_info dev_info;
	char dev_name[16];
	struct ubbd_dev_ops *dev_ops;

	enum ubbd_dev_ustatus status;
	pthread_mutex_t lock;

	int num_queues;
	struct ubbd_queue *queues;

	struct ubbd_dev_features dev_features;

	ubbd_atomic	ref_count;
};

struct ubbd_file_device {
	struct ubbd_device ubbd_dev;
	char filepath[PATH_MAX];
	int fd;
};

struct ubbd_rbd_device {
	struct ubbd_device ubbd_dev;
	char pool[PATH_MAX];
	char imagename[PATH_MAX];
        rados_t cluster;
        char cluster_name[PATH_MAX];
        char user_name[PATH_MAX];
	rados_ioctx_t io_ctx;
	rbd_image_t image;
	uint64_t flags;
};

struct ubbd_null_device {
	struct ubbd_device ubbd_dev;
};

struct ubbd_dev_ops {
	int (*open) (struct ubbd_device *ubbd_dev);
	void (*close) (struct ubbd_device *ubbd_dev);
	void (*release) (struct ubbd_device *ubbd_dev);
	int (*writev) (struct ubbd_queue *ubbd_q, struct ubbd_se *se);
	int (*readv) (struct ubbd_queue *ubbd_q, struct ubbd_se *se);
	int (*flush) (struct ubbd_queue *ubbd_q, struct ubbd_se *se);
	int (*discard) (struct ubbd_queue *ubbd_q, struct ubbd_se *se);
	int (*write_zeros) (struct ubbd_queue *ubbd_q, struct ubbd_se *se);
};


static inline struct ubbd_ce *
device_comp_head(struct ubbd_queue *ubbd_q)
{
	struct ubbd_sb *sb = ubbd_q->uio_info.map;

	ubbd_dbg("comp: head: %u\n", sb->compr_head);

	return (struct ubbd_ce *) ((char *) sb + sb->compr_off + sb->compr_head);
}

struct ubbd_ce *get_available_ce(struct ubbd_queue *ubbd_q);

#define UBBD_UPDATE_DEV_TAIL(dev, sb, se) \
do { \
        sb->cmd_tail = (sb->cmd_tail + ubbd_se_hdr_get_len(se->header.len_op)) % sb->cmdr_size; \
	ubbd_dbg("cmd_tail: %u, cmd_head: %u\n", sb->cmd_tail, sb->cmd_head); \
} while (0)

#define UBBD_UPDATE_DEV_COMP_HEAD(dev, sb, ce) \
do { \
        sb->compr_head = (sb->compr_head + sizeof(struct ubbd_ce)) % sb->compr_size; \
	ubbd_dbg("compr_head: %u, compr_tail: %u\n", sb->compr_head, sb->compr_tail); \
} while (0)

#define UBBD_UPDATE_CMD_TO_HANDLE(dev, sb, len) \
do { \
        dev->se_to_handle = (dev->se_to_handle + len) % sb->cmdr_size; \
} while (0)

bool ubbd_dev_get(struct ubbd_device *ubbd_dev);
void ubbd_dev_put(struct ubbd_device *ubbd_dev);

struct ubbd_device *find_ubbd_dev(int dev_id);
struct ubbd_rbd_device *create_rbd_dev(void);
struct ubbd_file_device *create_file_dev(void);
struct ubbd_null_device *create_null_dev(void);
struct ubbd_device *ubbd_dev_create(struct ubbd_dev_info *info);
int ubbd_dev_open(struct ubbd_device *ubbd_dev);
int ubbd_dev_add(struct ubbd_device *ubbd_dev, struct context *ctx);
int ubbd_dev_remove(struct ubbd_device *ubbd_dev, bool force, struct context *ctx);
int ubbd_dev_config(struct ubbd_device *ubbd_dev, int data_pages_reserve, struct context *ctx);

int ubbd_dev_reopen_devs(void);
void ubbd_dev_stop_devs(void);

void ubbd_dev_add_ce(struct ubbd_queue *ubbd_q, uint64_t priv_data,
		int result);

void ubbd_dev_release(struct ubbd_device *ubbd_dev);

void *cmd_process(void *arg);

struct ubbd_dev_ops rbd_dev_ops;
struct ubbd_dev_ops file_dev_ops;
struct ubbd_dev_ops null_dev_ops;
#endif	/* UBBD_DEV_H */
