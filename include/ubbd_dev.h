#ifndef UBBD_DEV_H
#define UBBD_DEV_H

#include <rbd/librbd.h>
#include <stdlib.h>
#include <pthread.h>

#include "ubbd.h"
#include "ubbd_log.h"
#include "utils.h"
#include "list.h"

#define POOL_MAX	1024
#define IMAGE_MAX	1024

enum ubbd_dev_type {
	UBBD_DEV_TYPE_FILE,
	UBBD_DEV_TYPE_RBD
};

enum ubbd_dev_status {
	UBBD_DEV_STATUS_CREATED,
	UBBD_DEV_STATUS_ADD_PREPARED,
	UBBD_DEV_STATUS_ADDED,
	UBBD_DEV_STATUS_REMOVE_PREPARED,
	UBBD_DEV_STATUS_REMOVED
};

struct ubbd_dev_info {
	enum ubbd_dev_type type;
	union {
		struct {
			char path[PATH_MAX];
			uint64_t size;
		} file;
		struct {
			char pool[POOL_MAX];
			char image[IMAGE_MAX];
		} rbd;
	};
};

struct ubbd_dev_features {
	bool	write_cache;
	bool	fua;
	bool	discard;
	bool	write_zeros;
};

struct ubbd_device {
	int fd;

	int32_t dev_id;
	uint32_t uio_id;
	uint64_t uio_map_size;
	struct list_head dev_node;
	uint64_t dev_size;
	enum ubbd_dev_type dev_type;
	struct ubbd_dev_ops *dev_ops;
	struct ubbd_dev_info dev_info;
	uint32_t se_to_handle;

	struct ubbd_sb *map;
	pthread_t cmdproc_thread;

	char dev_name[16];

	enum ubbd_dev_status status;
	pthread_mutex_t lock;

	struct ubbd_dev_features dev_features;
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


struct ubbd_dev_ops {
	void (*release) (struct ubbd_device *ubbd_dev);
	int (*open) (struct ubbd_device *ubbd_dev);
	int (*writev) (struct ubbd_device *ubbd_dev, struct ubbd_se *se);
	int (*readv) (struct ubbd_device *ubbd_dev, struct ubbd_se *se);
	int (*flush) (struct ubbd_device *ubbd_dev, struct ubbd_se *se);
	int (*discard) (struct ubbd_device *ubbd_dev, struct ubbd_se *se);
	int (*write_zeros) (struct ubbd_device *ubbd_dev, struct ubbd_se *se);
};


static inline struct ubbd_ce *
device_comp_head(struct ubbd_device *dev)
{
	struct ubbd_sb *sb = dev->map;

	ubbd_dbg("comp: head: %u\n", sb->compr_head);

	return (struct ubbd_ce *) ((char *) sb + sb->compr_off + sb->compr_head);
}

struct ubbd_ce *get_available_ce(struct ubbd_device *dev);

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

struct ubbd_device *find_ubbd_dev(int dev_id);
struct ubbd_rbd_device *create_rbd_dev(void);
struct ubbd_file_device *create_file_dev(void);
struct ubbd_device *ubbd_dev_create(struct ubbd_dev_info *info);
int ubbd_dev_open(struct ubbd_device *ubbd_dev);
int ubbd_dev_add(struct ubbd_device *ubbd_dev);
int ubbd_dev_remove(struct ubbd_device *ubbd_dev, bool force);
int ubbd_dev_config(struct ubbd_device *ubbd_dev, int data_pages_reserve);

int ubd_dev_reopen_devs(void);

int device_open_shm(struct ubbd_device *ubbd_dev);
int device_close_shm(struct ubbd_device *ubbd_dev);
void ubbd_dev_release(struct ubbd_device *ubbd_dev);

void *cmd_process(void *arg);

struct ubbd_dev_ops rbd_dev_ops;
struct ubbd_dev_ops file_dev_ops;
#endif	/* UBBD_DEV_H */
