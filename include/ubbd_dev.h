#ifndef UBBD_DEV_H
#define UBBD_DEV_H

#include <rbd/librbd.h>
#include <pthread.h>

#include "ubbd.h"
#include "ubbd_log.h"
#include "ubbd_queue.h"
#include "utils.h"
#include "list.h"
#include "libubbd.h"
#include "ubbd_rbd.h"

#define UBBD_DEV_RESTART_MODE_DEFAULT	0
#define UBBD_DEV_RESTART_MODE_DEV	1
#define UBBD_DEV_RESTART_MODE_QUEUE	2


enum ubbd_dev_ustatus {
	UBBD_DEV_USTATUS_INIT,
	UBBD_DEV_USTATUS_OPENED,
	UBBD_DEV_USTATUS_PREPARED,
	UBBD_DEV_USTATUS_RUNNING,
	UBBD_DEV_USTATUS_STOPPING,
	UBBD_DEV_USTATUS_ERROR,
};

struct ubbd_dev_features {
	bool	write_cache;
	bool	fua;
	bool	discard;
	bool	write_zeros;
};


struct ubbd_device;
struct ubbd_dev_ops {
	struct ubbd_device* (*create) (struct __dev_info *info);
	int (*init) (struct ubbd_device *ubbd_dev);
	void (*release) (struct ubbd_device *ubbd_dev);
};

struct ubbd_device {
	int32_t dev_id;
	struct list_head dev_node;
	uint64_t dev_size;
	uint32_t io_timeout;
	enum ubbd_dev_type dev_type;
	struct ubbd_dev_info dev_info;
	int cache_mode;
	char dev_name[16];
	struct ubbd_dev_ops *dev_ops;
	uint32_t sh_mem_size;

	enum ubbd_dev_ustatus status;
	pthread_mutex_t lock;

	int num_queues;
	struct ubbd_dev_features dev_features;
	ubbd_atomic	ref_count;
	/* current_backend_id is current running backend id, id will be 
	 * used as part of namespace name for backend mgmt ipc.
	 *
	 * new_backend_id will be used in upgrading, then we can upgrade
	 * backend queue-by-queue.
	 *
	 * new_backend_id == -1 means not being upgrading */
	int current_backend_id;
	int new_backend_id;
	struct ubbd_queue_info queue_infos[UBBD_QUEUE_MAX];
};

struct ubbd_request {
	uint64_t	start_ns;
	uint64_t	handled_ns;
};

struct ubbd_file_device {
	struct ubbd_device ubbd_dev;
	char filepath[UBBD_PATH_MAX];
	int fd;
};

struct ubbd_rbd_device {
	struct ubbd_device ubbd_dev;
	struct ubbd_rbd_conn rbd_conn;
};

struct ubbd_null_device {
	struct ubbd_device ubbd_dev;
};

struct ubbd_ssh_device {
	struct ubbd_device ubbd_dev;
};

struct ubbd_cache_device {
	struct ubbd_device ubbd_dev;
	struct ubbd_device *backing_device;
	struct ubbd_device *cache_device;
	int cache_mode;
};

#define CACHE_DEV(ubbd_dev) ((struct ubbd_cache_device *)container_of(ubbd_dev, struct ubbd_cache_device, ubbd_dev))

struct ubbd_s3_device {
	struct ubbd_device ubbd_dev;
};

bool ubbd_dev_get(struct ubbd_device *ubbd_dev);
void ubbd_dev_put(struct ubbd_device *ubbd_dev);

struct ubbd_device *find_ubbd_dev(int dev_id);
struct ubbd_device *ubbd_dev_create(struct ubbd_dev_info *info, bool force);
int ubbd_dev_init(struct ubbd_device *ubbd_dev);
struct ubbd_device *ubbd_cache_dev_create(struct ubbd_dev_info *backing_dev_info,
		struct ubbd_dev_info *cache_dev_info, int cache_mode, bool force);
int ubbd_dev_restart(struct ubbd_device *ubbd_dev, int restart_mode);
int ubbd_dev_add(struct ubbd_device *ubbd_dev, struct context *ctx);
int ubbd_dev_remove(struct ubbd_device *ubbd_dev, bool force, bool detach, struct context *ctx);
int ubbd_dev_config(struct ubbd_device *ubbd_dev, int data_pages_reserve_percnt, struct context *ctx);

struct ubbd_nl_dev_status;
int ubbd_dev_init_from_dev_status(struct ubbd_device *ubbd_dev, struct ubbd_nl_dev_status *dev_status);
int ubbd_dev_reopen_devs(void);
void ubbd_dev_stop_devs(void);
void ubbd_dev_release(struct ubbd_device *ubbd_dev);

int ubbd_dev_checker_start_thread();
void ubbd_dev_checker_stop_thread(void);
int ubbd_dev_checker_wait_thread(void);
#endif	/* UBBD_DEV_H */
