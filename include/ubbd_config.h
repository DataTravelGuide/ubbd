#ifndef UBBD_CONF_H
#define UBBD_CONF_H
#include <linux/types.h>
#include "utils.h"
#include "libubbd.h"

#define UBBD_CONFIG_MAGIC	0x9a6c65b05efaULL

struct ubbd_conf_header {
	__u64		magic;
	__u32		version;
	__u32		conf_type;
};

#define UBBD_CONF_TYPE_BACKEND		1
#define UBBD_CONF_TYPE_DEVICE		2

#define UBBD_CONF_TYPE_RBD_BACKEND	1
#define UBBD_CONF_TYPE_FILE_BACKEND	2
#define UBBD_CONF_TYPE_NULL_BACKEND	3

struct ubbd_dev_conf {
	struct ubbd_conf_header conf_header;
	enum ubbd_dev_type dev_type;
	int dev_id;
	int num_queues;
	struct ubbd_dev_info dev_info;
	/* current_backend_id is current running backend id, id will be 
	 * used as part of namespace name for backend mgmt ipc.
	 *
	 * new_backend_id will be used in upgrading, then we can upgrade
	 * backend queue-by-queue.
	 *
	 * new_backend_id == -1 means not being upgrading */
	int current_backend_id;
	int new_backend_id;
	int cache_mode;
};

struct ubbd_backend_conf {
	struct ubbd_conf_header conf_header;
	enum ubbd_dev_type dev_type;
	uint64_t dev_size;
	int dev_id;
	struct ubbd_dev_info dev_info;
	int num_queues;
	struct ubbd_queue_info queue_infos[UBBD_QUEUE_MAX];
	int cache_mode;
};

static inline void ubbd_conf_header_init(struct ubbd_conf_header *header, int conf_type)
{
	header->magic = UBBD_CONFIG_MAGIC;
	header->version = 0;
	header->conf_type = conf_type;
}

int ubbd_conf_write_backend_conf(struct ubbd_backend_conf *conf);
struct ubbd_backend_conf *ubbd_conf_read_backend_conf(int dev_id);

int ubbd_conf_write_dev_conf(struct ubbd_dev_conf *conf);
struct ubbd_dev_conf *ubbd_conf_read_dev_conf(int dev_id);
#endif /* UBBD_CONF_H */
