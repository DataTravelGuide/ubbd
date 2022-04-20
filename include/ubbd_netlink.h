#ifndef UBBD_NETLINK_H
#define UBBD_NETLINK_H
#include "ubbd_dev.h"
#include "list.h"

enum ubbd_nl_req_type {
	UBBD_NL_REQ_ADD_DEV,
	UBBD_NL_REQ_ADD_DISK,
	UBBD_NL_REQ_REMOVE_DEV,
	UBBD_NL_REQ_REMOVE_DISK,
	UBBD_NL_REQ_CONFIG,
};

struct ubbd_nl_req {
	enum ubbd_nl_req_type type;
	union req_options {
		struct add_options {
			bool write_cache;
		} add_opts;
		struct remove_options {
			bool force;
		} remove_opts;
		struct config_options {
			int data_pages_reserve;
		} config_opts;
	} req_opts;
	struct ubbd_device *ubbd_dev;
	struct context *ctx;
	struct list_head node;
};

struct ubbd_nl_queue_info {
	int32_t	uio_id;
	uint64_t uio_map_size;
};

struct ubbd_nl_dev_status {
	struct list_head node;
	int32_t	dev_id;
	uint8_t	status;
	int	num_queues;
	struct ubbd_nl_queue_info *queue_infos;
};

int ubbd_nl_req_add_dev(struct ubbd_device *ubbd_dev, struct context *ctx);
int ubbd_nl_req_add_disk(struct ubbd_device *ubbd_dev, struct context *ctx);
int ubbd_nl_req_remove_disk(struct ubbd_device *ubbd_dev, bool force, struct context *ctx);
int ubbd_nl_req_remove_dev(struct ubbd_device *ubbd_dev, struct context *ctx);
int ubbd_nl_req_config(struct ubbd_device *ubbd_dev, int data_pages_reserve, struct context *ctx);
int ubbd_nl_start_thread(pthread_t *t);
void ubbd_nl_stop_thread(void);
int ubbd_nl_dev_list(struct list_head *dev_list);
#endif	/* UBBD_NETLINK_H */
