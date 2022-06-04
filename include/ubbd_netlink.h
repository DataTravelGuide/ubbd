#ifndef UBBD_NETLINK_H
#define UBBD_NETLINK_H
#include <libnl3/netlink/errno.h>

#include "ubbd_queue.h"
#include "ubbd_dev.h"
#include "list.h"
#include "ubbd_limits.h"

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

struct ubbd_nl_dev_status {
	int32_t	dev_id;
	uint8_t	status;
	int	num_queues;
	struct ubbd_queue_info queue_infos[UBBD_QUEUE_MAX];
};

struct ubbd_nl_list_result {
	int num_devs;
	int dev_ids[UBBD_DEV_MAX];
};

int ubbd_nl_req_add_dev(struct ubbd_device *ubbd_dev, struct context *ctx);
int ubbd_nl_req_add_disk(struct ubbd_device *ubbd_dev, struct context *ctx);
int ubbd_nl_req_remove_disk(struct ubbd_device *ubbd_dev, bool force, struct context *ctx);
int ubbd_nl_req_remove_dev(struct ubbd_device *ubbd_dev, struct context *ctx);
int ubbd_nl_req_config(struct ubbd_device *ubbd_dev, int data_pages_reserve, struct context *ctx);
int ubbd_nl_start_thread(void);
void ubbd_nl_stop_thread(void);
int ubbd_nl_wait_thread(void);
int ubbd_nl_dev_list(struct ubbd_nl_list_result *result);
int ubbd_nl_dev_status(int dev_id, struct ubbd_nl_dev_status *dev_status);
int ubbd_nl_stop_queue(struct ubbd_device *ubbd_dev, int queue_id);
int ubbd_nl_start_queue(struct ubbd_device *ubbd_dev, int queue_id);
#endif	/* UBBD_NETLINK_H */
