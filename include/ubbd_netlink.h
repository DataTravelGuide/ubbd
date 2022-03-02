#ifndef UBBD_NETLINK_H
#define UBBD_NETLINK_H
#include "ubbd_dev.h"
#include "list.h"

enum ubbd_nl_req_type {
	UBBD_NL_REQ_ADD_PREPARE,
	UBBD_NL_REQ_ADD,
	UBBD_NL_REQ_REMOVE_PREPARE,
	UBBD_NL_REQ_REMOVE,
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
	struct list_head node;
};

struct ubbd_nl_dev_status {
	struct list_head node;
	int32_t	dev_id;
	int32_t	uio_id;
	uint64_t uio_map_size;
	uint8_t	status;
};

void ubbd_nl_req_add(struct ubbd_device *ubbd_dev);
void ubbd_nl_req_remove(struct ubbd_device *ubbd_dev, bool force);
void ubbd_nl_req_config(struct ubbd_device *ubbd_dev, int data_pages_reserve);
int start_netlink_thread(pthread_t *t);
int ubbd_nl_dev_list(struct list_head *dev_list);
#endif	/* UBBD_NETLINK_H */
