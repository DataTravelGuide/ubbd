#ifndef UBBDD_MGMT_H
#define UBBDD_MGMT_H

#include "utils.h"
#include "ubbd_dev.h"
#include "ubbd_queue.h"
#include "ubbd_base_mgmt.h"

#define UBBDD_MGMT_NAMESPACE      "UBBDD_MGMT_ABSTRACT_NAMESPACE"
#define UBBD_DEV_MAX	1024

enum ubbdd_mgmt_cmd {
	UBBDD_MGMT_CMD_MAP,
	UBBDD_MGMT_CMD_UNMAP,
	UBBDD_MGMT_CMD_CONFIG,
	UBBDD_MGMT_CMD_LIST,
	UBBDD_MGMT_CMD_REQ_STATS,
	UBBDD_MGMT_CMD_REQ_STATS_RESET,
	UBBDD_MGMT_CMD_DEV_RESTART,
};

struct ubbdd_mgmt_request {
	enum ubbdd_mgmt_cmd cmd;
	union {
		struct {
			struct ubbd_dev_info info;
		} add;
		struct {
			int dev_id;
			bool force;
		} remove;
		struct {
			int dev_id;
			int data_pages_reserve;
		} config;
		struct {
		} list;
		struct {
			int dev_id;
		} req_stats;
		struct {
			int dev_id;
		} req_stats_reset;
		struct {
			int dev_id;
			int restart_mode;
		} dev_restart;
	} u;
};

struct ubbdd_mgmt_rsp {
	/* ret must be the first member */
	int ret;
	union {
		struct {
			char path[PATH_MAX];
		} add;
		struct {
			int dev_num;
			int dev_list[UBBD_DEV_MAX];
		} list;
		struct {
			int num_queues;
			struct ubbd_req_stats req_stats[UBBD_QUEUE_MAX];
		} req_stats;
	} u;
};

int ubbdd_request(int *fd, struct ubbdd_mgmt_request *req);
int ubbdd_response(int fd, struct ubbdd_mgmt_rsp *rsp,
		    int timeout);
int ubbdd_mgmt_start_thread(void);
void ubbdd_mgmt_stop_thread(void);
int ubbdd_mgmt_wait_thread(void);
#endif	/* UBBDD_MGMT_H */
