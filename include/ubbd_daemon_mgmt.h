#ifndef UBBDD_MGMT_H
#define UBBDD_MGMT_H

#include "utils.h"
#include "ubbd_dev.h"
#include "ubbd_queue.h"
#include "ubbd_base_mgmt.h"
#include "libubbd.h"

#define UBBDD_MGMT_NAMESPACE      "UBBDD_MGMT_ABSTRACT_NAMESPACE"

enum ubbdd_mgmt_cmd {
	UBBDD_MGMT_CMD_MAP,
	UBBDD_MGMT_CMD_UNMAP,
	UBBDD_MGMT_CMD_CONFIG,
	UBBDD_MGMT_CMD_LIST,
	UBBDD_MGMT_CMD_REQ_STATS,
	UBBDD_MGMT_CMD_REQ_STATS_RESET,
	UBBDD_MGMT_CMD_DEV_RESTART,
	UBBDD_MGMT_CMD_DEV_INFO,
};

struct ubbdd_mgmt_request {
	enum ubbdd_mgmt_cmd cmd;
	union {
		struct {
			enum ubbd_dev_type dev_type;
			struct ubbd_dev_info info;
			struct ubbd_dev_info extra_info;
			union {
				struct {
					int cache_mode;
				} cache;
			};
		} add;
		struct {
			int dev_id;
			bool force;
			bool detach;
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
		struct {
			int dev_id;
		} dev_info;
	} u;
};

int ubbdd_request(int *fd, struct ubbdd_mgmt_request *req);
int ubbdd_response(int fd, struct ubbdd_mgmt_rsp *rsp,
		    int timeout);

int ubbdd_mgmt_start_thread(void);
void ubbdd_mgmt_stop_thread(void);
int ubbdd_mgmt_wait_thread(void);
#endif	/* UBBDD_MGMT_H */
