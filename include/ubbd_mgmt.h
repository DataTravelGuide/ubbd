#ifndef UBBD_MGMT_H
#define UBBD_MGMT_H

#include "utils.h"
#include "ubbd_dev.h"

#define UBBD_MGMT_NAMESPACE      "UBBD_MGMT_ABSTRACT_NAMESPACE"

enum ubbd_mgmt_cmd {
	UBBD_MGMT_CMD_MAP,
	UBBD_MGMT_CMD_UNMAP,
	UBBD_MGMT_CMD_CONFIG
};

struct ubbd_mgmt_request {
	enum ubbd_mgmt_cmd cmd;
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
	} u;
};

struct ubbd_mgmt_rsp {
	int ret;
	union {
		struct {
			char path[PATH_MAX];
		} add;
	} u;
};

int ubbdd_request(int *fd, struct ubbd_mgmt_request *req);
int ubbdd_response(int fd, struct ubbd_mgmt_rsp *rsp,
		    int timeout);
int ubbd_mgmt_start_thread(pthread_t *t);
void ubbd_mgmt_stop_thread(void);

#endif	/* UBBD_MGMT_H */
