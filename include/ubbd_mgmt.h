#ifndef UBBD_MGMT_H
#define UBBD_MGMT_H

#include "utils.h"
#include "ubbd_dev.h"

#define UBBD_MGMT_NAMESPACE      "UBBD_MGMT_ABSTRACT_NAMESPACE"

enum ubbd_mgmt_cmd {
	UBBD_MGMT_CMD_MAP,
	UBBD_MGMT_CMD_UNMAP
};

struct ubbd_mgmt_request {
	enum ubbd_mgmt_cmd cmd;
	union {
		struct {
			struct ubbd_dev_info info;
		} add;
		struct {
			int dev_id;
		} remove;
	} u;
};

struct ubbd_mgmt_rsp {
	int ret;
};

int ubbdd_request(int *fd, struct ubbd_mgmt_request *req);
int start_mgmt_thread(pthread_t *t);

#endif	/* UBBD_MGMT_H */
