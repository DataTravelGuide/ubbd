#ifndef UBBD_BACKEND_MGMT_H
#define UBBD_BACKEND_MGMT_H

#include "utils.h"
#include "ubbd_queue.h"
#include "ubbd_backend.h"
#include "ubbd_base_mgmt.h"

static inline char *get_backend_mgmt_ns(int dev_id, int backend_id)
{
	char *backend_mgmt_ns;

	if (asprintf(&backend_mgmt_ns, "UBBD%d_BACKEND%d_MGMT_ABSTRACT_NAMESPACE", dev_id, backend_id) == -1) {
		ubbd_err("setup backend mgmt ns failed.\n");
		return NULL;
	}

	return backend_mgmt_ns;
}

enum ubbd_backend_mgmt_cmd {
	UBBD_BACKEND_MGMT_CMD_STOP,
	UBBD_BACKEND_MGMT_CMD_GET_STATUS,
	UBBD_BACKEND_MGMT_CMD_STOP_QUEUE,
	UBBD_BACKEND_MGMT_CMD_START_QUEUE,
	UBBD_BACKEND_MGMT_CMD_GET_QUEUE_STATUS,
	UBBD_BACKEND_MGMT_CMD_REQ_STATS,
	UBBD_BACKEND_MGMT_CMD_REQ_STATS_RESET,
};

struct ubbd_backend_mgmt_request {
	int dev_id;
	int backend_id;
	enum ubbd_backend_mgmt_cmd cmd;
	union {
		struct {
			int queue_id;
		} stop_queue;
		struct {
			int queue_id;
		} start_queue;
		struct {
			int queue_id;
		} get_queue_status;
	} u;
};

struct ubbd_backend_mgmt_rsp {
	/* ret must be the first member */
	int ret;
	union {
		struct {
			int status;
		} get_status;
		struct {
			int status;
		} get_queue_status;
		struct {
			int num_queues;
			struct ubbd_req_stats req_stats[UBBD_QUEUE_MAX];
		} req_stats;
	} u;
};

int ubbd_backend_request(int *fd, struct ubbd_backend_mgmt_request *req);
int ubbd_backend_response(int fd, struct ubbd_backend_mgmt_rsp *rsp,
		    int timeout);
int ubbd_backend_mgmt_start_thread(struct ubbd_backend *backend);
void ubbd_backend_mgmt_stop_thread(void);
int ubbd_backend_mgmt_wait_thread(void);
#endif	/* UBBD_BACKEND_MGMT_H */
