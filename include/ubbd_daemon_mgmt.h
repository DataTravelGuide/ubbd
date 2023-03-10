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

struct ubbdd_mgmt_request_header {
	uint64_t		magic;
	uint32_t		version;
};

struct ubbdd_mgmt_request {
	struct ubbdd_mgmt_request_header header;
	enum ubbdd_mgmt_cmd	cmd;
	union {
		struct {
			struct ubbd_dev_info info;
		} add;
		struct {
			int dev_id;
			bool force;
			bool detach;
		} remove;
		struct {
			int dev_id;
			int data_pages_reserve_percnt;
		} config;
		struct {
			enum ubbd_dev_type type;
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

static inline int ubbdd_request(int *fd, struct ubbdd_mgmt_request *req)
{
	return ubbd_request(fd, UBBDD_MGMT_NAMESPACE, req, sizeof(*req));
}

static inline int ubbdd_response(int fd, struct ubbdd_mgmt_rsp *rsp,
		    int timeout)
{
	return ubbd_response(fd, rsp, sizeof(*rsp), timeout);
}

#define UBBDD_MGMT_REQ_MAGIC	0xa3b15aULL
#define UBBDD_MGMT_REQ_VERSION	1

static inline void ubbd_request_header_init(struct ubbdd_mgmt_request_header *hdr)
{
	hdr->magic = UBBDD_MGMT_REQ_MAGIC;
	hdr->version = UBBDD_MGMT_REQ_VERSION;
}

int ubbdd_mgmt_start_thread(void);
void ubbdd_mgmt_stop_thread(void);
int ubbdd_mgmt_wait_thread(void);
#endif	/* UBBDD_MGMT_H */
