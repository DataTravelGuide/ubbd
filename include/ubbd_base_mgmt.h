#ifndef UBBD_BASE_MGMT_H
#define UBBD_BASE_MGMT_H
#include <sys/un.h>

#include "utils.h"

struct ubbd_response {
	int ret;
};

int ubbd_ipc_listen(char *sock_name);
int ubbd_ipc_read_data(int fd, void *ptr, size_t len);
int ubbd_response(int fd, void *rsp, size_t len,
		    int timeout);
int ubbd_request(int *fd, char *sock_name, void *req, size_t len);
int ubbd_ipc_read_data(int fd, void *ptr, size_t len);
#endif /* UBBD_BASE_MGMT_H */
