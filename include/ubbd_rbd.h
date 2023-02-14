#ifndef UBBD_RBD_H
#define UBBD_RBD_H

#include <rados/librados.h>
#include <rbd/librbd.h>
#include "libubbd.h"

struct ubbd_rbd_conn {
	char ceph_conf[UBBD_NAME_MAX];
	char pool[UBBD_NAME_MAX];
	char ns[UBBD_NAME_MAX];
	char imagename[UBBD_NAME_MAX];
        char cluster_name[UBBD_NAME_MAX];
        char user_name[UBBD_NAME_MAX];
        rados_t cluster;
	rados_ioctx_t io_ctx;
	rbd_image_t image;
	uint64_t flags;
	int io_timeout;
};

int ubbd_rbd_conn_open(struct ubbd_rbd_conn *rbd_conn);
int ubbd_rbd_get_size(struct ubbd_rbd_conn *rbd_conn, uint64_t *dev_size);
void ubbd_rbd_conn_close(struct ubbd_rbd_conn *rbd_conn);
#endif
