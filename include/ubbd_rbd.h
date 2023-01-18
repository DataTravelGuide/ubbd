#ifndef UBBD_RBD_H
#define UBBD_RBD_H

#include <rados/librados.h>
#include <rbd/librbd.h>
#include <limits.h>

struct ubbd_rbd_conn {
	char ceph_conf[PATH_MAX];
	char pool[PATH_MAX];
	char imagename[PATH_MAX];
        char cluster_name[PATH_MAX];
        char user_name[PATH_MAX];
        rados_t cluster;
	rados_ioctx_t io_ctx;
	rbd_image_t image;
	uint64_t flags;
};

int ubbd_rbd_conn_open(struct ubbd_rbd_conn *rbd_conn);
int ubbd_rbd_get_size(struct ubbd_rbd_conn *rbd_conn, uint64_t *dev_size);
void ubbd_rbd_conn_close(struct ubbd_rbd_conn *rbd_conn);
#endif
