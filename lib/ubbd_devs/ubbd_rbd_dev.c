#include <rados/librados.h>
#include <pthread.h>

#include "ubbd_dev.h"
#include "ubbd_uio.h"

// rbd ops
#define RBD_DEV(ubbd_dev) ((struct ubbd_rbd_device *)container_of(ubbd_dev, struct ubbd_rbd_device, ubbd_dev))

struct ubbd_dev_ops rbd_dev_ops;

static struct ubbd_device *rbd_dev_create(struct __dev_info *info)
{
	struct ubbd_rbd_device *rbd_dev;
	struct ubbd_rbd_conn *rbd_conn;
	struct ubbd_device *ubbd_dev;

	rbd_dev = calloc(1, sizeof(*rbd_dev));
	if (!rbd_dev)
		return NULL;

	ubbd_dev = &rbd_dev->ubbd_dev;
	ubbd_dev->dev_type = UBBD_DEV_TYPE_RBD;
	ubbd_dev->dev_ops = &rbd_dev_ops;

	rbd_conn = &rbd_dev->rbd_conn;
	strcpy(rbd_conn->pool, info->rbd.pool);
	strcpy(rbd_conn->imagename, info->rbd.image);
	strcpy(rbd_conn->ceph_conf, info->rbd.ceph_conf);
	strcpy(rbd_conn->user_name, info->rbd.user_name);
	strcpy(rbd_conn->cluster_name, info->rbd.cluster_name);

	return ubbd_dev;
}

static int rbd_dev_init(struct ubbd_device *ubbd_dev)
{
	struct ubbd_rbd_device *rbd_dev = RBD_DEV(ubbd_dev);
	struct ubbd_rbd_conn *rbd_conn = &rbd_dev->rbd_conn;
        int ret;

	ret = ubbd_rbd_conn_open(rbd_conn);
	if (ret < 0) {
		ubbd_dev_err(ubbd_dev, "failed to open rbd connection: %s", strerror(-ret));
		goto out;
	}

	ret = ubbd_rbd_get_size(rbd_conn, &ubbd_dev->dev_size);
        if (ret < 0) {
                ubbd_dev_err(ubbd_dev, "failed to get image size: %s\n",  strerror(-ret));
		goto close_rbd;
        } else {
                ubbd_dev_info(ubbd_dev, "\nimage get size: %lu.\n", ubbd_dev->dev_size);
        }

	ubbd_dev->dev_features.write_cache = false;
	ubbd_dev->dev_features.fua = false;
	ubbd_dev->dev_features.discard = true;
#ifdef LIBRBD_SUPPORTS_WRITE_ZEROES
	ubbd_dev->dev_features.write_zeros = true;
#else
	ubbd_dev->dev_features.write_zeros = false;
#endif
	ret = 0;

close_rbd:
	ubbd_rbd_conn_close(rbd_conn);
out:
	return ret;
}

static void rbd_dev_release(struct ubbd_device *ubbd_dev)
{
	struct ubbd_rbd_device *rbd_dev = RBD_DEV(ubbd_dev);

	free(rbd_dev);
}

struct ubbd_dev_ops rbd_dev_ops = {
	.create = rbd_dev_create,
	.init = rbd_dev_init,
	.release = rbd_dev_release,
};
