#include <rados/librados.h>
#include <pthread.h>

#include "ubbd_dev.h"
#include "ubbd_uio.h"

// rbd ops
#define RBD_DEV(ubbd_dev) ((struct ubbd_rbd_device *)container_of(ubbd_dev, struct ubbd_rbd_device, ubbd_dev))

static int rbd_dev_init(struct ubbd_device *ubbd_dev)
{
	struct ubbd_rbd_device *rbd_dev = RBD_DEV(ubbd_dev);
        int err;

        err = rados_create2(&rbd_dev->cluster, "ceph", "client.admin", rbd_dev->flags);
        if (err < 0) {
                ubbd_dev_err(ubbd_dev, "Couldn't create the cluster handle! %s\n", strerror(-err));
                return err;
        } else {
                ubbd_dev_info(ubbd_dev, "\nCreated a cluster handle.\n");
        }

        /* Read a Ceph configuration file to configure the cluster handle. */
        err = rados_conf_read_file(rbd_dev->cluster, ubbd_dev->dev_info.rbd.ceph_conf);
        if (err < 0) {
                ubbd_dev_err(ubbd_dev, "cannot read config file: %s\n", strerror(-err));
		goto shutdown_cluster;
        } else {
                ubbd_dev_info(ubbd_dev, "\nRead the config file.\n");
        }

	rados_conf_set(rbd_dev->cluster, "rbd_cache", "false");
        /* Connect to the cluster */
        err = rados_connect(rbd_dev->cluster);
        if (err < 0) {
                ubbd_dev_err(ubbd_dev, "cannot connect to cluster: %s\n",  strerror(-err));
		goto shutdown_cluster;
        } else {
                ubbd_dev_info(ubbd_dev, "\nConnected to the cluster.\n");
        }

	err = rados_ioctx_create(rbd_dev->cluster, rbd_dev->pool, &rbd_dev->io_ctx);
        if (err < 0) {
                ubbd_dev_err(ubbd_dev, "cannot create ioctx to %s pool: %s\n", rbd_dev->pool, strerror(-err));
		goto shutdown_cluster;
        } else {
                ubbd_dev_info(ubbd_dev, "\nioctx created.\n");
        }

	err = rbd_open(rbd_dev->io_ctx, rbd_dev->imagename, &rbd_dev->image, NULL);
        if (err < 0) {
                ubbd_dev_err(ubbd_dev, "cannot open image(%s): %s\n", rbd_dev->imagename, strerror(-err));
		goto destroy_ioctx;
        } else {
                ubbd_dev_info(ubbd_dev, "\nimage opened.\n");
        }

	err = rbd_get_size(rbd_dev->image, &ubbd_dev->dev_size);
        if (err < 0) {
                ubbd_dev_err(ubbd_dev, "cannot get image size: %s\n",  strerror(-err));
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
	err = 0;

close_rbd:
	rbd_close(rbd_dev->image);
destroy_ioctx:
	rados_ioctx_destroy(rbd_dev->io_ctx);
shutdown_cluster:
	rados_shutdown(rbd_dev->cluster);

	return err;
}

static void rbd_dev_release(struct ubbd_device *ubbd_dev)
{
	struct ubbd_rbd_device *rbd_dev = RBD_DEV(ubbd_dev);

	free(rbd_dev);
}

struct ubbd_dev_ops rbd_dev_ops = {
	.init = rbd_dev_init,
	.release = rbd_dev_release,
};


