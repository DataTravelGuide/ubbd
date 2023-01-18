#include "ubbd_rbd.h"
#include "ubbd_log.h"

int ubbd_rbd_conn_open(struct ubbd_rbd_conn *rbd_conn)
{
        int err;

        err = rados_create2(&rbd_conn->cluster, "ceph", "client.admin", rbd_conn->flags);
        if (err < 0) {
                ubbd_err("Couldn't create the cluster handle! %s\n", strerror(-err));
                return err;
        } else {
                ubbd_info("\nCreated a cluster handle.\n");
        }

        /* Read a Ceph configuration file to configure the cluster handle. */
        err = rados_conf_read_file(rbd_conn->cluster, rbd_conn->ceph_conf);
        if (err < 0) {
                ubbd_err("cannot read config file: %s\n", strerror(-err));
		goto shutdown_cluster;
        } else {
                ubbd_info("\nRead the config file.\n");
        }

	rados_conf_set(rbd_conn->cluster, "rbd_cache", "false");
        /* Connect to the cluster */
        err = rados_connect(rbd_conn->cluster);
        if (err < 0) {
                ubbd_err("cannot connect to cluster: %s\n",  strerror(-err));
		goto shutdown_cluster;
        } else {
                ubbd_info("\nConnected to the cluster.\n");
        }

	err = rados_ioctx_create(rbd_conn->cluster, rbd_conn->pool, &rbd_conn->io_ctx);
        if (err < 0) {
                ubbd_err("cannot create ioctx to %s pool: %s\n", rbd_conn->pool, strerror(-err));
		goto shutdown_cluster;
        } else {
                ubbd_info("\nioctx created.\n");
        }

	err = rbd_open(rbd_conn->io_ctx, rbd_conn->imagename, &rbd_conn->image, NULL);
        if (err < 0) {
                ubbd_err("cannot open image(%s): %s\n", rbd_conn->imagename, strerror(-err));
		goto destroy_ioctx;
        } else {
                ubbd_info("\nimage opened.\n");
        }
	return 0;

	rbd_close(rbd_conn->image);
destroy_ioctx:
	rados_ioctx_destroy(rbd_conn->io_ctx);
shutdown_cluster:
	rados_shutdown(rbd_conn->cluster);
	return err;
}

int ubbd_rbd_get_size(struct ubbd_rbd_conn *rbd_conn, uint64_t *dev_size)
{
	int ret = 0;

	ret = rbd_get_size(rbd_conn->image, dev_size);
        if (ret < 0) {
                ubbd_err("cannot get image size: %s\n",  strerror(-ret));
		goto out;
        }
	
	ubbd_info("\nimage get size: %lu.\n", *dev_size);
out:
	return ret;
}

void ubbd_rbd_conn_close(struct ubbd_rbd_conn *rbd_conn)
{
	rbd_close(rbd_conn->image);
	rados_ioctx_destroy(rbd_conn->io_ctx);
	rados_shutdown(rbd_conn->cluster);
}
