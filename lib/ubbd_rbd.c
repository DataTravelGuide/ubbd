#define _GNU_SOURCE
#include "ubbd_rbd.h"
#include "ubbd_log.h"

#define RBD_DEV_SETUP_TIMEOUT		"30"

int ubbd_rbd_conn_open(struct ubbd_rbd_conn *rbd_conn)
{
        int err;
	char *timeout_buf;

	if (asprintf(&timeout_buf, "%d", rbd_conn->io_timeout) == -1) {
		ubbd_err("failed to setup timeout_buf for ceph config.\n");
		return -1;
	}

        err = rados_create2(&rbd_conn->cluster, rbd_conn->cluster_name, rbd_conn->user_name, rbd_conn->flags);
        if (err < 0) {
                ubbd_err("Couldn't create the cluster handle! %s\n", strerror(-err));
		goto out;
        } else {
                ubbd_info("\nCreated a cluster handle.\n");
        }

        /* Read a Ceph configuration file to configure the cluster handle. */
        err = rados_conf_read_file(rbd_conn->cluster, rbd_conn->ceph_conf);
        if (err < 0) {
                ubbd_err("cannot read config file: %s, %s\n", rbd_conn->ceph_conf, strerror(-err));
		goto shutdown_cluster;
        } else {
                ubbd_info("\nRead the config file.\n");
        }

	rados_conf_set(rbd_conn->cluster, "client_mount_timeout", RBD_DEV_SETUP_TIMEOUT);
	rados_conf_set(rbd_conn->cluster, "rados_osd_op_timeout", RBD_DEV_SETUP_TIMEOUT);
	rados_conf_set(rbd_conn->cluster, "rados_mon_op_timeout", RBD_DEV_SETUP_TIMEOUT);

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

	/* rados_ioctx_set_namespace is void function */
	rados_ioctx_set_namespace(rbd_conn->io_ctx, rbd_conn->ns);

	err = rbd_open(rbd_conn->io_ctx, rbd_conn->imagename, &rbd_conn->image, rbd_conn->snap);
        if (err < 0) {
                ubbd_err("cannot open image(%s/%s): %s\n", rbd_conn->imagename, rbd_conn->snap,
				strerror(-err));
		goto destroy_ioctx;
        } else {
                ubbd_info("\nimage opened.\n");
        }

	rados_conf_set(rbd_conn->cluster, "client_mount_timeout", timeout_buf);
	rados_conf_set(rbd_conn->cluster, "rados_osd_op_timeout", timeout_buf);
	rados_conf_set(rbd_conn->cluster, "rados_mon_op_timeout", timeout_buf);

	rbd_conn->update_handle = 0;
	rbd_conn->quiesce_handle = 0;

	return 0;

	rbd_close(rbd_conn->image);
destroy_ioctx:
	rados_ioctx_destroy(rbd_conn->io_ctx);
shutdown_cluster:
	rados_shutdown(rbd_conn->cluster);
out:
	free(timeout_buf);
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
