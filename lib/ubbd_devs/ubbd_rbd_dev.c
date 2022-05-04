#include <rados/librados.h>
#include <pthread.h>

#include "ubbd_dev.h"
#include "ubbd_uio.h"

// rbd ops
#define RBD_DEV(ubbd_dev) ((struct ubbd_rbd_device *)container_of(ubbd_dev, struct ubbd_rbd_device, ubbd_dev))
static int rbd_dev_open(struct ubbd_device *ubbd_dev)
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
        err = rados_conf_read_file(rbd_dev->cluster, "/etc/ceph/ceph.conf");
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
	return 0;

close_rbd:
	rbd_close(rbd_dev->image);
destroy_ioctx:
	rados_ioctx_destroy(rbd_dev->io_ctx);
shutdown_cluster:
	rados_shutdown(rbd_dev->cluster);
	return err;
}

static void rbd_dev_close(struct ubbd_device *ubbd_dev)
{
	struct ubbd_rbd_device *rbd_dev = RBD_DEV(ubbd_dev);

	rbd_close(rbd_dev->image);
	rados_ioctx_destroy(rbd_dev->io_ctx);
	rados_shutdown(rbd_dev->cluster);
}

static void rbd_dev_release(struct ubbd_device *ubbd_dev)
{
	struct ubbd_rbd_device *rbd_dev = RBD_DEV(ubbd_dev);

	free(rbd_dev);
}

enum rbd_aio_type {
	RBD_AIO_TYPE_WRITE = 0,
	RBD_AIO_TYPE_READ,
	RBD_AIO_TYPE_FLUSH,
	RBD_AIO_TYPE_DISCARD,
	RBD_AIO_TYPE_WRITE_ZEROS,
};

struct rbd_aio_cb {
	enum rbd_aio_type type;
	struct ubbd_queue *ubbd_q;
	uint64_t priv_data;
	uint32_t len;
	struct iovec iovec[0];
};

static void rbd_finish_aio_generic(rbd_completion_t completion,
				   struct rbd_aio_cb *aio_cb)
{
	struct ubbd_queue *ubbd_q = aio_cb->ubbd_q;
	struct ubbd_device *ubbd_dev = ubbd_q->ubbd_dev;
	int64_t ret;

	ubbd_dev_dbg(ubbd_dev, "into finish op \n");
	ret = rbd_aio_get_return_value(completion);
	ubbd_dev_dbg(ubbd_dev, "ret: %ld\n", ret);

	if (aio_cb->type == RBD_AIO_TYPE_READ ||
			aio_cb->type == RBD_AIO_TYPE_WRITE)
		ret = (ret == aio_cb->len? 0 : ret);

	free(aio_cb);
	rbd_aio_release(completion);

	ubbd_dev_add_ce(ubbd_q, aio_cb->priv_data, ret);
}

static int rbd_dev_writev(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	struct ubbd_device *ubbd_dev = ubbd_q->ubbd_dev;
	struct ubbd_rbd_device *rbd_dev = RBD_DEV(ubbd_dev);
	struct rbd_aio_cb *aio_cb;
	struct iovec *iov;
	rbd_completion_t completion;
	ssize_t ret;
	int i;

	aio_cb = calloc(1, sizeof(*aio_cb) + sizeof(struct iovec) * se->iov_cnt);
	if (!aio_cb) {
		ubbd_dev_err(ubbd_dev, "Could not allocate aio_cb.\n");
		return -1;
	}

	iov = aio_cb->iovec;
	for (i = 0; i < se->iov_cnt; i++) {
		ubbd_dev_dbg(ubbd_dev, "iov_base: %lu", (size_t)se->iov[i].iov_base);
		iov[i].iov_base = (void*)ubbd_q->uio_info.map + (size_t)se->iov[i].iov_base;
		iov[i].iov_len = se->iov[i].iov_len;
	}

	aio_cb->type = RBD_AIO_TYPE_WRITE;
	aio_cb->priv_data = se->priv_data;
	aio_cb->len = se->len;
	aio_cb->ubbd_q = ubbd_q;

	ret = rbd_aio_create_completion
		(aio_cb, (rbd_callback_t) rbd_finish_aio_generic, &completion);
	if (ret < 0) {
		ubbd_dev_err(ubbd_dev, "create completion failed\n");
		return -1;
	}
	ubbd_dev_dbg(ubbd_dev, "writev");
	ret = rbd_aio_writev(rbd_dev->image, iov, se->iov_cnt, se->offset, completion);
	return ret;
}

static int rbd_dev_readv(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	struct ubbd_device *ubbd_dev = ubbd_q->ubbd_dev;
	struct ubbd_rbd_device *rbd_dev = RBD_DEV(ubbd_dev);
	struct rbd_aio_cb *aio_cb;
	struct iovec *iov;
	rbd_completion_t completion;
	ssize_t ret;
	int i;

	aio_cb = calloc(1, sizeof(*aio_cb) + sizeof(struct iovec) * se->iov_cnt);
	if (!aio_cb) {
		ubbd_dev_err(ubbd_dev, "Could not allocate aio_cb.\n");
		return -1;
	}

	aio_cb->type = RBD_AIO_TYPE_READ;
	aio_cb->priv_data = se->priv_data;
	aio_cb->len = se->len;
	aio_cb->ubbd_q = ubbd_q;

	iov = aio_cb->iovec;
	for (i = 0; i < se->iov_cnt; i++) {
		ubbd_dev_dbg(ubbd_dev, "iov_base: %lu", (size_t)se->iov[i].iov_base);
		iov[i].iov_base = (void*)ubbd_q->uio_info.map + (size_t)se->iov[i].iov_base;
		iov[i].iov_len = se->iov[i].iov_len;
	}

	ret = rbd_aio_create_completion
		(aio_cb, (rbd_callback_t) rbd_finish_aio_generic, &completion);
	if (ret < 0) {
		return -1;
	}
	ubbd_dev_dbg(ubbd_dev, "readv");

	ret = rbd_aio_readv(rbd_dev->image, iov, se->iov_cnt, se->offset, completion);
	ubbd_dev_dbg(ubbd_dev, "after wait\n");
	return ret;
}

static int rbd_dev_flush(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	struct ubbd_device *ubbd_dev = ubbd_q->ubbd_dev;
	struct ubbd_rbd_device *rbd_dev = RBD_DEV(ubbd_dev);
	struct rbd_aio_cb *aio_cb;
	rbd_completion_t completion;
	ssize_t ret;

	aio_cb = calloc(1, sizeof(*aio_cb) + sizeof(struct iovec) * se->iov_cnt);
	if (!aio_cb) {
		ubbd_dev_err(ubbd_dev, "Could not allocate aio_cb.\n");
		return -1;
	}

	aio_cb->type = RBD_AIO_TYPE_FLUSH;
	aio_cb->priv_data = se->priv_data;
	aio_cb->len = se->len;
	aio_cb->ubbd_q = ubbd_q;

	ret = rbd_aio_create_completion
		(aio_cb, (rbd_callback_t) rbd_finish_aio_generic, &completion);
	if (ret < 0) {
		return -1;
	}
	ubbd_dev_dbg(ubbd_dev, "flush");

	ret = rbd_aio_flush(rbd_dev->image, completion);
	ubbd_dev_dbg(ubbd_dev, "after wait\n");
	return ret;
}

static int rbd_dev_discard(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	struct ubbd_device *ubbd_dev = ubbd_q->ubbd_dev;
	struct ubbd_rbd_device *rbd_dev = RBD_DEV(ubbd_dev);
	struct rbd_aio_cb *aio_cb;
	rbd_completion_t completion;
	ssize_t ret;

	aio_cb = calloc(1, sizeof(*aio_cb) + sizeof(struct iovec) * se->iov_cnt);
	if (!aio_cb) {
		ubbd_dev_err(ubbd_dev, "Could not allocate aio_cb.\n");
		return -1;
	}

	aio_cb->type = RBD_AIO_TYPE_DISCARD;
	aio_cb->priv_data = se->priv_data;
	aio_cb->len = se->len;
	aio_cb->ubbd_q = ubbd_q;

	ret = rbd_aio_create_completion
		(aio_cb, (rbd_callback_t) rbd_finish_aio_generic, &completion);
	if (ret < 0) {
		return -1;
	}
	ubbd_dev_dbg(ubbd_dev, "discard");

	ret = rbd_aio_discard(rbd_dev->image, se->offset, se->len, completion);
	ubbd_dev_dbg(ubbd_dev, "after wait\n");
	return ret;
}

#ifdef LIBRBD_SUPPORTS_WRITE_ZEROES
static int rbd_dev_write_zeros(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	struct ubbd_device *ubbd_dev = ubbd_q->ubbd_dev;
	struct ubbd_rbd_device *rbd_dev = RBD_DEV(ubbd_dev);
	struct rbd_aio_cb *aio_cb;
	rbd_completion_t completion;
	ssize_t ret;

	aio_cb = calloc(1, sizeof(*aio_cb) + sizeof(struct iovec) * se->iov_cnt);
	if (!aio_cb) {
		ubbd_dev_err(ubbd_dev, "Could not allocate aio_cb.\n");
		return -1;
	}

	aio_cb->type = RBD_AIO_TYPE_WRITE_ZEROS;
	aio_cb->priv_data = se->priv_data;
	aio_cb->len = se->len;
	aio_cb->ubbd_q = ubbd_q;

	ret = rbd_aio_create_completion
		(aio_cb, (rbd_callback_t) rbd_finish_aio_generic, &completion);
	if (ret < 0) {
		return -1;
	}
	ubbd_dev_dbg(ubbd_dev, "write_zeros");

	ret = rbd_aio_write_zeroes(rbd_dev->image, se->offset, se->len, completion, 0, 0);
	ubbd_dev_dbg(ubbd_dev, "after wait\n");
	return ret;
}
#else
static int rbd_dev_write_zeros(struct ubbd_device *ubbd_dev, struct ubbd_se *se)
{
	ubbd_dev_err(ubbd_dev, "write_zeros is not supported");

	return -1;
}
#endif

struct ubbd_dev_ops rbd_dev_ops = {
	.open = rbd_dev_open,
	.close = rbd_dev_close,
	.release = rbd_dev_release,
	.writev = rbd_dev_writev,
	.readv = rbd_dev_readv,
	.flush = rbd_dev_flush,
	.discard = rbd_dev_discard,
	.write_zeros = rbd_dev_write_zeros,
};


