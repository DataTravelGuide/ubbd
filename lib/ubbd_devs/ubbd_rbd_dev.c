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
                fprintf(stderr, "Couldn't create the cluster handle! %s\n", strerror(-err));
                exit(EXIT_FAILURE);
        } else {
                printf("\nCreated a cluster handle.\n");
        }


        /* Read a Ceph configuration file to configure the cluster handle. */
        err = rados_conf_read_file(rbd_dev->cluster, "/etc/ceph/ceph.conf");
        if (err < 0) {
                fprintf(stderr, "cannot read config file: %s\n", strerror(-err));
                exit(EXIT_FAILURE);
        } else {
                printf("\nRead the config file.\n");
        }

	rados_conf_set(rbd_dev->cluster, "rbd_cache", "true");

        /* Connect to the cluster */
        err = rados_connect(rbd_dev->cluster);
        if (err < 0) {
                fprintf(stderr, "cannot connect to cluster: %s\n",  strerror(-err));
                exit(EXIT_FAILURE);
        } else {
                printf("\nConnected to the cluster.\n");
        }

	err = rados_ioctx_create(rbd_dev->cluster, "rbd", &rbd_dev->io_ctx);
        if (err < 0) {
                fprintf(stderr, "cannot create ioctx to rbd pool: %s\n",  strerror(-err));
                exit(EXIT_FAILURE);
        } else {
                printf("\nioctx created.\n");
        }

	err = rbd_open(rbd_dev->io_ctx, rbd_dev->imagename, &rbd_dev->image, NULL);
        if (err < 0) {
                fprintf(stderr, "cannot open image: %s\n",  strerror(-err));
                exit(EXIT_FAILURE);
        } else {
                printf("\nimage opened.\n");
        }

	err = rbd_get_size(rbd_dev->image, &ubbd_dev->dev_size);
        if (err < 0) {
                fprintf(stderr, "cannot get image size: %s\n",  strerror(-err));
                exit(EXIT_FAILURE);
        } else {
                printf("\nimage get size: %lu.\n", ubbd_dev->dev_size);
        }

	ubbd_dev->dev_features.write_cache = true;
	ubbd_dev->dev_features.fua = false;

	return 0;
}

enum rbd_aio_type {
	RBD_AIO_TYPE_WRITE = 0,
	RBD_AIO_TYPE_READ,
	RBD_AIO_TYPE_FLUSH,
};

struct rbd_aio_cb {
	enum rbd_aio_type type;
	struct ubbd_se *se;
	struct ubbd_device *ubbd_dev;
	struct iovec iovec[0];
};

static void rbd_finish_aio_generic(rbd_completion_t completion,
				   struct rbd_aio_cb *aio_cb)
{
	struct ubbd_device *ubbd_dev = aio_cb->ubbd_dev;
	struct ubbd_sb *sb = ubbd_dev->map;
	struct ubbd_se *se = aio_cb->se;
	int64_t ret;
	struct ubbd_ce *ce;

	ubbd_dev_err(ubbd_dev, "into finish op \n");
	ret = rbd_aio_get_return_value(completion);
	ubbd_dev_err(ubbd_dev, "ret: %ld\n", ret);

	pthread_mutex_lock(&ubbd_dev->lock);
	ce = get_available_ce(ubbd_dev);
	memset(ce, 0, sizeof(*ce));
	ce->priv_data = se->priv_data;
	ce->flags = 0;

	if (aio_cb->type == RBD_AIO_TYPE_READ ||
			aio_cb->type == RBD_AIO_TYPE_WRITE)
		ret = (ret == se->len? 0 : ret);

	ce->result = ret;
	ubbd_dev_err(ubbd_dev, "finish se id: %p\n", se);
	ubbd_dev_err(ubbd_dev, "append ce: %llu\n", ce->priv_data);
	UBBD_UPDATE_DEV_COMP_HEAD(ubbd_dev, sb, ce);
	//ubbd_uio_advance_cmd_ring(ubbd_dev);
	pthread_mutex_unlock(&ubbd_dev->lock);
	ubbdlib_processing_complete(ubbd_dev);

	free(aio_cb);
	rbd_aio_release(completion);

}

static int rbd_dev_writev(struct ubbd_device *ubbd_dev, struct ubbd_se *se)
{
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
		ubbd_dev_err(ubbd_dev, "iov_base: %lu", (size_t)se->iov[i].iov_base);
		iov[i].iov_base = (void*)ubbd_dev->map + (size_t)se->iov[i].iov_base;
		iov[i].iov_len = se->iov[i].iov_len;
	}

	aio_cb->type = RBD_AIO_TYPE_WRITE;
	aio_cb->se = se;
	aio_cb->ubbd_dev = ubbd_dev;

	ret = rbd_aio_create_completion
		(aio_cb, (rbd_callback_t) rbd_finish_aio_generic, &completion);
	if (ret < 0) {
		ubbd_dev_err(ubbd_dev, "create completion failed\n");
		return -1;
	}
	ubbd_dev_err(ubbd_dev, "writev");
	ret = rbd_aio_writev(rbd_dev->image, iov, se->iov_cnt, se->offset, completion);
	return ret;
}

static int rbd_dev_readv(struct ubbd_device *ubbd_dev, struct ubbd_se *se)
{
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
	aio_cb->se = se;
	aio_cb->ubbd_dev = ubbd_dev;

	iov = aio_cb->iovec;
	for (i = 0; i < se->iov_cnt; i++) {
		ubbd_dev_err(ubbd_dev, "iov_base: %lu", (size_t)se->iov[i].iov_base);
		iov[i].iov_base = (void*)ubbd_dev->map + (size_t)se->iov[i].iov_base;
		iov[i].iov_len = se->iov[i].iov_len;
	}

	ret = rbd_aio_create_completion
		(aio_cb, (rbd_callback_t) rbd_finish_aio_generic, &completion);
	if (ret < 0) {
		return -1;
	}
	ubbd_dev_err(ubbd_dev, "readv");

	ret = rbd_aio_readv(rbd_dev->image, iov, se->iov_cnt, se->offset, completion);
	ubbd_dev_err(ubbd_dev, "after wait\n");
	return ret;
}

static void rbd_dev_release(struct ubbd_device *ubbd_dev)
{
	struct ubbd_rbd_device *rbd_dev = RBD_DEV(ubbd_dev);

	free(rbd_dev);
}

static int rbd_dev_flush(struct ubbd_device *ubbd_dev, struct ubbd_se *se)
{
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
	aio_cb->se = se;
	aio_cb->ubbd_dev = ubbd_dev;

	ret = rbd_aio_create_completion
		(aio_cb, (rbd_callback_t) rbd_finish_aio_generic, &completion);
	if (ret < 0) {
		return -1;
	}
	ubbd_dev_err(ubbd_dev, "flush");

	ret = rbd_aio_flush(rbd_dev->image, completion);
	ubbd_dev_err(ubbd_dev, "after wait\n");
	return ret;
}

struct ubbd_dev_ops rbd_dev_ops = {
	.open = rbd_dev_open,
	.writev = rbd_dev_writev,
	.readv = rbd_dev_readv,
	.release = rbd_dev_release,
	.flush = rbd_dev_flush,
};


