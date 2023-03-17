#define _GNU_SOURCE
#include <rados/librados.h>
#include <pthread.h>

#include "ubbd_dev.h"
#include "ubbd_uio.h"
#include "ubbd_netlink.h"
#include "utils.h"

// rbd ops
#define RBD_DEV(ubbd_dev) ((struct ubbd_rbd_device *)container_of(ubbd_dev, struct ubbd_rbd_device, ubbd_dev))

struct ubbd_dev_ops rbd_dev_ops;

static struct ubbd_device *rbd_dev_create(struct __ubbd_dev_info *info)
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
	strcpy(rbd_conn->ns, info->rbd.ns);
	strcpy(rbd_conn->imagename, info->rbd.image);
	if (info->rbd.flags & UBBD_DEV_INFO_RBD_FLAGS_SNAP) {
		rbd_conn->flags |= UBBD_DEV_INFO_RBD_FLAGS_SNAP;
		strcpy(rbd_conn->snap, info->rbd.snap);
	}

	strcpy(rbd_conn->snap, info->rbd.snap);
	strcpy(rbd_conn->ceph_conf, info->rbd.ceph_conf);
	strcpy(rbd_conn->user_name, info->rbd.user_name);
	strcpy(rbd_conn->cluster_name, info->rbd.cluster_name);
	rbd_conn->io_timeout = info->io_timeout;

	return ubbd_dev;
}

static void rbd_dev_update_cb(void *arg)
{
	struct ubbd_rbd_device *rbd_dev = (struct ubbd_rbd_device *)arg;
	struct ubbd_rbd_conn *rbd_conn = &rbd_dev->rbd_conn;
	struct ubbd_device *ubbd_dev = &rbd_dev->ubbd_dev;
	uint64_t dev_size;
	int ret;

	ret = ubbd_rbd_get_size(rbd_conn, &dev_size);
	if (ret < 0) {
		ubbd_err("failed to get size of ubbd in update watcher.\n");
		return;
	}

	if (dev_size != ubbd_dev->dev_size) {
		ret = ubbd_nl_req_config(ubbd_dev, -1, dev_size, NULL);
		if (ret) {
			ubbd_err("failed to send netlink request to resize.\n");
			return;
		}
	}

	ubbd_dev->dev_size = dev_size;
}

static int rbd_dev_init(struct ubbd_device *ubbd_dev, bool reopen)
{
	struct ubbd_rbd_device *rbd_dev = RBD_DEV(ubbd_dev);
	struct ubbd_rbd_conn *rbd_conn = &rbd_dev->rbd_conn;
	char *dev_path;
	uint64_t dev_size;
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

	/* check the dev_size for real device */
	if (reopen) {
		if (asprintf(&dev_path, "/dev/ubbd%d", ubbd_dev->dev_id) == -1) {
			ubbd_err("cant init dev path\n");
			goto close_rbd;
		}


		ret = ubbd_util_get_file_size(dev_path, &dev_size);
		free(dev_path);
		if (ret) {
			ubbd_err("failed to get dev size\n");
			goto close_rbd;
		}

		if (dev_size != ubbd_dev->dev_size) {
			ret = ubbd_nl_req_config(ubbd_dev, -1, ubbd_dev->dev_size, NULL);
			if (ret) {
				ubbd_err("failed to send netlink request to update dev_size.\n");
				goto close_rbd;
			}
		}
	}

	ret = rbd_update_watch(rbd_conn->image, &rbd_conn->update_handle,
			rbd_dev_update_cb, rbd_dev);
	if (ret) {
		ubbd_err("failed to register rbd update watcher:%d\n", ret);
		goto close_rbd;
	}

	ubbd_dev->dev_features.write_cache = false;
	ubbd_dev->dev_features.fua = false;
	ubbd_dev->dev_features.discard = true;
#ifdef LIBRBD_SUPPORTS_WRITE_ZEROES
	ubbd_dev->dev_features.write_zeros = true;
#else
	ubbd_dev->dev_features.write_zeros = false;
#endif
	if (rbd_conn->flags & UBBD_DEV_INFO_RBD_FLAGS_SNAP) {
		ubbd_dev->dev_features.read_only = true;
		ubbd_dev->dev_info.flags |= UBBD_DEV_INFO_FLAGS_READONLY;
	}

	return 0;

close_rbd:
	ubbd_rbd_conn_close(rbd_conn);
out:
	return ret;
}

static void rbd_dev_release(struct ubbd_device *ubbd_dev)
{
	struct ubbd_rbd_device *rbd_dev = RBD_DEV(ubbd_dev);
	struct ubbd_rbd_conn *rbd_conn = &rbd_dev->rbd_conn;

	if (rbd_conn->update_handle) {
		rbd_update_unwatch(rbd_conn->image, rbd_conn->update_handle);
	}
	ubbd_rbd_conn_close(rbd_conn);
	free(rbd_dev);
}

#define	UBBD_DEV_RBD_LINK_DIR	UBBD_DEV_LINK_DIR"/rbd"

static int mkdir_and_chdir(char *dir)
{
	int ret;

	ret = ubbd_mkdirs(dir);
	if (ret < 0)
		return ret;

	return chdir(dir);
}

static int rbd_dev_post_disk_added(struct ubbd_device *ubbd_dev)
{
	char target_path[PATH_MAX], link_path[PATH_MAX];
	struct ubbd_rbd_device *rbd_dev = RBD_DEV(ubbd_dev);
	struct ubbd_rbd_conn *rbd_conn = &rbd_dev->rbd_conn;
	char *retp;
	int ret;

	ret = mkdir_and_chdir(UBBD_DEV_RBD_LINK_DIR);
	if (ret < 0)
		goto out;

	ret = mkdir_and_chdir(rbd_conn->pool);
	if (ret < 0) {
		goto out;
	}

	if (strcmp(rbd_conn->ns, "")) {
		ret = mkdir_and_chdir(rbd_conn->ns);
		if (ret < 0)
			goto out;
	}

	ret = mkdir_and_chdir(rbd_conn->imagename);
	if (ret < 0)
		goto out;

	if (rbd_conn->flags & UBBD_DEV_INFO_RBD_FLAGS_SNAP) {
		ret = mkdir_and_chdir(rbd_conn->snap);
		if (ret < 0) {
			goto out;
		}
	}

	if ((ret = snprintf(target_path, PATH_MAX, "/dev/ubbd%d", ubbd_dev->dev_id)) < 0 ||
			(ret = snprintf(link_path, PATH_MAX, "%d", ubbd_dev->dev_id)) < 0) {
		ubbd_dev_err(ubbd_dev, "failed to setup target_path or link_path.\n");
		goto out;
	}

	retp = getcwd(rbd_dev->dev_link_dir, PATH_MAX);
	if (!retp) {
		ubbd_dev_err(ubbd_dev, "failed to get dev link dir.\n");
		ret = -errno;
		goto out;
	}

symlink:
	ret = symlink(target_path, link_path);
	if (ret < 0) {
		if (errno == EEXIST) {
			ret = unlink(link_path);
			if (ret < 0 && errno != ENOENT) {
				ubbd_dev_err(ubbd_dev, "link path exist and cant cleanup.\n");
				goto out;
			}
			goto symlink;
		}
		ubbd_dev_err(ubbd_dev, "failed to create symlink: %d\n", ret);
		goto out;
	}


	ret = 0;

out:
	return ret;
}

static int rbd_dev_before_dev_remove(struct ubbd_device *ubbd_dev)
{
	struct ubbd_rbd_device *rbd_dev = RBD_DEV(ubbd_dev);
	char link_path[PATH_MAX];
	int ret;

	ret = snprintf(link_path, PATH_MAX, "%s/%d", rbd_dev->dev_link_dir, ubbd_dev->dev_id);
	if (ret < 0) {
		ubbd_dev_err(ubbd_dev, "failed to setup link path.\n");
		goto out;
	}

	ret = unlink(link_path);
	if (ret < 0 && errno != ENOENT) {
		ubbd_dev_err(ubbd_dev, "failed to unlink dev link path: %s\n", link_path);
		ret = -errno;
		goto out;
	}
	/* try to rm dir, it will do nothing if this dir is not empty */
	ret = ubbd_rmdirs(rbd_dev->dev_link_dir, UBBD_DEV_RBD_LINK_DIR);
	if (ret < 0 && ret != -ENOTEMPTY) {
		ubbd_dev_err(ubbd_dev, "failed to rmdirs: %s\n", rbd_dev->dev_link_dir);
	}

	ret = 0;
out:
	return ret;

}

struct ubbd_dev_ops rbd_dev_ops = {
	.create = rbd_dev_create,
	.init = rbd_dev_init,
	.release = rbd_dev_release,
	.before_dev_remove = rbd_dev_before_dev_remove,
	.post_disk_added = rbd_dev_post_disk_added,
};
