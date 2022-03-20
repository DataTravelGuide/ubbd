#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <pthread.h>

#include "utils.h"
#include "list.h"
#include "ubbd_dev.h"
#include "ubbd_uio.h"
#include "ubbd_netlink.h"


static bool compr_space_enough(struct ubbd_device *ubbd_dev, uint32_t required)
{
	struct ubbd_sb *sb = ubbd_dev->map;
	uint32_t space_available;
	uint32_t space_max, space_used;

	/* There is a CMPR_RESERVED we dont use to prevent the ring to be used up */
	space_max = sb->compr_size - CMPR_RESERVED;

	if (sb->compr_head > sb->compr_tail)
		space_used = sb->compr_head - sb->compr_tail;
	else if (sb->compr_head < sb->compr_tail)
		space_used = sb->compr_head + (sb->compr_size - sb->compr_tail);
	else
		space_used = 0;

	space_available = space_max - space_used;
	if (space_available < required)
		return false;

	return true;
}

struct ubbd_ce *get_available_ce(struct ubbd_device *ubbd_dev)
{
	/*
	 * dev->lock held
	 */
	struct ubbd_sb *sb = ubbd_dev->map;

	while (!compr_space_enough(ubbd_dev, sizeof(struct ubbd_ce))) {
		pthread_mutex_unlock(&ubbd_dev->lock);
		ubbd_err(" compr not enough head: %u, tail: %u\n", sb->compr_head, sb->compr_tail);
		ubbdlib_processing_complete(ubbd_dev);
                usleep(50000);
		pthread_mutex_lock(&ubbd_dev->lock);
	}

	return device_comp_head(ubbd_dev);
}

static void wait_for_compr_empty(struct ubbd_device *ubbd_dev)
{
	struct ubbd_sb *sb = ubbd_dev->map;
 
         ubbd_info("waiting for ring to clear\n");
         while (sb->compr_head != sb->compr_tail) {
		 ubbd_info("head: %u, tail: %u\n", sb->compr_head, sb->compr_tail);
                 usleep(50000);
	 }
         ubbd_info("ring clear\n");
}

static void handle_cmd(struct ubbd_device *dev, struct ubbd_se *se);
void *cmd_process(void *arg)
{
	struct ubbd_device *ubbd_dev = arg;
	struct ubbd_se *se;
	struct ubbd_sb *sb = ubbd_dev->map;
	uint32_t op_len = 0;

	struct pollfd pollfds[128];
	int ret;

	ubbdlib_processing_complete(ubbd_dev);
	wait_for_compr_empty(ubbd_dev);

	ubbd_dev->se_to_handle = sb->cmd_tail;
	ubbd_dbg("cmd_tail: %u, cmd_head: %u\n", sb->cmd_tail, sb->cmd_head);

	while (1) {
		while (1) {
			ubbdlib_processing_start(ubbd_dev);

			se = device_cmd_to_handle(ubbd_dev);
			if (se == device_cmd_head(ubbd_dev)) {
				break;
			}
			op_len = ubbd_se_hdr_get_len(se->header.len_op);
			ubbd_dbg("len_op: %x\n", se->header.len_op);
			ubbd_dbg("op: %d, length: %u\n", ubbd_se_hdr_get_op(se->header.len_op), ubbd_se_hdr_get_len(se->header.len_op));
			if (ubbd_se_hdr_get_op(se->header.len_op) != UBBD_OP_PAD)
				ubbd_dbg("se id: %llu\n", se->priv_data);
			handle_cmd(ubbd_dev, se);
			UBBD_UPDATE_CMD_TO_HANDLE(ubbd_dev, sb, op_len);
			ubbd_dbg("finish handle_cmd\n");
		}

poll:
		pollfds[0].fd = ubbd_dev->fd;
		pollfds[0].events = POLLIN;
		pollfds[0].revents = 0;

		/* Use ppoll instead poll to avoid poll call reschedules during signal
		 * handling. If we were removing a device, then the uio device's memory
		 * could be freed, but the poll would be rescheduled and end up accessing
		 * the released device. */
		ret = poll(pollfds, 1, 60);
		if (ret == -1) {
			ubbd_err("ppoll() returned %d, exiting\n", ret);
			exit(EXIT_FAILURE);
		}

		if (ubbd_dev->status == UBBD_DEV_STATUS_REMOVING) {
			ubbd_err("exit cmd_process\n");
			break;
		}

		ubbd_dbg("poll cmd: %d\n", ret);
		if (!pollfds[0].revents) {
			goto poll;
		}

	}

	return NULL;
}



static void handle_cmd(struct ubbd_device *ubbd_dev, struct ubbd_se *se)
{
	struct ubbd_se_hdr *header = &se->header;
	int ret;

	ubbd_dbg("handle_cmd: se: %p\n", se);
	if (ubbd_se_hdr_flags_test(se, UBBD_SE_HDR_DONE)) {
		ubbd_dbg("flags is done\n");
		return;
	}

	switch (ubbd_se_hdr_get_op(header->len_op)) {
	case UBBD_OP_PAD:
		ubbd_dbg("set pad op to done\n");
		ubbd_se_hdr_flags_set(se, UBBD_SE_HDR_DONE);
		ret = 0;
		ubbdlib_processing_complete(ubbd_dev);
		break;
	case UBBD_OP_WRITE:
		ubbd_dbg("UBBD_OP_WRITE\n");
		ret = ubbd_dev->dev_ops->writev(ubbd_dev, se);
		break;
	case UBBD_OP_READ:
		ubbd_dbg("UBBD_OP_READ\n");
		ret = ubbd_dev->dev_ops->readv(ubbd_dev, se);
		break;
	case UBBD_OP_FLUSH:
		ubbd_dbg("UBBD_OP_FLUSH\n");
		if (!ubbd_dev->dev_ops->flush) {
			ret = -EOPNOTSUPP;
			ubbd_dev_err(ubbd_dev, "flush is not supportted.\n");
			goto out;
		}
		ret = ubbd_dev->dev_ops->flush(ubbd_dev, se);
		break;
	case UBBD_OP_DISCARD:
		ubbd_dbg("UBBD_OP_DISCARD\n");
		if (!ubbd_dev->dev_ops->discard) {
			ret = -EOPNOTSUPP;
			ubbd_dev_err(ubbd_dev, "discard is not supportted.\n");
			goto out;
		}
		ret = ubbd_dev->dev_ops->discard(ubbd_dev, se);
		break;
	case UBBD_OP_WRITE_ZEROS:
		ubbd_dbg("UBBD_OP_WRITE_ZEROS\n");
		if (!ubbd_dev->dev_ops->write_zeros) {
			ret = -EOPNOTSUPP;
			ubbd_dev_err(ubbd_dev, "write_zeros is not supportted.\n");
			goto out;
		}
		ret = ubbd_dev->dev_ops->write_zeros(ubbd_dev, se);
		break;
	default:
		ubbd_err("error handle_cmd\n");
		exit(EXIT_FAILURE);
	}

out:
	if (ret) {
		ubbd_err("ret of se: %llu: %d", se->priv_data, ret);
		exit(EXIT_FAILURE);
	}

	return;
}

static LIST_HEAD(ubbd_dev_list);

struct ubbd_device *find_ubbd_dev(int dev_id)
{
        struct ubbd_device *ubbd_dev = NULL;
        struct ubbd_device *ubbd_dev_tmp;

        list_for_each_entry(ubbd_dev_tmp, &ubbd_dev_list, dev_node) {
                if (ubbd_dev_tmp->dev_id == dev_id) {
                        ubbd_dev = ubbd_dev_tmp;
                        break;
                }
        }

        return ubbd_dev;
}

static void ubbd_dev_init(struct ubbd_device *ubbd_dev)
{
	ubbd_dev->status = UBBD_DEV_STATUS_INIT;
	INIT_LIST_HEAD(&ubbd_dev->dev_node);
	pthread_mutex_init(&ubbd_dev->lock, NULL);
}

struct ubbd_rbd_device *create_rbd_dev(void)
{
	struct ubbd_device *ubbd_dev;
	struct ubbd_rbd_device *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	ubbd_dev = &dev->ubbd_dev;
	ubbd_dev->dev_type = UBBD_DEV_TYPE_RBD;
	ubbd_dev->dev_ops = &rbd_dev_ops;

	return dev;
}

struct ubbd_file_device *create_file_dev(void)
{
	struct ubbd_device *ubbd_dev;
	struct ubbd_file_device *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	ubbd_dev = &dev->ubbd_dev;
	ubbd_dev->dev_type = UBBD_DEV_TYPE_FILE;
	ubbd_dev->dev_ops = &file_dev_ops;

	return dev;
}

struct ubbd_device *ubbd_dev_create(struct ubbd_dev_info *info)
{
	struct ubbd_device *ubbd_dev;

	if (info->type == UBBD_DEV_TYPE_FILE) {
		struct ubbd_file_device *file_dev;

		file_dev = create_file_dev();
		if (!file_dev)
			return NULL;
		ubbd_dev = &file_dev->ubbd_dev;
		strcpy(file_dev->filepath, info->file.path);
		ubbd_dev->dev_size = info->file.size;
	} else if (info->type == UBBD_DEV_TYPE_RBD) {
		struct ubbd_rbd_device *rbd_dev;

		rbd_dev = create_rbd_dev();
		if (!rbd_dev)
			return NULL;
		ubbd_dev = &rbd_dev->ubbd_dev;
		strcpy(rbd_dev->pool, info->rbd.pool);
		strcpy(rbd_dev->imagename, info->rbd.image);
	} else {
		ubbd_err("Unknown dev type\n");
		return NULL;
	}

	ubbd_dev_init(ubbd_dev);
	memcpy(&ubbd_dev->dev_info, info, sizeof(*info));

	return ubbd_dev;
}

int ubbd_dev_open(struct ubbd_device *ubbd_dev)
{
	int ret = 0;

	ret = ubbd_dev->dev_ops->open(ubbd_dev);
	if (ret)
		goto out;

	ubbd_dbg("add ubbd_dev: %p dev_id: %dinto list\n", ubbd_dev, ubbd_dev->dev_id);
	list_add_tail(&ubbd_dev->dev_node, &ubbd_dev_list);
	ubbd_dev->status = UBBD_DEV_STATUS_OPENED;

out:
	return ret;
}

void ubbd_dev_close(struct ubbd_device *ubbd_dev)
{
	list_del_init(&ubbd_dev->dev_node);
	ubbd_dev->dev_ops->close(ubbd_dev);
	ubbd_dev->status = UBBD_DEV_STATUS_INIT;
}

void ubbd_dev_release(struct ubbd_device *ubbd_dev)
{
	ubbd_dev->dev_ops->release(ubbd_dev);
}

/*
 * ubbd device add
 */
int dev_setup(struct ubbd_device *ubbd_dev)
{
	int ret;

	ret = device_open_shm(ubbd_dev);
	if (ret) {
		ubbd_dev_err(ubbd_dev, "failed to open shm: %d\n", ret);
		goto out;
	}

	memcpy(ubbd_uio_get_dev_info(ubbd_dev->map),
			&ubbd_dev->dev_info, sizeof(struct ubbd_dev_info));

	ret = pthread_create(&ubbd_dev->cmdproc_thread, NULL, cmd_process, ubbd_dev);
	if (ret) {
		ubbd_dev_err(ubbd_dev, "failed to create cmdproc_thread: %d\n", ret);
		goto out;
	}

out:
	return ret;
}

int dev_stop(struct ubbd_device *ubbd_dev)
{
	void *join_retval;
	int ret;

	ubbd_dev->status = UBBD_DEV_STATUS_REMOVING;

	ret = pthread_join(ubbd_dev->cmdproc_thread, &join_retval);
	if (ret)
		return ret;
	device_close_shm(ubbd_dev);

	return 0;
}

struct dev_ctx_data {
	struct ubbd_device *ubbd_dev;
};

struct context *dev_ctx_alloc(struct ubbd_device *ubbd_dev,
		struct context *ctx, int (*finish)(struct context *, int))
{
	struct context *dev_ctx;
	struct dev_ctx_data *ctx_data;

	dev_ctx = context_alloc(sizeof(struct dev_ctx_data));
	if (!dev_ctx) {
		return NULL;
	}

	ctx_data = (struct dev_ctx_data *)dev_ctx->data;
	ctx_data->ubbd_dev = ubbd_dev;

	dev_ctx->finish = finish;
	dev_ctx->parent = ctx;

	return dev_ctx;
}

struct dev_add_data {
	struct ubbd_device *ubbd_dev;
};

int dev_add_finish(struct context *ctx, int ret)
{
	struct dev_add_data *add_data = (struct dev_add_data *)ctx->data;
	struct ubbd_device *ubbd_dev = add_data->ubbd_dev;

	if (ret) {
		ubbd_dev_err(ubbd_dev, "error in add: %d.\n", ret);
		goto clean_dev;
	}

	ubbd_dev->status = UBBD_DEV_STATUS_RUNNING;

	return ret;

clean_dev:
	ubbd_dev_err(ubbd_dev, "clean dev up.\n");
	if (ubbd_dev_remove(ubbd_dev, false, NULL))
		ubbd_err("failed to cleanup dev.\n");
	return ret;
}

int dev_add(struct ubbd_device *ubbd_dev, struct context *ctx)
{
	struct context *add_ctx;
	struct dev_add_data *add_data;
	int ret;

	add_ctx = context_alloc(sizeof(struct dev_add_data));
	if (!add_ctx) {
		ret = -ENOMEM;
		goto out;
	}

	add_data = (struct dev_add_data *)add_ctx->data;
	add_data->ubbd_dev = ubbd_dev;

	add_ctx->finish = dev_add_finish;
	add_ctx->parent = ctx;

	ret = ubbd_nl_req_add(ubbd_dev, add_ctx);
	if (ret) {
		ubbd_dev_err(ubbd_dev, "failed to start add: %d\n", ret);
		goto out;
	}

out:
	return ret;
}

struct dev_add_prepare_data {
	struct ubbd_device *ubbd_dev;
};

int dev_add_prepare_finish(struct context *ctx, int ret)
{
	struct dev_add_prepare_data *add_prepare_data = (struct dev_add_prepare_data *)ctx->data;
	struct ubbd_device *ubbd_dev = add_prepare_data->ubbd_dev;

	if (ret) {
		ubbd_dev_err(ubbd_dev, "error in add_prepare: %d.\n", ret);
		goto clean_dev;
	}

	/* advance dev status into ADD_PREPARED */
	ubbd_dev->status = UBBD_DEV_STATUS_DISK_PREPARED;

	ret = dev_setup(ubbd_dev);
	if (ret) {
		goto clean_dev;
	}

	/*
	 * prepare is almost done, let's start add,
	 * and pass the parent_ctx to add req.
	 */
	ret = dev_add(ubbd_dev, ctx->parent);
	if (ret) {
		goto clean_dev;
	}

	/* parent will be finished by add cmd */
	ctx->parent = NULL;

	return 0;
clean_dev:
	ubbd_dev_err(ubbd_dev, "clean dev up.\n");
	if (ubbd_dev_remove(ubbd_dev, false, NULL))
		ubbd_err("failed to cleanup dev.\n");
	return ret;
}

int dev_add_prepare(struct ubbd_device *ubbd_dev, struct context *ctx)
{
	struct context *add_prepare_ctx;
	struct dev_add_prepare_data *add_prepare_data;

	add_prepare_ctx = context_alloc(sizeof(struct dev_add_prepare_data));
	if (!add_prepare_ctx) {
		return -ENOMEM;
	}

	add_prepare_data = (struct dev_add_prepare_data *)add_prepare_ctx->data;
	add_prepare_data->ubbd_dev = ubbd_dev;

	add_prepare_ctx->finish = dev_add_prepare_finish;
	add_prepare_ctx->parent = ctx;

	return ubbd_nl_req_add_prepare(ubbd_dev, add_prepare_ctx);
}

int ubbd_dev_add(struct ubbd_dev_info *info, struct context *ctx)
{
	int ret;
	struct ubbd_device *ubbd_dev;

	ubbd_dev = ubbd_dev_create(info);
	if (!ubbd_dev) {
		ubbd_err("error to create ubbd_dev\n");
		ret = -ENOMEM;
		goto err;
	}

	ret = ubbd_dev_open(ubbd_dev);
	if (ret) {
		goto release_dev;
	}

	ret = dev_add_prepare(ubbd_dev, ctx);
	if (ret)
		goto close_dev;
	return 0;

close_dev:
	ubbd_dev_close(ubbd_dev);
release_dev:
	ubbd_dev_release(ubbd_dev);
err:
	context_finish(ctx, ret);
	return ret;
}

/*
 * ubbd device remove
 */
static int dev_remove_finish(struct context *ctx, int ret)
{
	struct dev_ctx_data *ctx_data = (struct dev_ctx_data *)ctx->data;
	struct ubbd_device *ubbd_dev = ctx_data->ubbd_dev;

	if (ret) {
		ubbd_dev_err(ubbd_dev, "error in dev remove: %d.\n", ret);
		return ret;
	}
	ubbd_dev_close(ubbd_dev);
	ubbd_dev_release(ubbd_dev);

	return 0;
}


static int dev_remove(struct ubbd_device *ubbd_dev, struct context *ctx)
{
	struct context *remove_ctx;

	remove_ctx = dev_ctx_alloc(ubbd_dev, ctx, dev_remove_finish);
	if (!remove_ctx)
		return -ENOMEM;

	return ubbd_nl_req_remove(ubbd_dev, remove_ctx);
}

static int dev_remove_prepare_finish(struct context *ctx, int ret)
{
	struct dev_ctx_data *ctx_data = (struct dev_ctx_data *)ctx->data;
	struct ubbd_device *ubbd_dev = ctx_data->ubbd_dev;

	if (ret) {
		ubbd_dev_err(ubbd_dev, "error in dev remove: %d.\n", ret);
		return ret;
	}

	ret = dev_stop(ubbd_dev);
	if (ret) {
		ubbd_dev_err(ubbd_dev, "error in dev stop: %d,\n", ret);
		return ret;
	}

	dev_remove(ubbd_dev, ctx->parent);
	ctx->parent = NULL;
	return 0;
}

static int dev_remove_prepare(struct ubbd_device *ubbd_dev, bool force, struct context *ctx)
{
	struct context *remove_prepare_ctx;

	remove_prepare_ctx = dev_ctx_alloc(ubbd_dev, ctx, dev_remove_prepare_finish);
	if (!remove_prepare_ctx)
		return -ENOMEM;

	return ubbd_nl_req_remove_prepare(ubbd_dev, force, remove_prepare_ctx);
}

int ubbd_dev_remove(struct ubbd_device *ubbd_dev, bool force, struct context *ctx)
{
	int ret = 0;

	ubbd_dev_err(ubbd_dev, "status : %d.\n", ubbd_dev->status);

	switch (ubbd_dev->status) {
	case UBBD_DEV_STATUS_INIT:
		ubbd_dev_release(ubbd_dev);
		context_finish(ctx, 0);
		break;
	case UBBD_DEV_STATUS_OPENED:
		ubbd_err("opend\n");
		ubbd_dev_close(ubbd_dev);
		ubbd_dev_release(ubbd_dev);
		context_finish(ctx, 0);
		break;
	case UBBD_DEV_STATUS_DISK_PREPARED:
		ret = dev_remove(ubbd_dev, ctx);
		break;
	case UBBD_DEV_STATUS_RUNNING:
		ret = dev_remove_prepare(ubbd_dev, force, ctx);
		break;
	default:
		ubbd_dev_err(ubbd_dev, "Unknown status: %d\n", ubbd_dev->status);
		ret = -EINVAL;
	}

	if (ret)
		context_finish(ctx, ret);
	return ret;
}

/*
 * dev configure
 */
static int dev_config_finish(struct context *ctx, int ret)
{
	struct dev_ctx_data *ctx_data = (struct dev_ctx_data *)ctx->data;
	struct ubbd_device *ubbd_dev = ctx_data->ubbd_dev;

	if (ret) {
		ubbd_dev_err(ubbd_dev, "error in dev config: %d.\n", ret);
		return ret;
	}

	return 0;
}

int ubbd_dev_config(struct ubbd_device *ubbd_dev, int data_pages_reserve, struct context *ctx)
{
	struct context *config_ctx;

	config_ctx = dev_ctx_alloc(ubbd_dev, ctx, dev_config_finish);
	if (!config_ctx)
		return -ENOMEM;

	return ubbd_nl_req_config(ubbd_dev, data_pages_reserve, config_ctx);
}

static int reopen_dev(struct ubbd_nl_dev_status *dev_status)
{
	char *mmap_name;
	int fd;
	void *map;
	int ret;
	struct ubbd_dev_info *dev_info;
	struct ubbd_device *ubbd_dev;

	if (asprintf(&mmap_name, "/dev/uio%d", dev_status->uio_id) == -1) {
		ubbd_err("cont init mmap name\n");
		ret = -1;
		goto err_fail;
	}

	fd = open(mmap_name, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd == -1) {
		ubbd_err("could not open %s\n", mmap_name);
		ret = fd;
		goto err_mmap_name;
	}

	/* bring the map into memory */
	map = mmap(NULL, dev_status->uio_map_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		ubbd_err("could not mmap %s\n", mmap_name);
		ret = -1;
		goto err_fd_close;
	}

	dev_info = ubbd_uio_get_dev_info(map);
	ubbd_dev = ubbd_dev_create(dev_info);
	ubbd_dev_open(ubbd_dev);
	ubbd_dev->fd = fd;
	ubbd_dev->dev_id = dev_status->dev_id;
	ubbd_dev->uio_id = dev_status->uio_id;
	ubbd_dev->uio_map_size = dev_status->uio_map_size;
	ubbd_dev->map = map;

	pthread_create(&ubbd_dev->cmdproc_thread, NULL, cmd_process, ubbd_dev); 

	ubbd_err("version: %d\n", ubbd_dev->map->version);

	ubbd_dev->status = UBBD_DEV_STATUS_RUNNING;

	return 0;

err_fd_close:
	close(fd);
err_mmap_name:
	free(mmap_name);
err_fail:
	return ret;
}

static int cleanup_dev(struct ubbd_nl_dev_status *dev_status)
{
	ubbd_info("cleanup dev\n");
	return 0;
}

int ubd_dev_reopen_devs(void)
{
	struct ubbd_nl_dev_status *tmp_status, *next_status;
	LIST_HEAD(tmp_list);
	int ret;

	ret = ubbd_nl_dev_list(&tmp_list);
	list_for_each_entry_safe(tmp_status, next_status, &tmp_list, node) {
		list_del(&tmp_status->node);
		ubbd_dbg("tmp_status: dev_id: %d, uio_id: %d, status: %d\n", tmp_status->dev_id, tmp_status->uio_id, tmp_status->status);
		//if (tmp_status->status == UBBD_DEV_STATUS_RUNNING)
		if (1)
			reopen_dev(tmp_status);
		else
			cleanup_dev(tmp_status);
		free(tmp_status);
	}

	return ret;
}
