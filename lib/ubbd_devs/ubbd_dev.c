#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <pthread.h>

#include "utils.h"
#include "list.h"
#include "ubbd_dev.h"
#include "ubbd_uio.h"
#include "ubbd_netlink.h"


static bool compr_space_enough(struct ubbd_queue *ubbd_q, uint32_t required)
{
	struct ubbd_sb *sb = ubbd_q->uio_info.map;
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

struct ubbd_ce *get_available_ce(struct ubbd_queue *ubbd_q)
{
	/*
	 * dev->req_lock held
	 */
	struct ubbd_sb *sb = ubbd_q->uio_info.map;

	while (!compr_space_enough(ubbd_q, sizeof(struct ubbd_ce))) {
		pthread_mutex_unlock(&ubbd_q->req_lock);
		ubbd_err(" compr not enough head: %u, tail: %u\n", sb->compr_head, sb->compr_tail);
		ubbdlib_processing_complete(ubbd_q);
                usleep(50000);
		pthread_mutex_lock(&ubbd_q->req_lock);
	}

	return device_comp_head(ubbd_q);
}

static void wait_for_compr_empty(struct ubbd_queue *ubbd_q)
{
	struct ubbd_sb *sb = ubbd_q->uio_info.map;
	struct ubbd_device *ubbd_dev = ubbd_q->ubbd_dev;
 
         ubbd_info("waiting for ring to clear\n");
         while (sb->compr_head != sb->compr_tail) {
		 ubbd_info("head: %u, tail: %u\n", sb->compr_head, sb->compr_tail);
                 usleep(50000);
		 if (ubbd_dev->status == UBBD_DEV_USTATUS_STOPPING) {
			 ubbd_err("ubbd device is stopping\n");
			 break;
		 }
	 }
         ubbd_info("ring clear\n");
}

static void handle_cmd(struct ubbd_queue *ubbd_q, struct ubbd_se *se);
void *cmd_process(void *arg)
{
	struct ubbd_queue *ubbd_q = arg;
	struct ubbd_se *se;
	struct ubbd_sb *sb = ubbd_q->uio_info.map;
	uint32_t op_len = 0;

	struct pollfd pollfds[128];
	int ret;

	ubbdlib_processing_complete(ubbd_q);
	wait_for_compr_empty(ubbd_q);

	ubbd_q->se_to_handle = sb->cmd_tail;
	ubbd_dbg("cmd_tail: %u, cmd_head: %u\n", sb->cmd_tail, sb->cmd_head);

	while (1) {
		while (1) {
			ubbdlib_processing_start(ubbd_q);

			se = device_cmd_to_handle(ubbd_q);
			if (se == device_cmd_head(ubbd_q)) {
				break;
			}
			op_len = ubbd_se_hdr_get_len(se->header.len_op);
			ubbd_dbg("len_op: %x\n", se->header.len_op);
			ubbd_dbg("op: %d, length: %u\n", ubbd_se_hdr_get_op(se->header.len_op), ubbd_se_hdr_get_len(se->header.len_op));
			if (ubbd_se_hdr_get_op(se->header.len_op) != UBBD_OP_PAD)
				ubbd_dbg("se id: %llu\n", se->priv_data);
			handle_cmd(ubbd_q, se);
			UBBD_UPDATE_CMD_TO_HANDLE(ubbd_q, sb, op_len);
			ubbd_dbg("finish handle_cmd\n");
		}

poll:
		pollfds[0].fd = ubbd_q->uio_info.fd;
		pollfds[0].events = POLLIN;
		pollfds[0].revents = 0;

		ret = poll(pollfds, 1, 60);
		if (ret == -1) {
			ubbd_err("poll() returned %d, exiting\n", ret);
			return NULL;
		}

		if (ubbd_q->ubbd_dev->status == UBBD_DEV_USTATUS_STOPPING) {
			ubbd_err("exit cmd_process\n");
			return NULL;
		}

		ubbd_dbg("poll cmd: %d\n", ret);
		if (!pollfds[0].revents) {
			goto poll;
		}

	}

	return NULL;
}



static void handle_cmd(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	struct ubbd_se_hdr *header = &se->header;
	struct ubbd_device *ubbd_dev = ubbd_q->ubbd_dev;
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
		ubbdlib_processing_complete(ubbd_q);
		break;
	case UBBD_OP_WRITE:
		ubbd_dbg("UBBD_OP_WRITE\n");
		ret = ubbd_dev->dev_ops->writev(ubbd_q, se);
		break;
	case UBBD_OP_READ:
		ubbd_dbg("UBBD_OP_READ\n");
		ret = ubbd_dev->dev_ops->readv(ubbd_q, se);
		break;
	case UBBD_OP_FLUSH:
		ubbd_dbg("UBBD_OP_FLUSH\n");
		if (!ubbd_dev->dev_ops->flush) {
			ret = -EOPNOTSUPP;
			ubbd_dev_err(ubbd_dev, "flush is not supportted.\n");
			goto out;
		}
		ret = ubbd_dev->dev_ops->flush(ubbd_q, se);
		break;
	case UBBD_OP_DISCARD:
		ubbd_dbg("UBBD_OP_DISCARD\n");
		if (!ubbd_dev->dev_ops->discard) {
			ret = -EOPNOTSUPP;
			ubbd_dev_err(ubbd_dev, "discard is not supportted.\n");
			goto out;
		}
		ret = ubbd_dev->dev_ops->discard(ubbd_q, se);
		break;
	case UBBD_OP_WRITE_ZEROS:
		ubbd_dbg("UBBD_OP_WRITE_ZEROS\n");
		if (!ubbd_dev->dev_ops->write_zeros) {
			ret = -EOPNOTSUPP;
			ubbd_dev_err(ubbd_dev, "write_zeros is not supportted.\n");
			goto out;
		}
		ret = ubbd_dev->dev_ops->write_zeros(ubbd_q, se);
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
pthread_mutex_t ubbd_dev_list_mutex = PTHREAD_MUTEX_INITIALIZER;

struct ubbd_device *find_ubbd_dev(int dev_id)
{
        struct ubbd_device *ubbd_dev = NULL;
        struct ubbd_device *ubbd_dev_tmp;

	pthread_mutex_lock(&ubbd_dev_list_mutex);
        list_for_each_entry(ubbd_dev_tmp, &ubbd_dev_list, dev_node) {
                if (ubbd_dev_tmp->dev_id == dev_id) {
                        ubbd_dev = ubbd_dev_tmp;
                        break;
                }
        }
	pthread_mutex_unlock(&ubbd_dev_list_mutex);

        return ubbd_dev;
}

static void ubbd_dev_init(struct ubbd_device *ubbd_dev)
{
	ubbd_dev->status = UBBD_DEV_USTATUS_INIT;
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

struct ubbd_null_device *create_null_dev(void)
{
	struct ubbd_device *ubbd_dev;
	struct ubbd_null_device *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	ubbd_dev = &dev->ubbd_dev;
	ubbd_dev->dev_type = UBBD_DEV_TYPE_NULL;
	ubbd_dev->dev_ops = &null_dev_ops;

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
	} else if (info->type == UBBD_DEV_TYPE_NULL){
		struct ubbd_null_device *null_dev;

		null_dev = create_null_dev();
		if (!null_dev)
			return NULL;
		ubbd_dev = &null_dev->ubbd_dev;
		ubbd_dev->dev_size = info->null.size;
	}else {
		ubbd_err("Unknown dev type\n");
		return NULL;
	}

	ubbd_dev_init(ubbd_dev);
	memcpy(&ubbd_dev->dev_info, info, sizeof(*info));

	pthread_mutex_lock(&ubbd_dev_list_mutex);
	list_add_tail(&ubbd_dev->dev_node, &ubbd_dev_list);
	pthread_mutex_unlock(&ubbd_dev_list_mutex);

	return ubbd_dev;
}

int ubbd_dev_open(struct ubbd_device *ubbd_dev)
{
	int ret = 0;

	ret = ubbd_dev->dev_ops->open(ubbd_dev);
	if (ret)
		goto out;

	ubbd_dev->status = UBBD_DEV_USTATUS_OPENED;

out:
	return ret;
}

void ubbd_dev_close(struct ubbd_device *ubbd_dev)
{

	ubbd_dev->dev_ops->close(ubbd_dev);
	ubbd_dev->status = UBBD_DEV_USTATUS_INIT;
}

void ubbd_dev_release(struct ubbd_device *ubbd_dev)
{
	pthread_mutex_lock(&ubbd_dev_list_mutex);
	list_del_init(&ubbd_dev->dev_node);
	pthread_mutex_unlock(&ubbd_dev_list_mutex);

	ubbd_dev->dev_ops->release(ubbd_dev);
}

/*
 * ubbd device add
 */

int queue_setup(struct ubbd_queue *ubbd_q)
{
	int ret;
	struct ubbd_device *ubbd_dev = ubbd_q->ubbd_dev;

	ret = device_open_shm(&ubbd_q->uio_info);
	if (ret) {
		ubbd_dev_err(ubbd_dev, "failed to open shm: %d\n", ret);
		goto out;
	}

	memcpy(ubbd_uio_get_dev_info(ubbd_q->uio_info.map),
			&ubbd_dev->dev_info, sizeof(struct ubbd_dev_info));

	ret = pthread_create(&ubbd_q->cmdproc_thread, NULL, cmd_process, ubbd_q);
	if (ret) {
		ubbd_dev_err(ubbd_dev, "failed to create cmdproc_thread: %d\n", ret);
		goto out;
	}
out:
	return ret;
}

int dev_setup(struct ubbd_device *ubbd_dev)
{
	struct ubbd_queue *ubbd_q;
	int ret;
	int i;

	for (i = 0; i < ubbd_dev->num_queues; i++) {
		ubbd_q = &ubbd_dev->queues[i];
		ubbd_q->ubbd_dev = ubbd_dev;
		pthread_mutex_init(&ubbd_q->req_lock, NULL);
		ret = queue_setup(ubbd_q);
		if (ret)
			goto out;
	}

out:
	return ret;
}

static int stop_queues(struct ubbd_device *ubbd_dev)
{
	int i;
	int ret;
	struct ubbd_queue *ubbd_q;
	void *join_retval;

	for (i = 0; i < ubbd_dev->num_queues; i++) {
		ubbd_q = &ubbd_dev->queues[i];

		if (ubbd_q->cmdproc_thread) {
			ret = pthread_join(ubbd_q->cmdproc_thread, &join_retval);
			if (ret)
				return ret;
		}
		device_close_shm(&ubbd_q->uio_info);
	}

	return 0;
}

int dev_stop(struct ubbd_device *ubbd_dev)
{
	int ret;

	ubbd_dev->status = UBBD_DEV_USTATUS_STOPPING;
	ret = stop_queues(ubbd_dev);
	if (ret)
		return ret;

	free(ubbd_dev->queues);
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

struct dev_add_disk_data {
	struct ubbd_device *ubbd_dev;
};

int dev_add_disk_finish(struct context *ctx, int ret)
{
	struct dev_add_disk_data *add_disk_data = (struct dev_add_disk_data *)ctx->data;
	struct ubbd_device *ubbd_dev = add_disk_data->ubbd_dev;

	if (ret) {
		ubbd_dev_err(ubbd_dev, "error in add: %d.\n", ret);
		goto clean_dev;
	}

	pthread_mutex_lock(&ubbd_dev->lock);
	ubbd_dev->status = UBBD_DEV_USTATUS_RUNNING;
	pthread_mutex_unlock(&ubbd_dev->lock);

	return ret;

clean_dev:
	ubbd_dev_err(ubbd_dev, "clean dev up.\n");
	if (ubbd_dev_remove(ubbd_dev, false, NULL))
		ubbd_err("failed to cleanup dev.\n");
	return ret;
}

int dev_add_disk(struct ubbd_device *ubbd_dev, struct context *ctx)
{
	struct context *add_disk_ctx;
	struct dev_add_disk_data *add_disk_data;
	int ret;

	add_disk_ctx = context_alloc(sizeof(struct dev_add_disk_data));
	if (!add_disk_ctx) {
		ret = -ENOMEM;
		goto out;
	}

	add_disk_data = (struct dev_add_disk_data *)add_disk_ctx->data;
	add_disk_data->ubbd_dev = ubbd_dev;

	add_disk_ctx->finish = dev_add_disk_finish;
	add_disk_ctx->parent = ctx;

	ret = ubbd_nl_req_add_disk(ubbd_dev, add_disk_ctx);
	if (ret) {
		ubbd_dev_err(ubbd_dev, "failed to start add: %d\n", ret);
		context_free(add_disk_ctx);
		goto out;
	}

out:
	return ret;
}

struct dev_add_dev_data {
	struct ubbd_device *ubbd_dev;
};

int dev_add_dev_finish(struct context *ctx, int ret)
{
	struct dev_add_dev_data *add_dev_data = (struct dev_add_dev_data *)ctx->data;
	struct ubbd_device *ubbd_dev = add_dev_data->ubbd_dev;

	if (ret) {
		ubbd_dev_err(ubbd_dev, "error in add_dev: %d.\n", ret);
		goto clean_dev;
	}

	pthread_mutex_lock(&ubbd_dev->lock);
	/* advance dev status into ADD_DEVD */
	ubbd_dev->status = UBBD_DEV_USTATUS_PREPARED;

	ret = dev_setup(ubbd_dev);
	if (ret) {
		goto clean_dev;
	}

	/*
	 * prepare is almost done, let's start add,
	 * and pass the parent_ctx to add req.
	 */
	ret = dev_add_disk(ubbd_dev, ctx->parent);
	if (ret) {
		goto clean_dev;
	}

	/* parent will be finished by add cmd */
	ctx->parent = NULL;
	pthread_mutex_unlock(&ubbd_dev->lock);

	return 0;
clean_dev:
	pthread_mutex_unlock(&ubbd_dev->lock);
	ubbd_dev_err(ubbd_dev, "clean dev up.\n");
	if (ubbd_dev_remove(ubbd_dev, false, NULL))
		ubbd_err("failed to cleanup dev.\n");
	return ret;
}

int dev_add_dev(struct ubbd_device *ubbd_dev, struct context *ctx)
{
	struct context *add_dev_ctx;
	struct dev_add_dev_data *add_dev_data;
	int ret;

	add_dev_ctx = context_alloc(sizeof(struct dev_add_dev_data));
	if (!add_dev_ctx) {
		return -ENOMEM;
	}

	add_dev_data = (struct dev_add_dev_data *)add_dev_ctx->data;
	add_dev_data->ubbd_dev = ubbd_dev;

	add_dev_ctx->finish = dev_add_dev_finish;
	add_dev_ctx->parent = ctx;

	ret = ubbd_nl_req_add_dev(ubbd_dev, add_dev_ctx);
	if (ret)
		context_free(add_dev_ctx);
	return ret;
}

int ubbd_dev_add(struct ubbd_device *ubbd_dev, struct context *ctx)
{
	int ret;

	pthread_mutex_lock(&ubbd_dev->lock);
	ret = ubbd_dev_open(ubbd_dev);
	if (ret) {
		goto release_dev;
	}

	ret = dev_add_dev(ubbd_dev, ctx);
	if (ret)
		goto close_dev;
	pthread_mutex_unlock(&ubbd_dev->lock);
	return ret;

close_dev:
	ubbd_dev_close(ubbd_dev);
release_dev:
	ubbd_dev_release(ubbd_dev);
	pthread_mutex_unlock(&ubbd_dev->lock);

	return ret;
}

/*
 * ubbd device remove
 */
static int dev_remove_dev_finish(struct context *ctx, int ret)
{
	struct dev_ctx_data *ctx_data = (struct dev_ctx_data *)ctx->data;
	struct ubbd_device *ubbd_dev = ctx_data->ubbd_dev;

	if (ret) {
		ubbd_dev_err(ubbd_dev, "error in dev remove: %d.\n", ret);
		return ret;
	}
	pthread_mutex_lock(&ubbd_dev->lock);
	ubbd_dev_close(ubbd_dev);
	pthread_mutex_unlock(&ubbd_dev->lock);
	ubbd_dev_release(ubbd_dev);

	return 0;
}


static int dev_remove_dev(struct ubbd_device *ubbd_dev, struct context *ctx)
{
	struct context *remove_ctx;
	int ret;

	remove_ctx = dev_ctx_alloc(ubbd_dev, ctx, dev_remove_dev_finish);
	if (!remove_ctx)
		return -ENOMEM;

	ret = ubbd_nl_req_remove_dev(ubbd_dev, remove_ctx);
	if (ret)
		context_free(remove_ctx);

	return ret;
}

static int dev_remove_disk_finish(struct context *ctx, int ret)
{
	struct dev_ctx_data *ctx_data = (struct dev_ctx_data *)ctx->data;
	struct ubbd_device *ubbd_dev = ctx_data->ubbd_dev;

	if (ret) {
		ubbd_dev_err(ubbd_dev, "error in dev remove: %d.\n", ret);
		return ret;
	}

	pthread_mutex_lock(&ubbd_dev->lock);

	ret = dev_stop(ubbd_dev);
	if (ret) {
		pthread_mutex_unlock(&ubbd_dev->lock);
		ubbd_dev_err(ubbd_dev, "error in dev stop: %d,\n", ret);
		return ret;
	}

	dev_remove_dev(ubbd_dev, ctx->parent);
	ctx->parent = NULL;
	pthread_mutex_unlock(&ubbd_dev->lock);

	return 0;
}

static int dev_remove_disk(struct ubbd_device *ubbd_dev, bool force, struct context *ctx)
{
	struct context *remove_disk_ctx;
	int ret;

	remove_disk_ctx = dev_ctx_alloc(ubbd_dev, ctx, dev_remove_disk_finish);
	if (!remove_disk_ctx)
		return -ENOMEM;

	ret = ubbd_nl_req_remove_disk(ubbd_dev, force, remove_disk_ctx);
	if (ret)
		context_free(remove_disk_ctx);

	return ret;
}

int ubbd_dev_remove(struct ubbd_device *ubbd_dev, bool force, struct context *ctx)
{
	int ret = 0;

	ubbd_dev_err(ubbd_dev, "status : %d.\n", ubbd_dev->status);

	pthread_mutex_lock(&ubbd_dev->lock);
	switch (ubbd_dev->status) {
	case UBBD_DEV_USTATUS_INIT:
		ubbd_dev_release(ubbd_dev);
		break;
	case UBBD_DEV_USTATUS_OPENED:
		ubbd_err("opend\n");
		ubbd_dev_close(ubbd_dev);
		ubbd_dev_release(ubbd_dev);
		break;
	case UBBD_DEV_USTATUS_PREPARED:
	case UBBD_DEV_USTATUS_RUNNING:
	case UBBD_DEV_USTATUS_STOPPING:
		ret = dev_remove_disk(ubbd_dev, force, ctx);
		break;
	default:
		ubbd_dev_err(ubbd_dev, "Unknown status: %d\n", ubbd_dev->status);
		ret = -EINVAL;
	}
	pthread_mutex_unlock(&ubbd_dev->lock);

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
	int ret;

	pthread_mutex_lock(&ubbd_dev->lock);
	config_ctx = dev_ctx_alloc(ubbd_dev, ctx, dev_config_finish);
	if (!config_ctx)
		return -ENOMEM;

	ret = ubbd_nl_req_config(ubbd_dev, data_pages_reserve, config_ctx);
	pthread_mutex_unlock(&ubbd_dev->lock);
	if (ret)
		context_free(config_ctx);

	return ret;
}

static int reopen_dev(struct ubbd_nl_dev_status *dev_status,
				struct ubbd_device **ubbd_dev_p)
{
	int ret;
	struct ubbd_dev_info *dev_info;
	struct ubbd_device *ubbd_dev;
	struct ubbd_uio_info uio_info = { .uio_id = dev_status->queue_infos[0].uio_id,
				.uio_map_size = dev_status->queue_infos[0].uio_map_size };
	int i;

	ret = device_open_shm(&uio_info);
	if (ret)
		goto err_fail;

	dev_info = ubbd_uio_get_dev_info(uio_info.map);
	ubbd_dev = ubbd_dev_create(dev_info);
	device_close_shm(&uio_info);
	if (!ubbd_dev) {
		ret = -ENOMEM;
		goto err_close;
	}

	if (dev_status->status != UBBD_DEV_STATUS_RUNNING) {
		ubbd_dev->status = UBBD_DEV_USTATUS_STOPPING;
		goto out;
	}

	ret = ubbd_dev_open(ubbd_dev);
	if (ret)
		goto release_dev;

	ubbd_dev->dev_id = dev_status->dev_id;
	ubbd_dev->num_queues = dev_status->num_queues;

	ubbd_dev->queues = calloc(ubbd_dev->num_queues, sizeof(struct ubbd_queue));
	if (!ubbd_dev->queues) {
		ubbd_err("failed to alloc queues\n");
		ret = -ENOMEM;
		goto close_dev;
	}

	for (i = 0; i < ubbd_dev->num_queues; i++) {
		ubbd_dev->queues[i].uio_info.uio_id = dev_status->queue_infos[i].uio_id;
		ubbd_dev->queues[i].uio_info.uio_map_size = dev_status->queue_infos[i].uio_map_size;
	}

	ret = dev_setup(ubbd_dev);
	if (ret)
		goto destroy_queues;

	ubbd_dev->status = UBBD_DEV_USTATUS_RUNNING;

out:
	*ubbd_dev_p = ubbd_dev;

	return 0;

destroy_queues:

	//ubbd_dev_destroy_queues(ubbd_dev);
close_dev:
	ubbd_dev_close(ubbd_dev);
release_dev:
	ubbd_dev_release(ubbd_dev);
err_close:
	device_close_shm(&uio_info);
err_fail:
	return ret;
}

int ubbd_dev_reopen_devs(void)
{
	struct ubbd_nl_dev_status *tmp_status, *next_status;
	LIST_HEAD(tmp_list);
	struct ubbd_device *ubbd_dev;
	int ret;

	ret = ubbd_nl_dev_list(&tmp_list);
	list_for_each_entry_safe(tmp_status, next_status, &tmp_list, node) {
		list_del(&tmp_status->node);
		ubbd_err("tmp_status: %p\n", tmp_status);
		ret = reopen_dev(tmp_status, &ubbd_dev);
		ubbd_err("ubbd_Dev: %p, status: %d\n", ubbd_dev, tmp_status->status);
		if (ret)
			return ret;

		if (tmp_status->status != UBBD_DEV_STATUS_RUNNING)
			ubbd_dev_remove(ubbd_dev, false, NULL);
		free(tmp_status);
	}

	return ret;
}

void ubbd_dev_stop_devs(void)
{
        struct ubbd_device *ubbd_dev_tmp, *next;
	LIST_HEAD(tmp_list);

	pthread_mutex_lock(&ubbd_dev_list_mutex);
	list_splice_init(&ubbd_dev_list, &tmp_list);
	pthread_mutex_unlock(&ubbd_dev_list_mutex);

        list_for_each_entry_safe(ubbd_dev_tmp, next, &tmp_list, dev_node) {
		pthread_mutex_lock(&ubbd_dev_tmp->lock);
		dev_stop(ubbd_dev_tmp);
		ubbd_dev_close(ubbd_dev_tmp);
		pthread_mutex_unlock(&ubbd_dev_tmp->lock);
		ubbd_dev_release(ubbd_dev_tmp);
        }
}

void ubbd_dev_add_ce(struct ubbd_queue *ubbd_q, uint64_t priv_data,
		int result)
{
	struct ubbd_ce *ce;
	struct ubbd_sb *sb = ubbd_q->uio_info.map;

	pthread_mutex_lock(&ubbd_q->req_lock);
	ce = get_available_ce(ubbd_q);
	memset(ce, 0, sizeof(*ce));
	ce->priv_data = priv_data;
	ce->flags = 0;

	ce->result = result;
	ubbd_dbg("append ce: %llu, result: %d\n", ce->priv_data, ce->result);
	UBBD_UPDATE_DEV_COMP_HEAD(ubbd_q, sb, ce);
	pthread_mutex_unlock(&ubbd_q->req_lock);
	ubbdlib_processing_complete(ubbd_q);
}
