#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h> 
#include <unistd.h>

#include "utils.h"
#include "list.h"
#include "ubbd_dev.h"
#include "ubbd_backend_mgmt.h"

#include "ubbd_uio.h"
#include "ubbd_netlink.h"
#include "ubbd_backend.h"

LIST_HEAD(ubbd_dev_list);
pthread_mutex_t ubbd_dev_list_mutex = PTHREAD_MUTEX_INITIALIZER;
bool dev_checker_stop = false;

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

	ubbd_dev->status = UBBD_DEV_USTATUS_INIT;
	ubbd_atomic_set(&ubbd_dev->ref_count, 1);
	INIT_LIST_HEAD(&ubbd_dev->dev_node);
	pthread_mutex_init(&ubbd_dev->lock, NULL);
	ubbd_dev->num_queues = info->num_queues;
	memcpy(&ubbd_dev->dev_info, info, sizeof(*info));

	pthread_mutex_lock(&ubbd_dev_list_mutex);
	list_add_tail(&ubbd_dev->dev_node, &ubbd_dev_list);
	pthread_mutex_unlock(&ubbd_dev_list_mutex);

	return ubbd_dev;
}

int ubbd_dev_init(struct ubbd_device *ubbd_dev)
{
	int ret = 0;

	ret = ubbd_dev->dev_ops->init(ubbd_dev);
	if (ret)
		goto out;

	ubbd_dev->status = UBBD_DEV_USTATUS_OPENED;

out:
	return ret;
}

void ubbd_dev_release(struct ubbd_device *ubbd_dev)
{
	pthread_mutex_lock(&ubbd_dev_list_mutex);
	list_del_init(&ubbd_dev->dev_node);
	pthread_mutex_unlock(&ubbd_dev_list_mutex);

	ubbd_dev_put(ubbd_dev);
}

/*
 * ubbd device add
 */
int ubbd_dev_init_from_dev_status(struct ubbd_device *ubbd_dev, struct ubbd_nl_dev_status *dev_status)
{
	int ret = 0;

	ubbd_dev->dev_id = dev_status->dev_id;
	ubbd_dev->num_queues = dev_status->num_queues;
	memcpy(&ubbd_dev->queue_infos, &dev_status->queue_infos, sizeof(struct ubbd_queue_info) * UBBD_QUEUE_MAX);

	return ret;
}


extern pthread_t ubbdd_mgmt_thread;
extern pthread_t ubbdd_nl_thread;

extern void ubbdd_mgmt_stop_thread(void);
extern void ubbdd_mgmt_wait_thread(void);

static int backend_conf_setup(struct ubbd_device *ubbd_dev)
{
	int ret;
	struct ubbd_backend_conf backend_conf = { 0 };

	ubbd_conf_header_init(&backend_conf.conf_header, UBBD_CONF_TYPE_BACKEND);

	backend_conf.dev_id = ubbd_dev->dev_id;
	memcpy(&backend_conf.dev_info, &ubbd_dev->dev_info, sizeof(struct ubbd_dev_info));

	backend_conf.num_queues = ubbd_dev->num_queues;
	memcpy(&backend_conf.queue_infos, &ubbd_dev->queue_infos, sizeof(struct ubbd_queue_info) * UBBD_QUEUE_MAX);

	ret = ubbd_conf_write_backend_conf(&backend_conf);
	if (ret) {
		ubbd_err("failed to write backend_conf.\n");
		return ret;
	}

	return 0;
}

static int backend_start(struct ubbd_device *ubbd_dev, int backend_id, bool start_queues)
{
	char *dev_id_str;
	char *backend_id_str;
	char *start_queues_str;
	int ret;

	if (asprintf(&dev_id_str, "%d", ubbd_dev->dev_id) == -1) {
		ubbd_err("cont init dev_id_str\n");
		ret = -1;
		goto out;
	}

	if (asprintf(&backend_id_str, "%d", backend_id) == -1) {
		ubbd_err("cont init backend_id_str\n");
		ret = -1;
		goto free_dev_id_str;
	}

	if (asprintf(&start_queues_str, "%d", (start_queues? 1 : 0)) == -1) {
		ubbd_err("cont init backend_id_str\n");
		ret = -1;
		goto free_backend_id_str;
	}

	char *arg_list[] = {
		"ubbd-backend",
		"--dev-id",
		dev_id_str,
		"--backend-id",
		backend_id_str,
		"--start-queues",
		start_queues_str,
		NULL
	};

	ret = execute("ubbd-backend", arg_list);
	if (ret > 0)
		ret = 0;

	free(start_queues_str);
free_backend_id_str:
	free(backend_id_str);
free_dev_id_str:
	free(dev_id_str);
out:
	return ret;
}

static int start_backend_queue(struct ubbd_device *ubbd_dev, int backend_id, int queue_id)
{
	struct ubbd_backend_mgmt_rsp backend_rsp;
	struct ubbd_backend_mgmt_request backend_request = { 0 };
	int fd;
	int ret;

	backend_request.dev_id = ubbd_dev->dev_id;
	backend_request.backend_id = backend_id;
	backend_request.u.start_queue.queue_id = queue_id;
	backend_request.cmd = UBBD_BACKEND_MGMT_CMD_START_QUEUE;

	ret = ubbd_backend_request(&fd, &backend_request);
	if (ret)
		return ret;

	ret = ubbd_backend_response(fd, &backend_rsp, 5);

	return ret;
}

static int stop_backend_queue(struct ubbd_device *ubbd_dev, int backend_id, int queue_id)
{
	struct ubbd_backend_mgmt_rsp backend_rsp;
	struct ubbd_backend_mgmt_request backend_request = { 0 };
	int fd;
	int ret;

	backend_request.dev_id = ubbd_dev->dev_id;
	backend_request.backend_id = backend_id;
	backend_request.u.stop_queue.queue_id = queue_id;
	backend_request.cmd = UBBD_BACKEND_MGMT_CMD_STOP_QUEUE;

	ret = ubbd_backend_request(&fd, &backend_request);
	if (ret)
		return ret;

	ret = ubbd_backend_response(fd, &backend_rsp, 5);

	return ret;
}

static int backend_stop(struct ubbd_device *ubbd_dev, int backend_id)
{
	struct ubbd_backend_mgmt_rsp backend_rsp;
	struct ubbd_backend_mgmt_request backend_request = { 0 };
	int fd;
	int ret;

	backend_request.dev_id = ubbd_dev->dev_id;
	backend_request.backend_id = backend_id;
	backend_request.cmd = UBBD_BACKEND_MGMT_CMD_STOP;

	ret = ubbd_backend_request(&fd, &backend_request);
	if (ret)
		return ret;

	ret = ubbd_backend_response(fd, &backend_rsp, 5);

	return ret;
}

bool backend_stopped(void *data)
{
	struct ubbd_device *ubbd_dev = data;
	int ret;
	int i;
	struct ubbd_nl_dev_status dev_status = { 0 };
	bool stopped = false;

	ret = ubbd_nl_dev_status(ubbd_dev->dev_id, &dev_status);
	if (ret) {
		ubbd_err("failed to get status from netlink\n");
		goto out;
	}

	for (i = 0; i < dev_status.num_queues; i++) {
		if (dev_status.queue_infos[i].backend_pid != 0) {
			stopped = false;
			goto out;
		}
	}
	stopped = true;
out:
	return stopped;
}

int wait_for_backend_stopped(struct ubbd_device *ubbd_dev)
{
	return wait_condition(1000, 10000, backend_stopped, ubbd_dev);
}


static int dev_conf_write(struct ubbd_device *ubbd_dev)
{
	struct ubbd_dev_conf dev_conf = { 0 };

	ubbd_conf_header_init(&dev_conf.conf_header, UBBD_CONF_TYPE_DEVICE);

	memcpy(&dev_conf.dev_info, &ubbd_dev->dev_info, sizeof(struct ubbd_dev_info));
	dev_conf.current_backend_id = ubbd_dev->current_backend_id;
	dev_conf.new_backend_id = ubbd_dev->new_backend_id;
	dev_conf.dev_id = ubbd_dev->dev_id;

	return ubbd_conf_write_dev_conf(&dev_conf);
}

int dev_stop(struct ubbd_device *ubbd_dev)
{
	int ret;

	ubbd_dev->status = UBBD_DEV_USTATUS_STOPPING;

	if (backend_stopped(ubbd_dev)) {
		return 0;
	}

	ret = backend_stop(ubbd_dev, ubbd_dev->current_backend_id);
	if (ret)
		return ret;

	ret = wait_for_backend_stopped(ubbd_dev);
	if (ret) {
		ubbd_err("failed to wait for dev stopped: %d\n", ret);
		return ret;
	}

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

bool disk_running(void *data)
{
	struct ubbd_device *ubbd_dev = data;
	int ret;
	struct ubbd_nl_dev_status dev_status = { 0 };
	bool running = false;

	ret = ubbd_nl_dev_status(ubbd_dev->dev_id, &dev_status);
	if (ret) {
		ubbd_err("failed to get status from netlink\n");
		goto out;
	}

	if (dev_status.status == UBBD_DEV_STATUS_RUNNING) {
		running = true;
	}

out:
	return running;
}

int wait_disk_running(struct ubbd_device *ubbd_dev)
{
	return wait_condition(1000, 10000, disk_running, ubbd_dev);
}

int dev_add_disk_finish(struct context *ctx, int ret)
{
	struct dev_add_disk_data *add_disk_data = (struct dev_add_disk_data *)ctx->data;
	struct ubbd_device *ubbd_dev = add_disk_data->ubbd_dev;

	if (ret) {
		ubbd_dev_err(ubbd_dev, "error in add: %d.\n", ret);
		goto clean_dev;
	}

	ret = wait_disk_running(ubbd_dev);
	if (ret) {
		ubbd_dev_err(ubbd_dev, "error to wait disk running: %d\n", ret);
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

	ubbd_dev->current_backend_id = 0;
	ubbd_dev->new_backend_id = -1;

	ret = dev_conf_write(ubbd_dev);
	if (ret) {
		ubbd_err("failed to write dev_info.\n");
		goto clean_dev;
	}

	ret = backend_conf_setup(ubbd_dev);
	if (ret) {
		ubbd_err("backend_conf_setup failed: %d\n", ret);
		ret = -1;
		goto clean_dev;
	}

	ret = backend_start(ubbd_dev, ubbd_dev->current_backend_id, true);
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
	ret = ubbd_dev_init(ubbd_dev);
	if (ret) {
		goto release_dev;
	}

	ret = dev_add_dev(ubbd_dev, ctx);
	if (ret)
		goto release_dev;
	pthread_mutex_unlock(&ubbd_dev->lock);
	return ret;

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

	dev_stop(ubbd_dev);

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

static int get_backend_status(struct ubbd_device *ubbd_dev, int backend_id)
{
	struct ubbd_backend_mgmt_rsp backend_rsp;
	struct ubbd_backend_mgmt_request backend_request = { 0 };
	int fd;
	int ret;

	backend_request.dev_id = ubbd_dev->dev_id;
	backend_request.backend_id = backend_id;
	backend_request.cmd = UBBD_BACKEND_MGMT_CMD_GET_STATUS;

	ret = ubbd_backend_request(&fd, &backend_request);
	if (ret)
		return ret;

	ret = ubbd_backend_response(fd, &backend_rsp, 5);
	if (ret)
		return ret;

	return backend_rsp.u.get_status.status;
}

static int start_kernel_queue(struct ubbd_device *ubbd_dev, int queue_id)
{
	int ret;

	ret = ubbd_nl_start_queue(ubbd_dev, queue_id);
	if (ret) {
		ubbd_err("failed to start kernel queue: %d\n", ret);
		goto out;
	}

out:
	return ret;
}

static int stop_kernel_queue(struct ubbd_device *ubbd_dev, int queue_id)
{
	int ret;

	ret = ubbd_nl_stop_queue(ubbd_dev, queue_id);
	if (ret) {
		ubbd_err("failed to stop kernel queue: %d\n", ret);
		goto out;
	}

out:
	return ret;
}

static int dev_reset(struct ubbd_device *ubbd_dev)
{
	int ret;
	int i;

	if (ubbd_dev->current_backend_id != -1) {
		backend_stop(ubbd_dev, ubbd_dev->current_backend_id);
	}

	if (ubbd_dev->new_backend_id != -1) {
		backend_stop(ubbd_dev, ubbd_dev->new_backend_id);
	}

	ret = wait_for_backend_stopped(ubbd_dev);
	if (ret) {
		ubbd_err("failed to wait backend stopped in reset.\n");
		return ret;
	}

	/* reset backend id */
	ubbd_dev->current_backend_id = 0;
	ubbd_dev->new_backend_id = -1;

	ret = dev_conf_write(ubbd_dev);
	if (ret) {
		ubbd_err("failed to write dev_conf in reset.\n");
		return ret;
	}

	/* start current backend only */
	ret = backend_start(ubbd_dev, ubbd_dev->current_backend_id, true);
	if (ret) {
		ubbd_dev_err(ubbd_dev, "failed to start backend in reset\n");
		return ret;
	}

	for (i = 0; i < ubbd_dev->num_queues; i++) {
		ret = start_kernel_queue(ubbd_dev, i);
		if (ret) {
			ubbd_err("failed to start backend queue: %d\n", ret);
			return ret;
		}
	}

	return 0;
}

static int reopen_dev(struct ubbd_nl_dev_status *dev_status,
				struct ubbd_device **ubbd_dev_p)
{
	int ret;
	struct ubbd_device *ubbd_dev;
	struct ubbd_dev_conf *dev_conf;

	dev_conf = ubbd_conf_read_dev_conf(dev_status->dev_id);
	if (!dev_conf) {
		ubbd_err("failed to read dev config\n");
		return -1;
	}

	ubbd_dev = ubbd_dev_create(&dev_conf->dev_info);
	if (!ubbd_dev) {
		ret = -ENOMEM;
		free(dev_conf);
		goto err;
	}

	ubbd_dev->dev_id = dev_conf->dev_id;
	ubbd_dev->current_backend_id = dev_conf->current_backend_id;
	ubbd_dev->new_backend_id = dev_conf->new_backend_id;
	free(dev_conf);

	if (dev_status->status != UBBD_DEV_STATUS_RUNNING) {
		ubbd_dev->status = UBBD_DEV_USTATUS_STOPPING;
		goto out;
	}

	/* current_backend_id is always not -1 here.*/
	if (ubbd_dev->new_backend_id == -1 &&
			(get_backend_status(ubbd_dev, ubbd_dev->current_backend_id) == UBBD_BACKEND_STATUS_RUNNING)) {
		goto dev_running;
	}

	ret = dev_reset(ubbd_dev);
	if (ret) {
		ubbd_err("failed to reset dev: %d.", ret);
		goto release_dev;
	}

dev_running:
	ubbd_dev->status = UBBD_DEV_USTATUS_RUNNING;
out:
	*ubbd_dev_p = ubbd_dev;
	return 0;

release_dev:
	free(ubbd_dev);
err:
	return ret;
}

int ubbd_dev_reopen_devs(void)
{
	struct ubbd_device *ubbd_dev;
	struct ubbd_nl_list_result list_result = { 0 };
	struct ubbd_nl_dev_status dev_status = { 0 };
	int i;
	int ret;

	ret = ubbd_nl_dev_list(&list_result);
	if (ret) {
		ubbd_err("failed to list devs in reopen devs: %d\n", ret);
		return ret;
	}

	ubbd_err("num_devs: %d\n", list_result.num_devs);
	for (i = 0; i < list_result.num_devs; i++) {
		ret = ubbd_nl_dev_status(list_result.dev_ids[i], &dev_status);
		if (ret) {
			ubbd_err("failed to get status of dev: %d\n", list_result.dev_ids[i]);
			return ret;
		}
		ret = reopen_dev(&dev_status, &ubbd_dev);
		if (ret)
			return ret;

		if (dev_status.status != UBBD_DEV_STATUS_RUNNING)
			ubbd_dev_remove(ubbd_dev, false, NULL);
	}

	return 0;
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
		pthread_mutex_unlock(&ubbd_dev_tmp->lock);
		ubbd_dev_release(ubbd_dev_tmp);
        }
}

bool ubbd_dev_get(struct ubbd_device *ubbd_dev)
{
	if (!ubbd_atomic_add_unless(&ubbd_dev->ref_count, 1, 0)) {
		ubbd_err("use-after-free for ubbd device\n");
		return false;
	}

	return true;
}

void ubbd_dev_put(struct ubbd_device *ubbd_dev)
{
	if (ubbd_atomic_dec_and_test(&ubbd_dev->ref_count))
		ubbd_dev->dev_ops->release(ubbd_dev);
}

static int kernel_queue_get_status(int dev_id, int queue_id)
{
	struct ubbd_nl_dev_status dev_status = { 0 };
	int ret;
	int status;

	ret = ubbd_nl_dev_status(dev_id, &dev_status);
	if (ret) {
		ubbd_err("failed to get status from netlink\n");
		return ret;
	}

	status = dev_status.queue_infos[queue_id].status;

	return status;
}

static int wait_kernel_queue_stopped(int dev_id, int queue_id)
{
	int ret;
	int i;

	for (i = 0; i < 1000; i++) {
		ret = kernel_queue_get_status(dev_id, queue_id);
		if (ret < 0)
			continue;
		if (ret == UBBD_QUEUE_STATUS_STOPPED)
			return 0;
		usleep(100000);
	}
	return -1;
}

static int kernel_queue_get_backend_pid(int dev_id, int queue_id)
{
	struct ubbd_nl_dev_status dev_status = { 0 };
	int ret;
	pid_t backend_pid;

	ret = ubbd_nl_dev_status(dev_id, &dev_status);
	if (ret) {
		ubbd_err("failed to get status from netlink\n");
		return ret;
	}

	backend_pid = dev_status.queue_infos[queue_id].backend_pid;

	return backend_pid;
}

static int wait_kernel_queue_no_backend(int dev_id, int queue_id)
{
	int ret;
	int i;

	for (i = 0; i < 1000; i++) {
		ret = kernel_queue_get_backend_pid(dev_id, queue_id);
		if (ret < 0)
			continue;
		if (ret == 0)
			return 0;
		usleep(100000);
	}
	return -1;
}

static int get_backend_queue_status(struct ubbd_device *ubbd_dev, int backend_id, int queue_id)
{
	struct ubbd_backend_mgmt_rsp backend_rsp;
	struct ubbd_backend_mgmt_request backend_request = { 0 };
	int fd;
	int ret;

	backend_request.dev_id = ubbd_dev->dev_id;
	backend_request.backend_id = backend_id;
	backend_request.u.get_queue_status.queue_id = queue_id;
	backend_request.cmd = UBBD_BACKEND_MGMT_CMD_GET_QUEUE_STATUS;

	ret = ubbd_backend_request(&fd, &backend_request);
	if (ret)
		return ret;

	ret = ubbd_backend_response(fd, &backend_rsp, 5);
	if (ret)
		return ret;

	return backend_rsp.u.get_queue_status.status;
}

static int wait_backend_queue_ready(struct ubbd_device *ubbd_dev, int backend_id, int queue_id)
{
	int ret;
	int i;

	for (i = 0; i < 1000; i++) {
		ret = get_backend_queue_status(ubbd_dev, backend_id, queue_id);
		if (ret < 0)
			continue;

		if (ret == UBBD_QUEUE_USTATUS_RUNNING)
			return 0;
		usleep(100000);
	}
	return -1;
}


static int ubbd_backend_start_new_backend(struct ubbd_device *ubbd_dev)
{
	if (ubbd_dev->new_backend_id != -1) {
		ubbd_err("new_backend_id is not -1, cant start new backend\n");
		return -1;
	}

	return (ubbd_dev->current_backend_id == 0? 1 : 0);
}

static int ubbd_backend_finish_new_backend(struct ubbd_device *ubbd_dev)
{
	if (ubbd_dev->new_backend_id == -1) {
		ubbd_err("new_backend_id is -1, cant finish new backend\n");
		return -1;
	}

	ubbd_dev->current_backend_id = ubbd_dev->new_backend_id;
	ubbd_dev->new_backend_id = -1;

	return 0;
}

int ubbd_dev_restart(struct ubbd_device *ubbd_dev, int restart_mode)
{
	int ret;

again:
	if (restart_mode == UBBD_DEV_RESTART_MODE_DEV || 
			(restart_mode == UBBD_DEV_RESTART_MODE_DEFAULT && ubbd_dev->num_queues == 1)) {
		ret = dev_reset(ubbd_dev);
		if (ret) {
			ubbd_dev_err(ubbd_dev, "failed to reset ubbd_dev.\n");
			return ret;
		}
	} else {
		int i;
		int new_backend_id;

		new_backend_id = ubbd_backend_start_new_backend(ubbd_dev);
		if (new_backend_id < 0) {
			ubbd_err("failed to start new backend for restart\n");
			ret = -1;
			goto err;
		}
		ubbd_dev->new_backend_id = new_backend_id;

		ret = dev_conf_write(ubbd_dev);
		if (ret) {
			ubbd_err("failed to write dev_conf after start new backend.\n");
			goto err;
		}

		ret = backend_start(ubbd_dev, ubbd_dev->new_backend_id, false);

		for (i = 0; i < ubbd_dev->num_queues; i++) {
			ret = stop_kernel_queue(ubbd_dev, i);
			if (ret) {
				ubbd_err("failed to stop kernel queue: %d\n", ret);
				goto err;
			}
			ret = wait_kernel_queue_stopped(ubbd_dev->dev_id, i);
			if (ret) {
				ubbd_err("failed to wait kernel queue stopped.\n");
				goto err;
			}

			ret = stop_backend_queue(ubbd_dev, ubbd_dev->current_backend_id, i);
			if (ret) {
				ubbd_err("failed to stop backend queue: %d\n", ret);
				goto err;
			}

			ret = wait_kernel_queue_no_backend(ubbd_dev->dev_id, i);
			if (ret) {
				ubbd_err("failed to wait kernel queue no backend.\n");
				goto err;
			}

			ret = start_backend_queue(ubbd_dev, ubbd_dev->new_backend_id, i);
			if (ret) {
				ubbd_err("failed to start backend queue: %d\n", ret);
				goto err;
			}

			ret = wait_backend_queue_ready(ubbd_dev, ubbd_dev->new_backend_id, i);
			if (ret) {
				ubbd_err("failed to wait backend queue ready: %d\n", ret);
				goto err;
			}

			ret = start_kernel_queue(ubbd_dev, i);
			if (ret) {
				ubbd_err("failed to start kernel queue: %d\n", ret);
				goto err;
			}
		}

		ret = backend_stop(ubbd_dev, ubbd_dev->current_backend_id);
		if (ret) {
			ubbd_err("failed to stop current backend before finish new backend.\n");
			goto err;
		}

		ret = ubbd_backend_finish_new_backend(ubbd_dev);
		if (ret) {
			ubbd_err("failed to finish new backend.\n");
			goto err;
		}

		ret = dev_conf_write(ubbd_dev);
		if (ret) {
			ubbd_err("failed to write dev_conf after finish new backend.\n");
			goto err;
		}
	}

	return ret;
err:
	restart_mode = UBBD_DEV_RESTART_MODE_DEV;
	goto again;
}

static int get_kernel_dev_status(struct ubbd_device *ubbd_dev)
{
	int ret;
	struct ubbd_nl_dev_status dev_status = { 0 };

	ret = ubbd_nl_dev_status(ubbd_dev->dev_id, &dev_status);
	if (ret) {
		ubbd_err("failed to get status from netlink\n");
		goto out;
	}

	return dev_status.status;
out:
	return -1;
}

static void *ubbd_dev_checker_fn(void *arg)
{
        struct ubbd_device *ubbd_dev = NULL;
	int ret;

	while (!dev_checker_stop) {
		pthread_mutex_lock(&ubbd_dev_list_mutex);
		list_for_each_entry(ubbd_dev, &ubbd_dev_list, dev_node) {
			if (get_kernel_dev_status(ubbd_dev) == UBBD_DEV_STATUS_REMOVING)
				continue;

			if (backend_stopped(ubbd_dev)) {
				pthread_mutex_unlock(&ubbd_dev_list_mutex);
				ret = dev_reset(ubbd_dev);
				if (ret) {
					ubbd_dev_err(ubbd_dev, "reset dev failed in checker: %d\n", ret);
				}
				goto again;
			}
		}
		pthread_mutex_unlock(&ubbd_dev_list_mutex);
again:
		sleep(5);
	}

	return NULL;
}

pthread_t ubbd_dev_checker_thread;

int ubbd_dev_checker_start_thread()
{
	return pthread_create(&ubbd_dev_checker_thread, NULL, ubbd_dev_checker_fn, NULL);
}

void ubbd_dev_checker_stop_thread(void)
{
	dev_checker_stop = true;
}

int ubbd_dev_checker_wait_thread(void)
{
	void *join_retval;

	return pthread_join(ubbd_dev_checker_thread, &join_retval);
}
