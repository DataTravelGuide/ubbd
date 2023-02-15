#define _GNU_SOURCE
#include <pthread.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "utils.h"
#include "ubbd_dev.h"
#include "ubbd_daemon_mgmt.h"
#include "ubbd_backend_mgmt.h"

extern struct list_head ubbd_dev_list;
extern pthread_mutex_t ubbd_dev_list_mutex;

struct mgmt_ctx_data {
	int fd;
	struct ubbd_device *ubbd_dev;
};

static int mgmt_map_finish(struct context *ctx, int ret)
{
	struct mgmt_ctx_data *rsp_data = (struct mgmt_ctx_data *)ctx->data;
	int fd = rsp_data->fd;
	struct ubbdd_mgmt_rsp mgmt_rsp = {0};

	ubbd_dev_info(rsp_data->ubbd_dev, "map finish write rsp to fd: %d, ret: %d\n", fd, ret);
	mgmt_rsp.ret = ret;
	if (!ret) {
		sprintf(mgmt_rsp.add.path, "/dev/ubbd%d", 
				rsp_data->ubbd_dev->dev_id);
	}
	write(fd, &mgmt_rsp, sizeof(mgmt_rsp));
	close(fd);
	ubbd_dev_put(rsp_data->ubbd_dev);

	return 0;
}

static int mgmt_generic_finish(struct context *ctx, int ret)
{
	struct mgmt_ctx_data *rsp_data = (struct mgmt_ctx_data *)ctx->data;
	int fd = rsp_data->fd;
	struct ubbdd_mgmt_rsp mgmt_rsp = {0};

	ubbd_dev_info(rsp_data->ubbd_dev, "write rsp to fd: %d, ret: %d\n", fd, ret);
	mgmt_rsp.ret = ret;
	write(fd, &mgmt_rsp, sizeof(mgmt_rsp));
	close(fd);
	ubbd_dev_put(rsp_data->ubbd_dev);

	return 0;
}

static struct context *mgmt_ctx_alloc(struct ubbd_device *ubbd_dev,
		int fd, int (*finish)(struct context *, int))
{
	struct context *ctx;
	struct mgmt_ctx_data *ctx_data;

	if (!ubbd_dev_get(ubbd_dev)) {
		return NULL;
	}

	ctx = context_alloc(sizeof(struct mgmt_ctx_data));
	if (!ctx) {
		return NULL;
	}

	ctx_data = (struct mgmt_ctx_data *)ctx->data;
	ctx_data->fd = fd;
	ctx_data->ubbd_dev = ubbd_dev;

	ctx->finish = finish;

	return ctx;
}

static bool mgmt_stop = false;

static int ubbdd_mgmt_ipc_listen()
{
	return ubbd_ipc_listen(UBBDD_MGMT_NAMESPACE);
}

static void *mgmt_thread_fn(void* args)
{
	int fd;
	int ret = 0;
	struct pollfd pollfds[128];
	struct ubbd_device *ubbd_dev;
	int *retp = args;

	fd = ubbdd_mgmt_ipc_listen();
	if (fd < 0) {
		ubbd_err("failed to listen mgmt ipc.\n");
		*retp = fd;
		return NULL;
	}

	while (1) {
		pollfds[0].fd = fd;
		pollfds[0].events = POLLIN;
		pollfds[0].revents = 0;

		ret = poll(pollfds, 1, 60);
		if (ret == -1) {
			ubbd_err("ppoll() returned %d, exiting\n", ret);
			goto out;
		}

		if (mgmt_stop)
			goto out;

		if (pollfds[0].revents) {
			int read_fd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
			struct ubbdd_mgmt_request mgmt_req = {0};
			struct ubbdd_mgmt_rsp mgmt_rsp = {0};
			struct context *ctx;

			ubbd_ipc_read_data(read_fd, &mgmt_req, sizeof(mgmt_req));
			ubbd_info("receive mgmt request: %d. fd: %d\n", mgmt_req.cmd, read_fd);

			switch (mgmt_req.cmd) {
			case UBBDD_MGMT_CMD_MAP:
				ubbd_info("map type: %d\n", mgmt_req.u.add.info.type);

				ubbd_dev = ubbd_dev_create(&mgmt_req.u.add.info, false);
				if (!ubbd_dev) {
					ubbd_err("error to create ubbd_dev\n");
					ret = -ENOMEM;
					break;
				}

				ctx = mgmt_ctx_alloc(ubbd_dev, read_fd, mgmt_map_finish);
				if (!ctx) {
					ret = -ENOMEM;
					break;
				}
				ret = ubbd_dev_add(ubbd_dev, ctx);
				if (ret) {
					context_free(ctx);
					break;
				}
				continue;
			case UBBDD_MGMT_CMD_UNMAP:
				ubbd_dev = find_ubbd_dev(mgmt_req.u.remove.dev_id);
				if (!ubbd_dev) {
					ubbd_err("cant find ubbddev\n");
					ret = -EINVAL;
					break;
				}

				ctx = mgmt_ctx_alloc(ubbd_dev, read_fd, mgmt_generic_finish);
				if (!ctx) {
					ret = -ENOMEM;
					break;
				}

				ret = ubbd_dev_remove(ubbd_dev, mgmt_req.u.remove.force,
					       mgmt_req.u.remove.detach, ctx);
				if (ret) {
					context_free(ctx);
					break;
				}
				continue;
			case UBBDD_MGMT_CMD_CONFIG:
				ubbd_dev = find_ubbd_dev(mgmt_req.u.remove.dev_id);
				if (!ubbd_dev) {
					ubbd_err("cant find ubbddev\n");
					ret = -EINVAL;
					break;
				}
				ctx = mgmt_ctx_alloc(ubbd_dev, read_fd, mgmt_generic_finish);
				if (!ctx) {
					ret = -ENOMEM;
					break;
				}
				ret = ubbd_dev_config(ubbd_dev, mgmt_req.u.config.data_pages_reserve_percnt, ctx);
				if (ret) {
					context_free(ctx);
					break;
				}
				continue;
			case UBBDD_MGMT_CMD_LIST:
				mgmt_rsp.list.dev_num = 0;
				pthread_mutex_lock(&ubbd_dev_list_mutex);
				list_for_each_entry(ubbd_dev, &ubbd_dev_list, dev_node) {
					if (mgmt_rsp.list.dev_num  >= UBBD_DEV_MAX) {
						ret = -E2BIG;
						ubbd_err("ubbd device is too much than %d.\n", UBBD_DEV_MAX);
						break;
					}
					if (mgmt_req.u.list.type != -1 &&
							mgmt_req.u.list.type != ubbd_dev->dev_type)
						continue;

					mgmt_rsp.list.dev_list[mgmt_rsp.list.dev_num++] = ubbd_dev->dev_id;
				}
				pthread_mutex_unlock(&ubbd_dev_list_mutex);

				ret = 0;
				break;
			case UBBDD_MGMT_CMD_REQ_STATS:
				ubbd_dev = find_ubbd_dev(mgmt_req.u.req_stats.dev_id);
				if (!ubbd_dev) {
					ubbd_err("cant find ubbddev\n");
					ret = -EINVAL;
					break;
				}
				mgmt_rsp.req_stats.num_queues = ubbd_dev->num_queues;
				if (true) {
					struct ubbd_backend_mgmt_rsp backend_rsp;
					struct ubbd_backend_mgmt_request backend_request = { 0 };
					int fd;

					backend_request.dev_id = ubbd_dev->dev_id;
					backend_request.backend_id = ubbd_dev->current_backend_id;
					backend_request.cmd = UBBD_BACKEND_MGMT_CMD_REQ_STATS;

					ret = ubbd_backend_request(&fd, &backend_request);
					if (ret)
						break;

					ret = ubbd_backend_response(fd, &backend_rsp, 5);
					if (ret)
						break;
					memcpy(&mgmt_rsp.req_stats.req_stats,
					       &backend_rsp.u.req_stats.req_stats,
					       sizeof(struct ubbd_req_stats) * UBBD_QUEUE_MAX);
				}

				ret = 0;
				break;
			case UBBDD_MGMT_CMD_REQ_STATS_RESET:
				ubbd_dev = find_ubbd_dev(mgmt_req.u.req_stats_reset.dev_id);
				if (!ubbd_dev) {
					ubbd_err("cant find ubbddev\n");
					ret = -EINVAL;
					break;
				}
				if (true) {
					struct ubbd_backend_mgmt_rsp backend_rsp;
					struct ubbd_backend_mgmt_request backend_request = { 0 };
					int fd;

					backend_request.dev_id = ubbd_dev->dev_id;
					backend_request.backend_id = ubbd_dev->current_backend_id;
					backend_request.cmd = UBBD_BACKEND_MGMT_CMD_REQ_STATS_RESET;

					ret = ubbd_backend_request(&fd, &backend_request);
					if (ret) {
						ubbd_err("failed to send req-stats to backend: %d:%d\n", ubbd_dev->dev_id, ubbd_dev->current_backend_id);
						break;
					}

					ret = ubbd_backend_response(fd, &backend_rsp, 5);
					if (ret) {
						ubbd_err("failed to wait response req-stats from backend: %d:%d\n", ubbd_dev->dev_id, ubbd_dev->current_backend_id);
						break;
					}
				}

				ret = 0;
				break;
			case UBBDD_MGMT_CMD_DEV_RESTART:
				ubbd_dev = find_ubbd_dev(mgmt_req.u.dev_restart.dev_id);
				if (!ubbd_dev) {
					ubbd_err("cant find ubbddev\n");
					ret = -EINVAL;
					break;
				}
				ret = ubbd_dev_restart(ubbd_dev, mgmt_req.u.dev_restart.restart_mode);
				break;
			case UBBDD_MGMT_CMD_DEV_INFO:
				ubbd_dev = find_ubbd_dev(mgmt_req.u.dev_info.dev_id);
				if (!ubbd_dev) {
					ubbd_err("cant find ubbddev for dev info\n");
					ret = -EINVAL;
					break;
				}

				mgmt_rsp.dev_info.devid = ubbd_dev->dev_id;
				memcpy(&mgmt_rsp.dev_info.dev_info, &ubbd_dev->dev_info, sizeof(struct ubbd_dev_info));

				ret = 0;
				break;
			default:
				ubbd_err("unrecognized command: %d\n", mgmt_req.cmd);
				ret = -EINVAL;
				break;
			}
			ubbd_err("write ret: %d to fd: %d\n", ret, read_fd);
			mgmt_rsp.ret = ret;
			write(read_fd, &mgmt_rsp, sizeof(mgmt_rsp));
			close(read_fd);
			continue;
		}
	}
out:
	close(fd);
	*retp = ret;

	return NULL;
}

pthread_t ubbdd_mgmt_thread;

int thread_ret = 0;

int ubbdd_mgmt_start_thread(void)
{
	return pthread_create(&ubbdd_mgmt_thread, NULL, mgmt_thread_fn, &thread_ret);
}

void ubbdd_mgmt_stop_thread(void)
{
	mgmt_stop = true;
}

int ubbdd_mgmt_wait_thread(void)
{
	int ret;

	ret = pthread_join(ubbdd_mgmt_thread, NULL);
	if (ret) {
		ubbd_err("failed to wait ubbdd_mgmt joing: %d\n", ret);
		return ret;
	}

	if (thread_ret) {
		ubbd_err("ubbdd_mgmt exit with error: %d\n", thread_ret);
		return thread_ret;
	}

	return 0;
}
