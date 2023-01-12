#define _GNU_SOURCE
#include <pthread.h>
#include <sys/un.h>

#include "utils.h"
#include "ubbd_backend_mgmt.h"
#include "ubbd_netlink.h"

static int backend_mgmt_ipc_listen(int dev_id, int backend_id)
{
	char *backend_mgmt_ns;
	int ret;

	backend_mgmt_ns = get_backend_mgmt_ns(dev_id, backend_id);
	if (!backend_mgmt_ns) {
		return -1;
	}

	ret = ubbd_ipc_listen(backend_mgmt_ns);

	free(backend_mgmt_ns);

	return ret;
}

int ubbd_backend_response(int fd, struct ubbd_backend_mgmt_rsp *rsp,
		    int timeout)
{
	int ret;

	ret = ubbd_response(fd, rsp, sizeof(*rsp), timeout);
	ubbd_info("ret of backend response: %d\n", ret);
	return ret;
}

int ubbd_backend_request(int *fd, struct ubbd_backend_mgmt_request *req)
{
	char *backend_mgmt_ns;
	int ret;

	backend_mgmt_ns = get_backend_mgmt_ns(req->dev_id, req->backend_id);
	if (!backend_mgmt_ns) {
		return -1;
	}

	ret = ubbd_request(fd, backend_mgmt_ns, req, sizeof(*req));
	ubbd_info("ret of backend_request %d to backend: %s is %d\n", req->cmd, backend_mgmt_ns, ret);

	free(backend_mgmt_ns);

	return ret;
}

static bool mgmt_stop = false;

static int get_kernel_dev_status(int dev_id)
{
	int ret;
	struct ubbd_nl_dev_status dev_status = { 0 };

	ret = ubbd_nl_dev_status(dev_id, &dev_status);
	if (ret) {
		ubbd_err("failed to get status from netlink\n");
		goto out;
	}

	return dev_status.status;
out:
	return ret;
}

static void *mgmt_thread_fn(void* args)
{
	int fd;
	int ret = 0;
	struct pollfd pollfds[128];
	struct ubbd_backend *ubbd_backend = (struct ubbd_backend *)args;

	fd = backend_mgmt_ipc_listen(ubbd_backend->dev_id, ubbd_backend->backend_id);

	while (1) {
		pollfds[0].fd = fd;
		pollfds[0].events = POLLIN;
		pollfds[0].revents = 0;

		ret = poll(pollfds, 1, 60);
		if (ret == -1) {
			ubbd_err("ppoll() returned %d, exiting\n", ret);
			goto out;
		}

		ret = get_kernel_dev_status(ubbd_backend->dev_id);
		if (ret == -NLE_OBJ_NOTFOUND) {
			ubbd_err("device %d is already removed\n", ubbd_backend->dev_id);
			goto out;
		}
		
		if (ret == UBBD_DEV_KSTATUS_REMOVING) {
			ubbd_err("device %d is in removing\n", ubbd_backend->dev_id);
			goto out;
		}

		if (mgmt_stop)
			goto out;

		if (pollfds[0].revents) {
			int read_fd = accept(fd, NULL, NULL);
			struct ubbd_backend_mgmt_request mgmt_req = {0};
			struct ubbd_backend_mgmt_rsp mgmt_rsp = {0};
			int queue_id;

			ubbd_ipc_read_data(read_fd, &mgmt_req, sizeof(mgmt_req));
			ubbd_info("receive mgmt request: %d.\n", mgmt_req.cmd);

			switch (mgmt_req.cmd) {
			case UBBD_BACKEND_MGMT_CMD_STOP:
				ubbd_backend_mgmt_stop_thread();
				ret = 0;
				break;
			case UBBD_BACKEND_MGMT_CMD_GET_STATUS:
				mgmt_rsp.u.get_status.status = ubbd_backend->status;
				ret = 0;
				break;
			case UBBD_BACKEND_MGMT_CMD_STOP_QUEUE:
				queue_id = mgmt_req.u.stop_queue.queue_id;
				ret = ubbd_backend_stop_queue(ubbd_backend, queue_id);
				break;
			case UBBD_BACKEND_MGMT_CMD_START_QUEUE:
				queue_id = mgmt_req.u.start_queue.queue_id;
				ret = ubbd_backend_start_queue(ubbd_backend, queue_id);
				break;
			case UBBD_BACKEND_MGMT_CMD_GET_QUEUE_STATUS:
				queue_id = mgmt_req.u.get_queue_status.queue_id;
				mgmt_rsp.u.get_queue_status.status = ubbd_backend->queues[queue_id].status;
				ret = 0;
				break;
			case UBBD_BACKEND_MGMT_CMD_REQ_STATS:
				mgmt_rsp.u.req_stats.num_queues = ubbd_backend->num_queues;
				if (true) {
					int i;
					for (i = 0; i < ubbd_backend->num_queues; i++) {
						memcpy(&mgmt_rsp.u.req_stats.req_stats[i],
								&ubbd_backend->queues[i].req_stats,
								sizeof(struct ubbd_req_stats));
					}
				}
				ret = 0;
				break;
			case UBBD_BACKEND_MGMT_CMD_REQ_STATS_RESET:
				if (true) {
					int i;
					for (i = 0; i < ubbd_backend->num_queues; i++) {
						pthread_mutex_lock(&ubbd_backend->queues[i].req_stats_lock);
						ubbd_backend->queues[i].req_stats.reqs = 0;
						ubbd_backend->queues[i].req_stats.handle_time = 0;
						pthread_mutex_unlock(&ubbd_backend->queues[i].req_stats_lock);
					}
				}
				ret = 0;
				break;
			case UBBD_BACKEND_MGMT_CMD_SET_OPTS:
				ret = ubbd_backend_set_opts(ubbd_backend, &mgmt_req.u.set_opts);
				break;
			default:
				ubbd_err("unrecognized command: %d\n", mgmt_req.cmd);
				ret = -EINVAL;
				break;
			}
			ubbd_info("backend_mgmt: write ret: %d to %d\n", ret, read_fd);
			mgmt_rsp.ret = ret;
			write(read_fd, &mgmt_rsp, sizeof(mgmt_rsp));
			close(read_fd);
			continue;
		}
	}
out:
	close(fd);

	return NULL;
}

pthread_t ubbd_backend_mgmt_thread;

int ubbd_backend_mgmt_start_thread(struct ubbd_backend *ubbd_backend)
{
	return pthread_create(&ubbd_backend_mgmt_thread, NULL, mgmt_thread_fn, ubbd_backend);
}

void ubbd_backend_mgmt_stop_thread(void)
{
	mgmt_stop = true;
}

int ubbd_backend_mgmt_wait_thread(void)
{
	void *join_retval;

	return pthread_join(ubbd_backend_mgmt_thread, &join_retval);
}
