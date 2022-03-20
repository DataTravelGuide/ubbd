#include <pthread.h>
#include <sys/un.h>

#include "utils.h"
#include "ubbd_dev.h"
#include "ubbd_mgmt.h"

static int setup_abstract_addr(struct sockaddr_un *addr, char *unix_sock_name)
{
	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_LOCAL;
	strncpy(addr->sun_path + 1, unix_sock_name, sizeof(addr->sun_path) - 1);
	return offsetof(struct sockaddr_un, sun_path) +
		strlen(addr->sun_path + 1) + 1;
}


static int mgmt_ipc_listen(void)
{
	int fd, err, addr_len;
	struct sockaddr_un addr;

	/* manually establish a socket */
	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		ubbd_err("Can not create IPC socket");
		return fd;
	}

	addr_len = setup_abstract_addr(&addr, UBBD_MGMT_NAMESPACE);

	if ((err = bind(fd, (struct sockaddr *) &addr, addr_len)) < 0 ) {
		ubbd_err("Can not bind IPC socket");
		close(fd);
		return err;
	}

	if ((err = listen(fd, 32)) < 0) {
		ubbd_err("Can not listen IPC socket");
		close(fd);
		return err;
	}

	return fd;
}

static int ipc_connect(int *fd, char *unix_sock_name)
{
       int nsec, addr_len;
       struct sockaddr_un addr;

       *fd = socket(AF_LOCAL, SOCK_STREAM, 0);
       if (*fd < 0) {
               ubbd_err("can not create IPC socket (%d)!", errno);
               return -1;
       }

       addr_len = setup_abstract_addr(&addr, unix_sock_name);

       /*
        * Trying to connect with exponential backoff
        */
       for (nsec = 1; nsec <= 128; nsec <<= 1) {
               if (connect(*fd, (struct sockaddr *) &addr, addr_len) == 0)
                       /* Connection established */
                       return 0;

               /* If ubbdd isn't there, there's no sense
                * in retrying. */
               if (errno == ECONNREFUSED) {
                       break;
               }

               /*
                * Delay before trying again
                */
               if (nsec <= 128/2)
                       sleep(nsec);
       }
       close(*fd);
       *fd = -1;
       ubbd_err("can not connect to iSCSI daemon (%d)!", errno);
       return -1;
}


static int ubbdd_connect(int *fd)
{
	return ipc_connect(fd, UBBD_MGMT_NAMESPACE);
}


int ubbdd_response(int fd, struct ubbd_mgmt_rsp *rsp,
		    int timeout)
{
	size_t len = sizeof(*rsp);
	int err;

	while (len) {
		struct pollfd pfd;

		pfd.fd = fd;
		pfd.events = POLLIN;
		err = poll(&pfd, 1, timeout);
		if (!err) {
			return -1;
		} else if (err < 0) {
			if (errno == EINTR)
				continue;
			ubbd_err("got poll error (%d/%d), daemon died?",
				  err, errno);
			return -1;
		} else if (pfd.revents & POLLIN) {
			err = recv(fd, rsp, sizeof(*rsp), MSG_WAITALL);
			if (err <= 0) {
				ubbd_err("read error (%d/%d), daemon died?",
					  err, errno);
				break;
			}
			len -= err;
		}
	}
	close(fd);

	return rsp->ret;
}

int ubbdd_request(int *fd, struct ubbd_mgmt_request *req)
{
	int err;

	err = ubbdd_connect(fd);
	if (err)
		return err;

	if ((err = write(*fd, req, sizeof(*req))) != sizeof(*req)) {
		ubbd_err("got write error (%d/%d) on cmd %d, daemon died?",
			err, errno, req->cmd);
		close(*fd);
		return -1;
	}
	return 0;
}

static int mgmt_ipc_read_data(int fd, void *ptr, size_t len)
{
	int	n;

	while (len) {
		n = read(fd, ptr, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -EIO;
		}
		if (n == 0) {
			/* Client closed connection */
			return -EIO;
		}
		ptr += n;
		len -= n;
	}
	return 0;
}

struct mgmt_map_data {
	int fd;
	struct ubbd_device *ubbd_dev;
};

static int mgmt_map_finish(struct context *ctx, int ret)
{
	struct mgmt_map_data *rsp_data = ctx->data;
	int fd = rsp_data->fd;
	int32_t dev_id = rsp_data->ubbd_dev->dev_id;
	struct ubbd_mgmt_rsp mgmt_rsp;

	ubbd_err("write rsp to fd: %d\n", fd);
	mgmt_rsp.ret = ret;
	sprintf(mgmt_rsp.u.add.path, "/dev/ubbd%d", dev_id);
	write(fd, &mgmt_rsp, sizeof(mgmt_rsp));
	close(fd);

	return 0;
}

static void *mgmt_thread_fn(void* args)
{
	int fd;
	int ret = 0;
	struct pollfd pollfds[128];
	struct ubbd_device *ubbd_dev;

	fd = mgmt_ipc_listen();

	while (1) {
		pollfds[0].fd = fd;
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
		if (pollfds[0].revents) {
			int read_fd = accept(fd, NULL, NULL);
			struct ubbd_mgmt_request *mgmt_req = malloc(sizeof(struct ubbd_mgmt_request));
			struct ubbd_mgmt_rsp mgmt_rsp;
			struct context *ctx = context_alloc();

			mgmt_ipc_read_data(read_fd, mgmt_req, sizeof(*mgmt_req));
			ubbd_info("receive mgmt request: %d, fd: %d\n", mgmt_req->cmd, read_fd);
			if (mgmt_req->cmd == UBBD_MGMT_CMD_MAP) {
				struct mgmt_map_data *map_data = malloc(sizeof(struct mgmt_map_data));

				ubbd_info("type: %d\n", mgmt_req->u.add.info.type);
				ubbd_dev = ubbd_dev_create(&mgmt_req->u.add.info);
				if (!ubbd_dev) {
					ubbd_err("error to create ubbd_dev\n");
				}

				ret = ubbd_dev_open(ubbd_dev);
				if (ret) {
					goto write_rsp;
				}

				map_data->fd = read_fd;
				map_data->ubbd_dev = ubbd_dev;

				ctx->data = map_data;
				ctx->finish = mgmt_map_finish;

				ret = ubbd_dev_add(ubbd_dev, ctx);
				if (ret)
					goto write_rsp;

				continue;
write_rsp:
				mgmt_rsp.ret = ret;
				write(read_fd, &mgmt_rsp, sizeof(mgmt_rsp));
				continue;
			} else if (mgmt_req->cmd == UBBD_MGMT_CMD_UNMAP) {
				ubbd_dev = find_ubbd_dev(mgmt_req->u.remove.dev_id);
				if (!ubbd_dev) {
					ubbd_err("cant find ubbddev\n");
					continue;
				}
				ret = ubbd_dev_remove(ubbd_dev, mgmt_req->u.remove.force);
			} else if (mgmt_req->cmd == UBBD_MGMT_CMD_CONFIG) {
				ubbd_dev = find_ubbd_dev(mgmt_req->u.remove.dev_id);
				if (!ubbd_dev) {
					ubbd_err("cant find ubbddev\n");
					continue;
				}
				ret = ubbd_dev_config(ubbd_dev, mgmt_req->u.config.data_pages_reserve);
			} else {
				ubbd_err("unrecognized command: %d", mgmt_req->cmd);
				continue;
			}
		}
	}
}

int start_mgmt_thread(pthread_t *t)
{
	return pthread_create(t, NULL, mgmt_thread_fn, NULL);
}
