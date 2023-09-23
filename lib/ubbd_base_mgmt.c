#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>

#include "ubbd_log.h"
#include "ubbd_daemon_mgmt.h"
#include "utils.h"

static int setup_abstract_addr(struct sockaddr_un *addr, char *unix_sock_name)
{
	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_LOCAL;
	strncpy(addr->sun_path + 1, unix_sock_name, sizeof(addr->sun_path) - 2);
	return offsetof(struct sockaddr_un, sun_path) +
		strlen(addr->sun_path + 1) + 1;
}


int ubbd_ipc_listen(char *sock_name)
{
	int fd, err, addr_len;
	struct sockaddr_un addr;
	int retry_count = 0;

retry:
	/* manually establish a socket */
	fd = socket(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		ubbd_err("Can not create IPC socket\n");
		err = fd;
		goto err;
	}

	addr_len = setup_abstract_addr(&addr, sock_name);

	if ((err = bind(fd, (struct sockaddr *) &addr, addr_len)) < 0 ) {
		ubbd_err("Can not bind IPC socket\n");
		close(fd);
		goto err;
	}

	if ((err = listen(fd, 32)) < 0) {
		ubbd_err("Can not listen IPC socket\n");
		close(fd);
		goto err;
	}

	return fd;
err:
	if (++retry_count < 10) {
		sleep(1);
		goto retry;
	}

	return err;
}

static int ubbd_ipc_connect(int *fd, char *unix_sock_name)
{
       int nsec, addr_len;
       struct sockaddr_un addr;

       *fd = socket(AF_LOCAL, SOCK_STREAM, 0);
       if (*fd < 0) {
               ubbd_err("can not create IPC socket (%d)!\n", errno);
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

               /* If ubbd isn't there, there's no sense
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
       ubbd_err("can not connect to ubbd daemon (%d)!\n", errno);
       return -1;
}


int ubbd_response(int fd, void *rsp, size_t len,
		    int timeout)
{
	int err;

	while (len) {
		struct pollfd pfd;

		pfd.fd = fd;
		pfd.events = POLLIN;
		err = poll(&pfd, 1, timeout);
		if (!err) {
			continue;
		} else if (err < 0) {
			if (errno == EINTR)
				continue;
			ubbd_err("got poll error (%d/%d), daemon died?\n",
				  err, errno);
			close(fd);
			return -ECONNABORTED;
		} else if (pfd.revents & POLLIN) {
			err = recv(fd, rsp, len, MSG_WAITALL);
			if (err <= 0) {
				ubbd_err("read error (%d/%d), daemon died?\n",
					  err, errno);
				close(fd);
				return -ECONNABORTED;
			}
			len -= err;
		}
	}
	close(fd);

	return ((struct ubbd_response *)rsp)->ret;
}

int ubbd_request(int *fd, char *sock_name, void *req, size_t len)
{
	int err;

	err = ubbd_ipc_connect(fd, sock_name);
	if (err) {
		ubbd_err("failed to connect to %s\n", sock_name);
		return -ECONNABORTED;
	}

	if ((err = write(*fd, req, len)) != len) {
		ubbd_err("got write error (%d/%d), daemon died?\n",
			err, errno);
		close(*fd);
		return -ECONNABORTED;
	}

	return 0;
}

int ubbd_ipc_read_data(int fd, void *ptr, size_t len)
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
