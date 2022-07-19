#define _GNU_SOURCE
#include <pthread.h>
#include <getopt.h>
#include <sys/types.h>

#include <signal.h>

#include "ubbd_log.h"
#include "ubbd_backend_mgmt.h"
#include "utils.h"
#include "ubbd_netlink.h"
#include "ubbd_backend.h"
#include "ubbd_config.h"

struct ubbd_backend *ubbd_backend = NULL;

static void catch_signal(int signo)
{
	switch (signo) {
	case SIGTERM:
	case SIGINT:
		ubbd_backend_mgmt_stop_thread();
		break;
	default:
		break;
	}
}

static void setup_signal_handler(void)
{
	struct sigaction sa_old;
	struct sigaction sa_new;

	sa_new.sa_handler = catch_signal;
	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	sigaction(SIGTERM, &sa_new, &sa_old);
	sigaction(SIGINT, &sa_new, &sa_old);
}

static struct option const long_options[] =
{
	{"dev-id", required_argument, NULL, 'i'},
	{"deamon", required_argument, NULL, 'd'},
	{"backend-id", required_argument, NULL, 'b'},
	{"start-queues", required_argument, NULL, 'q'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static char *short_options = "b:i:h:";

static void usage(int status)
{ 
	if (status != 0)
		fprintf(stderr, "Try `ubbd-backend --help' for more information.\n");
	else {
		printf("\
			Usage: \n\
				ubbd-backend --dev-id ID --backend-id B_ID --start-queues 1\n\n");
	}
	exit(status);
}


int main(int argc, char **argv)
{
	int ret;
	int ch, longindex;
	int devid = -1;
	int b_id = -1;
	int start_queues = 1;
	struct ubbd_backend_conf *ubbd_backend_conf;
	char *log_filename;
	int deamon = 1;
	pid_t pid;
	int fd;

	optopt = 0;
	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'i':
			devid = atoi(optarg);
			break;
		case 'b':
			b_id = atoi(optarg);
			break;
		case 'q':
			start_queues = atoi(optarg);
			break;
		case 'd':
			deamon = atoi(optarg);
			break;
		case 'h':
			usage(0);
		}
	}

	if (optopt) {
		ubbd_err("unrecognized character '%c'\n", optopt);
		usage(-1);
	}

	if (devid == -1 || b_id == -1) {
		ubbd_err("missing dev-id or backend-idoption.\n");
		usage(-1);
	}

	if (deamon) {
		/* daemonize */
		pid = fork();
		if (pid < 0) {
			ret = -errno;
			goto out;
		} else if (pid > 0) {
			goto out;
		}
	}

	if (asprintf(&log_filename, "backend%d.log", devid) == -1) {
		ubbd_err("cont init backend log filename\n");
		goto out;
	}

	ret = ubbd_setup_log("/var/log/ubbd/", log_filename);
	free(log_filename);
	if (ret)
		goto out;

	ret = ubbd_backend_lock(devid, b_id, &fd);
	if (ret) {
		ubbd_err("cant lock backend conf file\n");
		ret = -EBUSY;
		goto err_destroy_log;
	}

	ubbd_backend_conf = ubbd_conf_read_backend_conf(devid);
	if (!ubbd_backend_conf) {
		ubbd_err("cant get backend info\n");
		ret = -EINVAL;
		goto err_unlock_conf;
	}

	ubbd_backend = ubbd_backend_create(ubbd_backend_conf);
	free(ubbd_backend_conf);
	if (!ubbd_backend) {
		ret = -ENOMEM;
		ubbd_err("failed to create backend\n");
		goto err_unlock_conf;
	}

	ubbd_backend->backend_id = b_id;

	ret = ubbd_backend_open(ubbd_backend);
	if (ret) {
		ubbd_err("failed to open backend\n");
		goto err_destroy_backend;
	}

	ret = ubbd_backend_start(ubbd_backend, start_queues);
	if (ret) {
		ubbd_err("failed to setup backend\n");
		goto err_close_backend;
	}

	ret = ubbd_backend_mgmt_start_thread(ubbd_backend);
	if (ret) {
		ubbd_err("failed to start backend mgmt thread.\n");
		goto err_stop_backend;
	}

	setup_signal_handler();

	ubbd_info("ubbd-backend for ubbd%d started.....\n", devid);

	ret = ubbd_backend_mgmt_wait_thread();

	ubbd_info("ubbd-backend for ubbd%d stoping...\n", devid);

err_stop_backend:
	ubbd_backend_stop(ubbd_backend);
	ubbd_backend_wait_stopped(ubbd_backend);
err_close_backend:
	ubbd_backend_close(ubbd_backend);
err_destroy_backend:
	ubbd_backend_release(ubbd_backend);
err_unlock_conf:
	ubbd_backend_unlock(fd);
err_destroy_log:
	ubbd_destroy_log();
out:
	return ret;
}
