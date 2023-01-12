#include <pthread.h>
#include <getopt.h>
#include <signal.h>

#include "ubbd_daemon_mgmt.h"
#include "ubbd_netlink.h"
#include "utils.h"
#include "ubbd_log.h"

static void catch_signal(int signo)
{
	switch (signo) {
	case SIGTERM:
	case SIGINT:
		ubbdd_mgmt_stop_thread();
		break;
	case SIGPIPE:
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
	sigaction(SIGTERM, &sa_new, &sa_old );
	sigaction(SIGINT, &sa_new, &sa_old );
	sigaction(SIGPIPE, &sa_new, &sa_old );
}

static struct option const long_options[] =
{
	{"daemon", required_argument, NULL, 'd'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static char *short_options = "d:h";

static void usage(int status)
{ 
	if (status != 0)
		fprintf(stderr, "Try `ubbdd --help' for more information.\n");
	else {
		printf("\
			Usage: \n\
				ubbdd [--daemon]\n\n");
	}
	exit(status);
}

int main(int argc, char **argv)
{
	int ret;
	int ch, longindex;
	int daemon = 1;

	optopt = 0;
	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'd':
			daemon = atoi(optarg);
			break;
		case 'h':
			usage(0);
		}
	}

	if (optopt) {
		ubbd_err("unrecognized character '%c'\n", optopt);
		usage(-1);
	}

	if (daemon) {
		/* daemonize */
		int pid = fork();
		if (pid < 0) {
			ret = -errno;
			goto out;
		} else if (pid > 0) {
			goto out;
		}
	}

	ret = ubbd_setup_log("/var/log/ubbd/", "ubbdd.log");
	if (ret)
		goto out;

	setup_signal_handler();
	ret = ubbd_nl_start_thread();
	if (ret)
		goto destroy_log;

	ret = ubbd_dev_reopen_devs();
	if (ret)
		goto stop_nl_thread;

	ret = ubbd_dev_checker_start_thread();
	if (ret)
		goto stop_nl_thread;

	ret = ubbdd_mgmt_start_thread();
	if (ret)
		goto stop_nl_thread;
	ubbd_info("ubbdd started.....\n");

	ubbdd_mgmt_wait_thread();

	ubbd_info("ubbdd stoping...\n");

	ubbd_dev_checker_stop_thread();
	ubbd_dev_checker_wait_thread();

stop_nl_thread:
	ubbd_nl_stop_thread();
	ubbd_nl_wait_thread();
destroy_log:
	ubbd_destroy_log();
out:
	return ret;
}
