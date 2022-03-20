#include <pthread.h>
#include <signal.h>

#include "ubbd_mgmt.h"
#include "ubbd_netlink.h"
#include "utils.h"
#include "ubbd_log.h"

static void catch_signal(int signo)
{
	ubbd_info("%d caught signal -%d...", signo, getpid());
	switch (signo) {
	case SIGTERM:
	case SIGINT:
		ubbd_mgmt_stop_thread();
		ubbd_dev_stop_devs();
		ubbd_nl_stop_thread();
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
}

int main()
{
	int ret;
	void *join_retval;
	pthread_t mgmt_thread;
	pthread_t nl_thread;

	ret = ubbd_setup_log("/var/log/");
	if (ret)
		goto out;

	setup_signal_handler();
	ubbd_nl_start_thread(&nl_thread);
	ret = ubbd_dev_reopen_devs();
	if (ret)
		goto destroy_log;

	ubbd_mgmt_start_thread(&mgmt_thread);
	ubbd_info("ubbdd started.....\n");

	ret = pthread_join(mgmt_thread, &join_retval);
	ret = pthread_join(nl_thread, &join_retval);
destroy_log:
	ubbd_destroy_log();
out:
	return ret;
}
