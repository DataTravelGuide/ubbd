#include <pthread.h>

#include "ubbd_mgmt.h"
#include "ubbd_netlink.h"
#include "utils.h"
#include "ubbd_log.h"

int main()
{
	int ret;
	void *join_retval;
	pthread_t mgmt_thread;
	pthread_t nl_thread;

	ret = ubbd_setup_log("/var/log/");
	if (ret)
		goto out;

	ret = ubd_dev_reopen_devs();
	if (ret)
		goto destroy_log;

	start_netlink_thread(&nl_thread);
	start_mgmt_thread(&mgmt_thread);
	ubbd_info("ubbdd started.....\n");
	ret = pthread_join(mgmt_thread, &join_retval);
	ret = pthread_join(nl_thread, &join_retval);
destroy_log:
	ubbd_destroy_log();
out:
	return ret;
}
