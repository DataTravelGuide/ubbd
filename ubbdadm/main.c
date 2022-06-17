#define _GNU_SOURCE
#include <getopt.h>
#include <sys/types.h>

#include "ubbd_deamon_mgmt.h"
#include "ubbd_dev.h"
#include "utils.h"
#include "ubbd_netlink.h"


enum ubbdd_mgmt_cmd str_to_cmd(char *str)
{
	enum ubbdd_mgmt_cmd cmd;

	if (!strcmp("map", str))
		cmd = UBBDD_MGMT_CMD_MAP;
	else if (!strcmp("unmap", str))
		cmd = UBBDD_MGMT_CMD_UNMAP;
	else if (!strcmp("config", str))
		cmd = UBBDD_MGMT_CMD_CONFIG;
	else if (!strcmp("list", str))
		cmd = UBBDD_MGMT_CMD_LIST;
	else if (!strcmp("req-stats", str))
		cmd = UBBDD_MGMT_CMD_REQ_STATS;
	else if (!strcmp("req-stats-reset", str))
		cmd = UBBDD_MGMT_CMD_REQ_STATS_RESET;
	else if (!strcmp("dev-restart", str))
		cmd = UBBDD_MGMT_CMD_DEV_RESTART;
	else
		cmd = -1;

	return cmd;
}

char *cmd_to_str(enum ubbdd_mgmt_cmd cmd)
{
	if (cmd == UBBDD_MGMT_CMD_MAP)
		return "map";
	else if (cmd == UBBDD_MGMT_CMD_UNMAP)
		return "unmap";
	else if (cmd == UBBDD_MGMT_CMD_CONFIG)
		return "config";
	else if (cmd == UBBDD_MGMT_CMD_LIST)
		return "list";
	else if (cmd == UBBDD_MGMT_CMD_REQ_STATS)
		return "req-stats";
	else if (cmd == UBBDD_MGMT_CMD_REQ_STATS_RESET)
		return "req-stats-reset";
	else if (cmd == UBBDD_MGMT_CMD_DEV_RESTART)
		return "dev-restart";
	else
		return "UNKNOWN";
}

static enum ubbd_dev_type str_to_type(char *str)
{
	enum ubbd_dev_type type;

	if (!strcmp("file", str))
		type = UBBD_DEV_TYPE_FILE;
	else if (!strcmp("rbd", str))
		type = UBBD_DEV_TYPE_RBD;
	else if (!strcmp("null", str))
		type = UBBD_DEV_TYPE_NULL;
	else if (!strcmp("ssh", str))
		type = UBBD_DEV_TYPE_SSH;
	else
		type = -1;

	return type;
}

static struct option const long_options[] =
{
	{"command", required_argument, NULL, 'c'},
	{"type", required_argument, NULL, 't'},
	{"filepath", required_argument, NULL, 'f'},
	{"devsize", required_argument, NULL, 's'},
	{"force", no_argument, NULL, 'o'},
	{"pool", required_argument, NULL, 'p'},
	{"image", required_argument, NULL, 'i'},
	{"ceph-conf", required_argument, NULL, 'e'},
	{"ubbdid", required_argument, NULL, 'u'},
	{"data-pages-reserve", required_argument, NULL, 'r'},
	{"num-queues", required_argument, NULL, 'q'},
	{"restart-mode", required_argument, NULL, 'm'},
	{"hostname", required_argument, NULL, 'n'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static char *short_options = "c:t:f:p:i:u:h:s:o:r:q:e:m:n";

static void usage(int status)
{ 
	if (status != 0)
		fprintf(stderr, "Try `ubbdadm --help' for more information.\n");
	else {
		printf("\
			ubbdadm --command map --type file --filepath PATH --devsize SIZE\n\
			ubbdadm --command map --type rbd --pool POOL --image IMANGE \n\
			ubbdadm --command map --type ssh --hostname HOST --filepath REMOTE_PATH --devsize SIZE --num-queues N\n\
			ubbdadm --command unmap --ubbdid ID\n\
			ubbdadm --command config --ubbdid ID --data-pages-reserve 50\n\
			ubbdadm --command list\n\
			ubbdadm --command req-stats --ubbdid ID\n\
			ubbdadm --command req-stats-reset --ubbdid ID\n\
			ubbdadm --command dev-restart --ubbdid ID [--restart-mode (default|dev|queue)]\n");
	}
	exit(status);
}

typedef void (*request_callback)(struct ubbdd_mgmt_rsp *rsp);

static int request_and_wait(struct ubbdd_mgmt_request *req, request_callback cb)
{
	struct ubbdd_mgmt_rsp rsp = {0};
	int fd;
	int ret;

	ret = ubbdd_request(&fd, req);
	if (ret) {
		ubbd_err("failed to send %s request to ubbdd: %d.\n", cmd_to_str(req->cmd), ret);
		return ret;
	}
	
	ret = ubbdd_response(fd, &rsp, -1);
	if (ret) {
		ubbd_err("error in waiting response for %s request: %d.\n", cmd_to_str(req->cmd), ret);
		return ret;
	}

	if (cb)
		cb(&rsp);

	return 0;
}

static int generic_request_and_wait(struct ubbdd_mgmt_request *req)
{
	return request_and_wait(req, NULL);
}

static void map_request_callback(struct ubbdd_mgmt_rsp *rsp)
{
	fprintf(stdout, "%s\n", rsp->u.add.path);
}

static int map_request_and_wait(struct ubbdd_mgmt_request *req)
{
	int ret;

	ret = request_and_wait(req, map_request_callback);
	if (ret)
		return ret;

	return 0;
}

static int do_file_map(char *filepath, uint64_t devsize, uint32_t num_queues)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_MAP;
	req.u.add.info.num_queues = num_queues;
	req.u.add.info.type = UBBD_DEV_TYPE_FILE;
	strcpy(req.u.add.info.file.path, filepath);
	req.u.add.info.file.size = devsize;

	return map_request_and_wait(&req);
}

static int do_rbd_map(char *pool, char *image, char *ceph_conf, uint32_t num_queues)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_MAP;
	req.u.add.info.num_queues = num_queues;
	req.u.add.info.type = UBBD_DEV_TYPE_RBD;
	strcpy(req.u.add.info.rbd.pool, pool);
	strcpy(req.u.add.info.rbd.image, image);
	strcpy(req.u.add.info.rbd.ceph_conf, ceph_conf);

	return map_request_and_wait(&req);
}

static int do_null_map(uint64_t dev_size, uint32_t num_queues)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_MAP;
	req.u.add.info.num_queues = num_queues;
	req.u.add.info.type = UBBD_DEV_TYPE_NULL;
	req.u.add.info.null.size = dev_size;

	return map_request_and_wait(&req);
}

static int do_ssh_map(char *hostname, char *filepath, uint64_t devsize, uint32_t num_queues)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_MAP;
	req.u.add.info.num_queues = num_queues;
	req.u.add.info.type = UBBD_DEV_TYPE_SSH;
	strcpy(req.u.add.info.ssh.path, filepath);
	strcpy(req.u.add.info.ssh.hostname, hostname);
	req.u.add.info.ssh.size = devsize;

	return map_request_and_wait(&req);
}

static int do_unmap(int ubbdid, bool force)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_UNMAP;
	req.u.remove.dev_id = ubbdid;
	req.u.remove.force = force;

	return generic_request_and_wait(&req);
}

static int do_config(int ubbdid, int data_pages_reserve)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_CONFIG;
	req.u.config.dev_id = ubbdid;
	req.u.config.data_pages_reserve = data_pages_reserve;

	return generic_request_and_wait(&req);
}

static int do_dev_restart(int ubbdid, int restart_mode)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_DEV_RESTART;
	req.u.dev_restart.dev_id = ubbdid;
	req.u.dev_restart.restart_mode = restart_mode;

	return generic_request_and_wait(&req);
}

static void list_request_callback(struct ubbdd_mgmt_rsp *rsp)
{
	int i;

	for (i = 0; i < rsp->u.list.dev_num; i++) {
		fprintf(stdout, "/dev/ubbd%d\n", rsp->u.list.dev_list[i]);
	}
}

static int list_request_and_wait(struct ubbdd_mgmt_request *req)
{
	int ret;

	ret = request_and_wait(req, list_request_callback);
	if (ret)
		return ret;

	return 0;
}

static int do_list()
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_LIST;

	return list_request_and_wait(&req);
}

static void req_stats_request_callback(struct ubbdd_mgmt_rsp *rsp)
{
	int i;
	struct ubbd_req_stats *req_stats;

	for (i = 0; i < rsp->u.req_stats.num_queues; i++) {
		req_stats = &rsp->u.req_stats.req_stats[i];
		fprintf(stdout, "Queue-%d:\n", i);
		fprintf(stdout, "\tRequests:%lu\n", req_stats->reqs);
		fprintf(stdout, "\tHandle_time:%lu\n", req_stats->reqs? req_stats->handle_time / req_stats->reqs : 0);
	}
}

static int req_stats_request_and_wait(struct ubbdd_mgmt_request *req)
{
	int ret;

	ret = request_and_wait(req, req_stats_request_callback);
	if (ret)
		return ret;

	return 0;
}

static int do_req_stats(int ubbdid)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_REQ_STATS;
	req.u.req_stats.dev_id = ubbdid;

	return req_stats_request_and_wait(&req);
}

static int do_req_stats_reset(int ubbdid)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_REQ_STATS_RESET;
	req.u.req_stats_reset.dev_id = ubbdid;

	return generic_request_and_wait(&req);
}

int str_to_restart_mode(char *str)
{
	int restart_mode;

	if (!strcmp("default", str))
		restart_mode = UBBD_DEV_RESTART_MODE_DEFAULT;
	else if (!strcmp("dev", str))
		restart_mode = UBBD_DEV_RESTART_MODE_DEV;
	else if (!strcmp("queue", str))
		restart_mode = UBBD_DEV_RESTART_MODE_QUEUE;
	else {
		ubbd_err("unrecognized restart mode: %s\n", str);
		restart_mode = -1;
	}

	return restart_mode;

}

int main(int argc, char **argv)
{
	int ch, longindex;
	enum ubbdd_mgmt_cmd command;
	enum ubbd_dev_type type;
	char *filepath, *pool, *image, *ceph_conf;
	char *hostname;
	uint64_t dev_size;
	int ubbdid;
	int data_pages_reserve;
	bool force = false;
	int ret = 0;
	uint32_t num_queues = 0;
	int restart_mode = UBBD_DEV_RESTART_MODE_DEFAULT;

	optopt = 0;
	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'c':
			command = str_to_cmd(optarg);
			break;
		case 't':
			type = str_to_type(optarg);
			break;
		case 'f':
			filepath = optarg;
			break;
		case 's':
			dev_size = atoll(optarg);
			break;
		case 'o':
			force = true;
			break;
		case 'p':
			pool = optarg;
			break;
		case 'i':
			image = optarg;
			break;
		case 'e':
			ceph_conf = optarg;
			break;
		case 'u':
			ubbdid = atoi(optarg);
			break;
		case 'r':
			data_pages_reserve = atoi(optarg);
			break;
		case 'q':
			num_queues = atoi(optarg);
			break;
		case 'm':
			restart_mode = str_to_restart_mode(optarg);
			if (restart_mode < 0) {
				return -1;
			}
			break;
		case 'n':
			hostname = optarg;
			break;
		case 'h':
			usage(0);
		}
	}

	if (optopt) {
		ubbd_err("unrecognized character '%c'\n", optopt);
		return -1;
	}

	if (command == UBBDD_MGMT_CMD_MAP) {
		switch (type) {
		case UBBD_DEV_TYPE_FILE:
			ret = do_file_map(filepath, dev_size, num_queues);
			break;
		case UBBD_DEV_TYPE_RBD:
			ret = do_rbd_map(pool, image, ceph_conf, num_queues);
			break;
		case UBBD_DEV_TYPE_NULL:
			ret = do_null_map(dev_size, num_queues);
			break;
		case UBBD_DEV_TYPE_SSH:
			ret = do_ssh_map(hostname, filepath, dev_size, num_queues);
			break;
		default:
			printf("error type: %d\n", type);
			exit(-1);
		}
	} else if (command == UBBDD_MGMT_CMD_UNMAP) {
		ret = do_unmap(ubbdid, force);
	} else if (command == UBBDD_MGMT_CMD_CONFIG) {
		if (data_pages_reserve < 0 ||
				data_pages_reserve > 100) {
			ubbd_err("data_pages_reserve should be [0 - 100]\n");
			exit(-1);
		}

		ret = do_config(ubbdid, data_pages_reserve);
	} else if (command == UBBDD_MGMT_CMD_LIST) {
		ret = do_list();
	} else if (command == UBBDD_MGMT_CMD_REQ_STATS) {
		ret = do_req_stats(ubbdid);
	} else if (command == UBBDD_MGMT_CMD_REQ_STATS_RESET) {
		ret = do_req_stats_reset(ubbdid);
	} else if (command == UBBDD_MGMT_CMD_DEV_RESTART) {
		ret = do_dev_restart(ubbdid, restart_mode);
	} else {
		printf("error command: %d\n", command);
		exit(-1);
	}

	return ret;
}
