#define _GNU_SOURCE
#include <getopt.h>
#include <sys/types.h>

#include "ocf/ocf_def.h"
#include "ubbd_deamon_mgmt.h"
#include "ubbd_dev.h"
#include "utils.h"
#include "ubbd_netlink.h"


int str_to_cache_mode(char *str)
{
	int cache_mode;

	if (!strcmp("writeback", str)){
		cache_mode = ocf_cache_mode_wb;
	} else if (!strcmp("writethrough", str)) {
		cache_mode = ocf_cache_mode_wt;
	} else {
		cache_mode = -1;
	}

	return cache_mode;
}

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
	else if (!strcmp("cache", str))
		type = UBBD_DEV_TYPE_CACHE;
	else if (!strcmp("s3", str))
		type = UBBD_DEV_TYPE_S3;
	else
		type = -1;

	return type;
}

struct ubbdadm_map_options {
	enum ubbd_dev_type type;
	char *filepath;
	char *pool;
	char *image;
	char *ceph_conf;
	char *hostname;
	uint64_t dev_size;
	uint32_t block_size;
	char *accessid;
	char *accesskey;
	char *volume_name;
	char *bucket_name;
	int port;
	uint32_t dev_share_memory_size;
	int num_queues;
};

static struct option const long_options[] =
{
	{"command", required_argument, NULL, 'c'},
	{"force", no_argument, NULL, 'o'},
	{"ubbdid", required_argument, NULL, 'u'},
	{"data-pages-reserve", required_argument, NULL, 'r'},
	{"num-queues", required_argument, NULL, 0},
	{"restart-mode", required_argument, NULL, 'm'},

	{"type", required_argument, NULL, 0},
	{"cache-dev-type", required_argument, NULL, 0},
	{"backing-dev-type", required_argument, NULL, 0},

	{"filepath", required_argument, NULL, 0},
	{"cache-dev-filepath", required_argument, NULL, 0},
	{"backing-dev-filepath", required_argument, NULL, 0},

	{"devsize", required_argument, NULL, 0},
	{"cache-dev-devsize", required_argument, NULL, 0},
	{"backing-dev-devsize", required_argument, NULL, 0},

	{"pool", required_argument, NULL, 0},
	{"cache-dev-pool", required_argument, NULL, 0},
	{"backing-dev-pool", required_argument, NULL, 0},

	{"image", required_argument, NULL, 0},
	{"cache-dev-image", required_argument, NULL, 0},
	{"backing-dev-image", required_argument, NULL, 0},

	{"ceph-conf", required_argument, NULL, 0},
	{"cache-dev-ceph-conf", required_argument, NULL, 0},
	{"backing-dev-ceph-conf", required_argument, NULL, 0},

	{"hostname", required_argument, NULL, 0},
	{"cache-dev-hostname", required_argument, NULL, 0},
	{"backing-dev-hostname", required_argument, NULL, 0},

	{"cache-mode", required_argument, NULL, 'a'},

	{"accessid", required_argument, NULL, 0},
	{"accesskey", required_argument, NULL, 0},
	{"volume-name", required_argument, NULL, 0},
	{"cache-dev-accessid", required_argument, NULL, 0},
	{"cache-dev-accesskey", required_argument, NULL, 0},
	{"cache-dev-volume-name", required_argument, NULL, 0},
	{"backing-dev-accessid", required_argument, NULL, 0},
	{"backing-dev-accesskey", required_argument, NULL, 0},
	{"backing-dev-volume-name", required_argument, NULL, 0},

	{"port", required_argument, NULL, 0},
	{"cache-dev-port", required_argument, NULL, 0},
	{"backing-dev-port", required_argument, NULL, 0},

	{"block-size", required_argument, NULL, 0},
	{"cache-dev-block-size", required_argument, NULL, 0},
	{"backing-dev-block-size", required_argument, NULL, 0},

	{"bucket-name", required_argument, NULL, 0},
	{"cache-dev-bucket-name", required_argument, NULL, 0},
	{"backing-dev-bucket-name", required_argument, NULL, 0},

	{"detach", no_argument, NULL, 'd'},
	{"dev-share-memory-size", required_argument, NULL, 0},

	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static char *short_options = "c:t:f:p:i:u:h:s:o:r:q:e:m:n:d";

static void usage(int status)
{ 
	if (status != 0)
		fprintf(stderr, "Try `ubbdadm --help' for more information.\n");
	else {
		printf("\
			ubbdadm --command map --type file --filepath PATH --devsize SIZE --dev-share-memory-size [4194304 - 1073741824]\n\
			ubbdadm --command map --type rbd --pool POOL --image IMANGE \n\
			ubbdadm --command map --type ssh --hostname HOST --filepath REMOTE_PATH --devsize SIZE --num-queues N\n\
			ubbdadm --command map --type s3 --hostname IP/URL --port PORT --accessid ID --accesskey KEY --volume-name VOL_NAME --devsize SIZE --num-queues N\n\
			ubbdadm --command map --type cache --devsize SIZE --num-queues N\n\
						--cache-dev-type file --cache-dev-filepath PATH --cache-dev-devsize SIZE\n\
						--backing-dev-type rbd --backing-dev-pool POOL --backing-dev-image IMG\n\
						--cache-mode [writeback|writethrough]\n\
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

static void file_dev_info_setup(struct ubbd_dev_info *dev_info,
		struct ubbdadm_map_options *opts)
{
	strcpy(dev_info->file.path, opts->filepath);
	dev_info->file.size = opts->dev_size;
}

static void rbd_dev_info_setup(struct ubbd_dev_info *dev_info,
		struct ubbdadm_map_options *opts)
{
	strcpy(dev_info->rbd.pool, opts->pool);
	strcpy(dev_info->rbd.image, opts->image);
	strcpy(dev_info->rbd.ceph_conf, opts->ceph_conf);
}

static void null_dev_info_setup(struct ubbd_dev_info *dev_info,
		struct ubbdadm_map_options *opts)
{
	dev_info->null.size = opts->dev_size;
}

static void s3_dev_info_setup(struct ubbd_dev_info *dev_info,
		struct ubbdadm_map_options *opts)
{
	dev_info->s3.size = opts->dev_size;
	dev_info->s3.block_size = opts->block_size;
	dev_info->s3.port = opts->port;
	strcpy(dev_info->s3.hostname, opts->hostname);
	strcpy(dev_info->s3.accessid, opts->accessid);
	strcpy(dev_info->s3.accesskey, opts->accesskey);
	strcpy(dev_info->s3.volume_name, opts->volume_name);
	strcpy(dev_info->s3.bucket_name, opts->bucket_name);
}

static void ssh_dev_info_setup(struct ubbd_dev_info *dev_info,
		struct ubbdadm_map_options *opts)
{
	strcpy(dev_info->ssh.path, opts->filepath);
	strcpy(dev_info->ssh.hostname, opts->hostname);
	dev_info->ssh.size = opts->dev_size;
}

static int dev_info_setup(struct ubbd_dev_info *dev_info,
		enum ubbd_dev_type dev_type, struct ubbdadm_map_options *opts)
{
	if (dev_type == UBBD_DEV_TYPE_FILE) {
		file_dev_info_setup(dev_info, opts);
	} else if (dev_type == UBBD_DEV_TYPE_RBD) {
		rbd_dev_info_setup(dev_info, opts);
	} else if (dev_type == UBBD_DEV_TYPE_NULL) {
		null_dev_info_setup(dev_info, opts);
	} else if (dev_type == UBBD_DEV_TYPE_SSH) {
		ssh_dev_info_setup(dev_info, opts);
	} else if (dev_type == UBBD_DEV_TYPE_S3) {
		s3_dev_info_setup(dev_info, opts);
	} else {
		ubbd_err("error dev_type: %d\n", dev_type);
		return -1;
	}
	dev_info->num_queues = opts->num_queues;
	dev_info->type = dev_type;
	dev_info->sh_mem_size = opts->dev_share_memory_size;

	return 0;
}

static int do_rbd_map(struct ubbdadm_map_options *opts)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_MAP;
	req.u.add.dev_type = UBBD_DEV_TYPE_RBD;
	dev_info_setup(&req.u.add.info, UBBD_DEV_TYPE_RBD, opts);

	return map_request_and_wait(&req);
}

static int do_null_map(struct ubbdadm_map_options *opts)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_MAP;
	req.u.add.dev_type = UBBD_DEV_TYPE_NULL;
	dev_info_setup(&req.u.add.info, UBBD_DEV_TYPE_NULL, opts);

	return map_request_and_wait(&req);
}

static int do_s3_map(struct ubbdadm_map_options *opts)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_MAP;
	req.u.add.dev_type = UBBD_DEV_TYPE_S3;
	dev_info_setup(&req.u.add.info, UBBD_DEV_TYPE_S3, opts);

	return map_request_and_wait(&req);
}

static int do_file_map(struct ubbdadm_map_options *opts)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_MAP;
	req.u.add.dev_type = UBBD_DEV_TYPE_FILE;
	dev_info_setup(&req.u.add.info, UBBD_DEV_TYPE_FILE, opts);

	return map_request_and_wait(&req);
}


static int do_ssh_map(struct ubbdadm_map_options *opts)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_MAP;
	req.u.add.dev_type = UBBD_DEV_TYPE_SSH;
	dev_info_setup(&req.u.add.info, UBBD_DEV_TYPE_SSH, opts);

	return map_request_and_wait(&req);
}

static int do_cache_map(struct ubbd_dev_info *cache_dev_info,
		struct ubbd_dev_info *backing_dev_info,
		int cache_mode)
{
	struct ubbdd_mgmt_request req = { 0 };

	req.cmd = UBBDD_MGMT_CMD_MAP;
	req.u.add.dev_type = UBBD_DEV_TYPE_CACHE;
	req.u.add.cache.cache_mode = cache_mode;
	
	memcpy(&req.u.add.info, backing_dev_info, sizeof(struct ubbd_dev_info));
	memcpy(&req.u.add.extra_info, cache_dev_info, sizeof(struct ubbd_dev_info));

	return map_request_and_wait(&req);
}

static int do_unmap(int ubbdid, bool force, bool detach)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_UNMAP;
	req.u.remove.dev_id = ubbdid;
	req.u.remove.force = force;
	req.u.remove.detach = detach;

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

static void options_init(struct ubbdadm_map_options *opts){
	memset(opts, 0, sizeof(*opts));
}

static int parse_options(struct ubbdadm_map_options *opts, const char *name, char *optarg)
{
	if (!strcmp(name, "type")) {
		opts->type = str_to_type(optarg);
	} else if (!strcmp(name, "filepath")) {
		opts->filepath = optarg;
	} else if (!strcmp(name, "pool")) {
		opts->pool = optarg;
	} else if (!strcmp(name, "image")) {
		opts->image = optarg;
	} else if (!strcmp(name, "ceph-conf")) {
		opts->ceph_conf = optarg;
	} else if (!strcmp(name, "hostname")) {
		opts->hostname = optarg;
	} else if (!strcmp(name, "devsize")) {
		opts->dev_size = atoll(optarg);
	} else if (!strcmp(name, "accessid")) {
		opts->accessid = optarg;
	} else if (!strcmp(name, "accesskey")) {
		opts->accesskey = optarg;
	} else if (!strcmp(name, "volume-name")) {
		opts->volume_name = optarg;
	} else if (!strcmp(name, "bucket-name")) {
		opts->bucket_name = optarg;
	} else if (!strcmp(name, "port")) {
		opts->port = atoi(optarg);
	} else if (!strcmp(name, "block-size")) {
		opts->block_size = atoi(optarg);
	} else if (!strcmp(name, "dev-share-memory-size")) {
		opts->dev_share_memory_size = atoi(optarg);
		if (opts->dev_share_memory_size % PAGE_SIZE) {
			ubbd_err("dev-share-memory-size: %d is not multiple of 4096.\n", opts->dev_share_memory_size);
			return -1;
		}

		if (opts->dev_share_memory_size < 4194304) {
			ubbd_err("dev-share-memory-size: %d is not in range of [4194304 - 1073741824]\n", opts->dev_share_memory_size);
			return -1;
		}
	} else if (!strcmp(name, "num-queues")) {
		opts->num_queues = atoi(optarg);
	} else {
		ubbd_err("unrecognized option: %s\n", name);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ch, longindex;
	enum ubbdd_mgmt_cmd command;
	struct ubbd_dev_info cache_dev_info, backing_dev_info;
	int ubbdid;
	int data_pages_reserve;
	bool force = false;
	int ret = 0;
	int restart_mode = UBBD_DEV_RESTART_MODE_DEFAULT;
	struct ubbdadm_map_options cache_opts, backing_opts, opts;
	int cache_mode = ocf_cache_mode_wb;
	bool detach = false;

	options_init(&cache_opts);
	options_init(&backing_opts);
	options_init(&opts);

	optopt = 0;
	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 0:
			if (!strncmp(long_options[longindex].name, "cache-dev-", 10)) {
				ret = parse_options(&cache_opts, long_options[longindex].name + 10, optarg);
			} else if (!strncmp(long_options[longindex].name, "backing-dev-", 12)) {
				ret = parse_options(&backing_opts, long_options[longindex].name + 12, optarg);
			} else {
				ret = parse_options(&opts, long_options[longindex].name, optarg);
			}
			if (ret) {
				return -1;
			}
			break;
		case 'c':
			command = str_to_cmd(optarg);
			break;
		case 'o':
			force = true;
			break;
		case 'u':
			ubbdid = atoi(optarg);
			break;
		case 'r':
			data_pages_reserve = atoi(optarg);
			break;
		case 'm':
			restart_mode = str_to_restart_mode(optarg);
			if (restart_mode < 0) {
				return -1;
			}
			break;
		case 'a':
			cache_mode = str_to_cache_mode(optarg);
			break;
		case 'd':
			detach = true;
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
		switch (opts.type) {
		case UBBD_DEV_TYPE_FILE:
			ret = do_file_map(&opts);
			break;
		case UBBD_DEV_TYPE_RBD:
			ret = do_rbd_map(&opts);
			break;
		case UBBD_DEV_TYPE_NULL:
			ret = do_null_map(&opts);
			break;
		case UBBD_DEV_TYPE_SSH:
			ret = do_ssh_map(&opts);
			break;
		case UBBD_DEV_TYPE_S3:
			ret = do_s3_map(&opts);
			break;
		case UBBD_DEV_TYPE_CACHE:
			ret = dev_info_setup(&cache_dev_info, cache_opts.type, &cache_opts);
			if (ret) {
				exit(-1);
			}

			ret = dev_info_setup(&backing_dev_info, backing_opts.type, &backing_opts);
			if (ret) {
				exit(-1);
			}

			ret = do_cache_map(&cache_dev_info, &backing_dev_info, cache_mode);
			break;
		default:
			printf("error type: %d\n", opts.type);
			exit(-1);
		}
	} else if (command == UBBDD_MGMT_CMD_UNMAP) {
		ret = do_unmap(ubbdid, force, detach);
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
