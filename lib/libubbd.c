#define _GNU_SOURCE
#include <getopt.h>
#include <sys/types.h>

#include "libubbd.h"
#include "ocf/ocf_def.h"
#include "ubbd_daemon_mgmt.h"
#include "ubbd_dev.h"
#include "utils.h"
#include "ubbd_netlink.h"

#define DEFAULT_CEPH_CONF "/etc/ceph/ceph.conf"
#define DEFAULT_CEPH_USER	"client.admin"
#define DEFAULT_CEPH_CLUSTER	"ceph"

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

char* cache_mode_to_str(int cache_mode)
{
	if (cache_mode == ocf_cache_mode_wb)
		return "writeback";
	else if (cache_mode == ocf_cache_mode_wt)
		return "writethrough";
	else
		return NULL;
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
		printf("unrecognized restart mode: %s\n", str);
		restart_mode = -1;
	}

	return restart_mode;

}


int request_and_wait(struct ubbdd_mgmt_request *req, struct ubbdd_mgmt_rsp *rsp)
{
	int fd;
	int ret;

	ret = ubbdd_request(&fd, req);
	if (ret) {
		ubbd_err("failed to send %s request to ubbdd: %d.\n", cmd_to_str(req->cmd), ret);
		return ret;
	}
	
	ret = ubbdd_response(fd, rsp, -1);
	if (ret) {
		ubbd_err("error in waiting response for %s request: %d.\n", cmd_to_str(req->cmd), ret);
		return ret;
	}

	return 0;
}

int generic_request_and_wait(struct ubbdd_mgmt_request *req, struct ubbdd_mgmt_rsp *rsp)
{
	return request_and_wait(req, rsp);
}

void file_dev_info_setup(struct ubbd_dev_info *dev_info,
		struct ubbd_map_options *opts)
{
	strcpy(dev_info->generic_dev.info.file.path, opts->u.file.filepath);
	dev_info->generic_dev.info.file.size = opts->dev_size;
}

void rbd_dev_info_setup(struct ubbd_dev_info *dev_info,
		struct ubbd_map_options *opts)
{
	strcpy(dev_info->generic_dev.info.rbd.pool, opts->u.rbd.pool);
	strcpy(dev_info->generic_dev.info.rbd.image, opts->u.rbd.image);
	if (opts->u.rbd.ceph_conf)
		strcpy(dev_info->generic_dev.info.rbd.ceph_conf, opts->u.rbd.ceph_conf);
	else
		strcpy(dev_info->generic_dev.info.rbd.ceph_conf, DEFAULT_CEPH_CONF);

	if (opts->u.rbd.user_name)
		strcpy(dev_info->generic_dev.info.rbd.user_name, opts->u.rbd.user_name);
	else
		strcpy(dev_info->generic_dev.info.rbd.user_name, DEFAULT_CEPH_USER);

	if (opts->u.rbd.cluster_name)
		strcpy(dev_info->generic_dev.info.rbd.cluster_name, opts->u.rbd.cluster_name);
	else
		strcpy(dev_info->generic_dev.info.rbd.cluster_name, DEFAULT_CEPH_CLUSTER);
}

void null_dev_info_setup(struct ubbd_dev_info *dev_info,
		struct ubbd_map_options *opts)
{
	dev_info->generic_dev.info.null.size = opts->dev_size;
}

void s3_dev_info_setup(struct ubbd_dev_info *dev_info,
		struct ubbd_map_options *opts)
{
	dev_info->generic_dev.info.s3.size = opts->dev_size;
	dev_info->generic_dev.info.s3.block_size = opts->u.s3.block_size;
	dev_info->generic_dev.info.s3.port = opts->u.s3.port;
	strcpy(dev_info->generic_dev.info.s3.hostname, opts->u.s3.hostname);
	strcpy(dev_info->generic_dev.info.s3.accessid, opts->u.s3.accessid);
	strcpy(dev_info->generic_dev.info.s3.accesskey, opts->u.s3.accesskey);
	strcpy(dev_info->generic_dev.info.s3.volume_name, opts->u.s3.volume_name);
	strcpy(dev_info->generic_dev.info.s3.bucket_name, opts->u.s3.bucket_name);
}

void ssh_dev_info_setup(struct ubbd_dev_info *dev_info,
		struct ubbd_map_options *opts)
{
	strcpy(dev_info->generic_dev.info.ssh.path, opts->u.ssh.path);
	strcpy(dev_info->generic_dev.info.ssh.hostname, opts->u.ssh.hostname);
	dev_info->generic_dev.info.ssh.size = opts->dev_size;
}

int dev_info_setup(struct ubbd_dev_info *dev_info,
		enum ubbd_dev_type dev_type, struct ubbd_map_options *opts)
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

int do_rbd_map(struct ubbd_map_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_MAP;
	req.u.add.dev_type = UBBD_DEV_TYPE_RBD;
	dev_info_setup(&req.u.add.info, UBBD_DEV_TYPE_RBD, opts);

	return request_and_wait(&req, rsp);
}

int do_null_map(struct ubbd_map_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_MAP;
	req.u.add.dev_type = UBBD_DEV_TYPE_NULL;
	dev_info_setup(&req.u.add.info, UBBD_DEV_TYPE_NULL, opts);

	return request_and_wait(&req, rsp);
}

int do_s3_map(struct ubbd_map_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_MAP;
	req.u.add.dev_type = UBBD_DEV_TYPE_S3;
	dev_info_setup(&req.u.add.info, UBBD_DEV_TYPE_S3, opts);

	return request_and_wait(&req, rsp);
}

int do_file_map(struct ubbd_map_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_MAP;
	req.u.add.dev_type = UBBD_DEV_TYPE_FILE;
	dev_info_setup(&req.u.add.info, UBBD_DEV_TYPE_FILE, opts);

	return request_and_wait(&req, rsp);
}


int do_ssh_map(struct ubbd_map_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_MAP;
	req.u.add.dev_type = UBBD_DEV_TYPE_SSH;
	dev_info_setup(&req.u.add.info, UBBD_DEV_TYPE_SSH, opts);

	return request_and_wait(&req, rsp);
}

int do_cache_map(struct ubbd_map_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = { 0 };
	int ret = 0;

	req.cmd = UBBDD_MGMT_CMD_MAP;
	req.u.add.dev_type = UBBD_DEV_TYPE_CACHE;
	req.u.add.cache.cache_mode = str_to_cache_mode(opts->u.cache.cache_mode);

	ret = dev_info_setup(&req.u.add.info, str_to_type(opts->u.cache.backing_opts->type), opts->u.cache.backing_opts);
	if (ret) {
		return ret;
	}

	ret = dev_info_setup(&req.u.add.extra_info, str_to_type(opts->u.cache.cache_opts->type), opts->u.cache.cache_opts);
	if (ret) {
		return ret;
	}
	
	return request_and_wait(&req, rsp);
}

int ubbd_map(struct ubbd_map_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	int ret = 0;

	if (!strcmp("file", opts->type)) {
		ret = do_file_map(opts, rsp);
	} else if (!strcmp("rbd", opts->type)){
		ret = do_rbd_map(opts, rsp);
	} else if (!strcmp("null", opts->type)){
		ret = do_null_map(opts, rsp);
	} else if (!strcmp("ssh", opts->type)){
		ret = do_ssh_map(opts, rsp);
	} else if (!strcmp("s3", opts->type)){
		ret = do_s3_map(opts, rsp);
	} else if (!strcmp("cache", opts->type)){
		ret = do_cache_map(opts, rsp);
	} else {
		ret = -1;
	}

	return ret;
}

int ubbd_unmap(struct ubbd_unmap_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_UNMAP;
	req.u.remove.dev_id = opts->ubbdid;
	req.u.remove.force = opts->force;
	req.u.remove.detach = opts->detach;

	return generic_request_and_wait(&req, rsp);
}

int ubbd_config(struct ubbd_config_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_CONFIG;
	req.u.config.dev_id = opts->ubbdid;
	req.u.config.data_pages_reserve_percnt = opts->data_pages_reserve_percnt;

	return generic_request_and_wait(&req, rsp);
}

int ubbd_list(struct ubbd_list_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_LIST;

	return generic_request_and_wait(&req, rsp);
}

int ubbd_req_stats(struct ubbd_req_stats_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_REQ_STATS;
	req.u.req_stats.dev_id = opts->ubbdid;

	return generic_request_and_wait(&req, rsp);
}

int ubbd_req_stats_reset(struct ubbd_req_stats_reset_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_REQ_STATS_RESET;
	req.u.req_stats_reset.dev_id = opts->ubbdid;

	return generic_request_and_wait(&req, rsp);
}

int ubbd_device_restart(struct ubbd_dev_restart_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = {0};

	req.cmd = UBBDD_MGMT_CMD_DEV_RESTART;
	req.u.dev_restart.dev_id = opts->ubbdid;
	req.u.dev_restart.restart_mode = str_to_restart_mode(opts->restart_mode);

	return generic_request_and_wait(&req, rsp);
}

int ubbd_device_info(struct ubbd_info_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = { 0 };

	req.cmd = UBBDD_MGMT_CMD_DEV_INFO;
	req.u.dev_info.dev_id = opts->ubbdid;

	return generic_request_and_wait(&req, rsp);
}
