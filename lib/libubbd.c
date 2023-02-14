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
#define DEFAULT_RBD_NS		""

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

void file_dev_info_setup(struct __dev_info *info,
		struct __ubbd_map_opts *opts)
{
	strcpy(info->file.path, opts->file.filepath);
}

void rbd_dev_info_setup(struct __dev_info *info,
		struct __ubbd_map_opts *opts)
{
	strcpy(info->rbd.pool, opts->rbd.pool);
	strcpy(info->rbd.image, opts->rbd.image);
	if (opts->rbd.ceph_conf)
		strcpy(info->rbd.ceph_conf, opts->rbd.ceph_conf);
	else
		strcpy(info->rbd.ceph_conf, DEFAULT_CEPH_CONF);

	if (opts->rbd.user_name)
		strcpy(info->rbd.user_name, opts->rbd.user_name);
	else
		strcpy(info->rbd.user_name, DEFAULT_CEPH_USER);

	if (opts->rbd.cluster_name)
		strcpy(info->rbd.cluster_name, opts->rbd.cluster_name);
	else
		strcpy(info->rbd.cluster_name, DEFAULT_CEPH_CLUSTER);

	if (opts->rbd.ns)
		strcpy(info->rbd.ns, opts->rbd.ns);
	else
		strcpy(info->rbd.ns, DEFAULT_RBD_NS);
}

void null_dev_info_setup(struct __dev_info *info,
		struct __ubbd_map_opts *opts)
{
	return;
}

void s3_dev_info_setup(struct __dev_info *info,
		struct __ubbd_map_opts *opts)
{
	info->s3.block_size = opts->s3.block_size;
	info->s3.port = opts->s3.port;
	strcpy(info->s3.hostname, opts->s3.hostname);
	strcpy(info->s3.accessid, opts->s3.accessid);
	strcpy(info->s3.accesskey, opts->s3.accesskey);
	strcpy(info->s3.volume_name, opts->s3.volume_name);
	strcpy(info->s3.bucket_name, opts->s3.bucket_name);
}

void ssh_dev_info_setup(struct __dev_info *info,
		struct __ubbd_map_opts *opts)
{
	strcpy(info->ssh.path, opts->ssh.path);
	strcpy(info->ssh.hostname, opts->ssh.hostname);
}

int generic_dev_info_setup(enum ubbd_dev_type dev_type,
		struct __dev_info *info, struct __ubbd_map_opts *opts)
{
	if (dev_type == UBBD_DEV_TYPE_FILE) {
		file_dev_info_setup(info, opts);
	} else if (dev_type == UBBD_DEV_TYPE_RBD) {
		rbd_dev_info_setup(info, opts);
	} else if (dev_type == UBBD_DEV_TYPE_NULL) {
		null_dev_info_setup(info, opts);
	} else if (dev_type == UBBD_DEV_TYPE_SSH) {
		ssh_dev_info_setup(info, opts);
	} else if (dev_type == UBBD_DEV_TYPE_S3) {
		s3_dev_info_setup(info, opts);
	} else {
		ubbd_err("error dev_type: %d\n", dev_type);
		return -EINVAL;
	}

	info->size = opts->dev_size;
	info->io_timeout = opts->io_timeout;
	info->type = str_to_type(opts->type);

	return 0;
}

int dev_info_setup(struct ubbd_dev_info *dev_info,
		enum ubbd_dev_type dev_type, struct ubbd_map_options *opts)
{
	int ret = 0;

	if (dev_type >= UBBD_DEV_TYPE_MAX) {
		ubbd_err("error dev_type: %d\n", dev_type);
		return -EINVAL;
	} else if (dev_type == UBBD_DEV_TYPE_CACHE) {
		dev_info->cache_dev.cache_mode = str_to_cache_mode(opts->cache_dev.cache_mode);
		ret = generic_dev_info_setup(str_to_type(opts->cache_dev.backing_opts.type),
					&dev_info->cache_dev.backing_info, &opts->cache_dev.backing_opts);
		if (ret)
			return ret;

		ret = generic_dev_info_setup(str_to_type(opts->cache_dev.cache_opts.type),
					&dev_info->cache_dev.cache_info, &opts->cache_dev.cache_opts);
		if (ret)
			return ret;
	} else {
		opts->generic_dev.opts.type = opts->type;
		ret = generic_dev_info_setup(dev_type,
				&dev_info->generic_dev.info, &opts->generic_dev.opts);
		if (ret)
			return ret;
	}

	dev_info->num_queues = opts->num_queues;
	dev_info->type = dev_type;
	dev_info->sh_mem_size = opts->dev_share_memory_size;

	return 0;
}

int ubbd_map(struct ubbd_map_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = { 0 };
	int ret;

	req.cmd = UBBDD_MGMT_CMD_MAP;
	ret = dev_info_setup(&req.u.add.info, str_to_type(opts->type), opts);
	if (ret)
		return ret;

	return request_and_wait(&req, rsp);
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
