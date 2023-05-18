#define _GNU_SOURCE
#include <getopt.h>
#include <sys/types.h>

#include "ubbd_compat.h"
#include "ubbd_log.h"
#include "ubbd_daemon_mgmt.h"
#include "utils.h"

/* 32M */
#define DEFAULT_SHMEM_SIZE	(32 * 1024 *1024)
#define DEFAULT_NUM_QUEUES	1

#define DEFAULT_CEPH_CONF	"/etc/ceph/ceph.conf"
#define DEFAULT_CEPH_USER	"client.admin"
#define DEFAULT_CEPH_CLUSTER	"ceph"
#define DEFAULT_RBD_NS		""
#define DEFAULT_RBD_POOL	"rbd"
#define DEFAULT_RBD_QUIESCE_HOOK	"/usr/lib/ubbd/ubbd-rbd_quiesce"

#define UBBD_CACHE_MODE_WT	0
#define UBBD_CACHE_MODE_WB	1

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

static enum ubbd_dev_type str_to_type(const char *str)
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
	else if (!strcmp("mem", str))
		type = UBBD_DEV_TYPE_MEM;
	else
		type = -1;

	return type;
}

int str_to_cache_mode(const char *str)
{
	int cache_mode;

	if (!strcmp("writeback", str)){
		cache_mode = UBBD_CACHE_MODE_WB;
	} else if (!strcmp("writethrough", str)) {
		cache_mode = UBBD_CACHE_MODE_WT;
	} else {
		cache_mode = -1;
	}

	return cache_mode;
}

const char* ubbd_cache_mode_to_str(int cache_mode)
{
	if (cache_mode == UBBD_CACHE_MODE_WB)
		return "writeback";
	else if (cache_mode == UBBD_CACHE_MODE_WT)
		return "writethrough";
	else
		return NULL;
}

int str_to_restart_mode(const char *str)
{
	int restart_mode;

	if (!strcmp("default", str))
		restart_mode = UBBD_DEV_RESTART_MODE_DEFAULT;
	else if (!strcmp("dev", str))
		restart_mode = UBBD_DEV_RESTART_MODE_DEV;
	else if (!strcmp("queue", str))
		restart_mode = UBBD_DEV_RESTART_MODE_QUEUE;
	else {
		fprintf(stderr, "unrecognized restart mode: %s\n", str);
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
		fprintf(stderr, "failed to send %s request to ubbdd: %d.\n", cmd_to_str(req->cmd), ret);
		return ret;
	}
	
	memset(rsp, 0, sizeof(*rsp));

	ret = ubbdd_response(fd, rsp, -1);
	if (ret) {
		fprintf(stderr, "error in waiting response for %s request: %d.\n", cmd_to_str(req->cmd), ret);
		return ret;
	}

	return 0;
}

int generic_request_and_wait(struct ubbdd_mgmt_request *req, struct ubbdd_mgmt_rsp *rsp)
{
	return request_and_wait(req, rsp);
}

void file_dev_info_setup(struct __ubbd_dev_info *info,
		struct __ubbd_map_opts *opts)
{
	strcpy(info->file.path, opts->file.filepath);
}

void rbd_dev_info_setup(struct __ubbd_dev_info *info,
		struct __ubbd_map_opts *opts)
{
	strcpy(info->rbd.image, opts->rbd.image);
	if (opts->rbd.pool && strlen(opts->rbd.pool))
		strcpy(info->rbd.pool, opts->rbd.pool);
	else
		strcpy(info->rbd.pool, DEFAULT_RBD_POOL);

	if (opts->rbd.ceph_conf && strlen(opts->rbd.ceph_conf))
		strcpy(info->rbd.ceph_conf, opts->rbd.ceph_conf);
	else
		strcpy(info->rbd.ceph_conf, DEFAULT_CEPH_CONF);

	if (opts->rbd.user_name && strlen(opts->rbd.user_name))
		strcpy(info->rbd.user_name, opts->rbd.user_name);
	else
		strcpy(info->rbd.user_name, DEFAULT_CEPH_USER);

	if (opts->rbd.cluster_name && strlen(opts->rbd.cluster_name))
		strcpy(info->rbd.cluster_name, opts->rbd.cluster_name);
	else
		strcpy(info->rbd.cluster_name, DEFAULT_CEPH_CLUSTER);

	if (opts->rbd.ns && strlen(opts->rbd.ns))
		strcpy(info->rbd.ns, opts->rbd.ns);
	else
		strcpy(info->rbd.ns, DEFAULT_RBD_NS);

	if (opts->rbd.snap && strlen(opts->rbd.snap)) {
		info->rbd.flags |= UBBD_DEV_INFO_RBD_FLAGS_SNAP;
		strcpy(info->rbd.snap, opts->rbd.snap);
	}

	if (opts->rbd.exclusive) {
		info->rbd.flags |= UBBD_DEV_INFO_RBD_FLAGS_EXCLUSIVE;
	}

	if (opts->rbd.quiesce) {
		info->rbd.flags |= UBBD_DEV_INFO_RBD_FLAGS_QUIESCE;
		if (opts->rbd.quiesce_hook && strlen(opts->rbd.quiesce_hook)) {
			strcpy(info->rbd.quiesce_hook, opts->rbd.quiesce_hook);
		} else {
			strcpy(info->rbd.quiesce_hook, DEFAULT_RBD_QUIESCE_HOOK);
		}
	}
}

void null_dev_info_setup(struct __ubbd_dev_info *info,
		struct __ubbd_map_opts *opts)
{
	return;
}

void mem_dev_info_setup(struct __ubbd_dev_info *info,
		struct __ubbd_map_opts *opts)
{
	return;
}

void s3_dev_info_setup(struct __ubbd_dev_info *info,
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

void ssh_dev_info_setup(struct __ubbd_dev_info *info,
		struct __ubbd_map_opts *opts)
{
	strcpy(info->ssh.path, opts->ssh.path);
	strcpy(info->ssh.hostname, opts->ssh.hostname);
}

int generic_dev_info_setup(enum ubbd_dev_type dev_type,
		struct __ubbd_dev_info *info, struct __ubbd_map_opts *opts)
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
	} else if (dev_type == UBBD_DEV_TYPE_MEM) {
		mem_dev_info_setup(info, opts);
	} else {
		fprintf(stderr, "error dev_type: %d\n", dev_type);
		return -EINVAL;
	}

	info->header.magic = UBBD_DEV_INFO_MAGIC;
	info->header.version = UBBD_DEV_INFO_VERSION;
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
		fprintf(stderr, "error dev_type: %d\n", dev_type);
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
	if (opts->read_only) {
		dev_info->flags |= UBBD_DEV_INFO_FLAGS_READONLY;
	}

	return 0;
}

static int validate_generic_map_opts(struct __ubbd_map_opts *opts)
{
	if (!opts->type) {
		fprintf(stderr, "type is required in __ubbd_map_opts.\n");
		return -EINVAL;
	}

	if (!strcmp("file", opts->type)) {
		if (!opts->file.filepath) {
			fprintf(stderr, "filepath is required for file mapping.\n");
			return -EINVAL;
		}
	} else if (!strcmp("rbd", opts->type)) {
		if (!opts->rbd.image) {
			fprintf(stderr, "image is required for rbd mapping.\n");
			return -EINVAL;
		}

#ifndef HAVE_RBD_QUIESCE
		if (opts->rbd.quiesce) {
			fprintf(stderr, "rbd quiesce is not supported by librbd,\
					please make sure rbd_quiesce_complete is in your librbd.so\n");
			return -EINVAL;
		}
#endif
	} else if (!strcmp("ssh", opts->type)) {
		if (!opts->ssh.hostname ||
			!opts->ssh.path) {
			fprintf(stderr, "hostname and path is required for ssh mapping.\n");
			return -EINVAL;
		}
	} else if (!strcmp("s3", opts->type)) {
		if (!opts->s3.block_size ||
				!opts->s3.hostname ||
				!opts->s3.accessid ||
				!opts->s3.accesskey ||
				!opts->s3.volume_name ||
				!opts->s3.bucket_name) {
			fprintf(stderr, "block_size, hostname, accessid, accesskey, \
					volume_name, bucket_name are required for ssh mapping.\n");
			return -EINVAL;
		}
	}

	return 0;
}

static int validate_map_opts(struct ubbd_map_options *opts)
{
	int ret;

	if (!opts->type) {
		fprintf(stderr, "type is required for mapping.\n");
		return -EINVAL;
	}

	if (strcmp("rbd", opts->type) && strcmp("file", opts->type)) {
		if (!opts->generic_dev.opts.dev_size) {
			fprintf(stderr, "devsize is required.\n");
			return -EINVAL;
		}
	}

	if (!opts->num_queues)
		opts->num_queues = DEFAULT_NUM_QUEUES;

	if (!opts->dev_share_memory_size)
		opts->dev_share_memory_size = DEFAULT_SHMEM_SIZE;

	if (!strcmp("cache", opts->type)) {
		if (!opts->cache_dev.cache_mode) {
			fprintf(stderr, "cache_mode is required for cache mapping.\n");
			return -EINVAL;
		}

		ret = validate_generic_map_opts(&opts->cache_dev.cache_opts);
		if (ret) {
			fprintf(stderr, "cache options is invalid\n");
			return ret;
		}

		ret = validate_generic_map_opts(&opts->cache_dev.backing_opts);
		if (ret) {
			fprintf(stderr, "backing options is invalid\n");
			return ret;
		}
	} else {
		opts->generic_dev.opts.type = opts->type;
		return validate_generic_map_opts(&opts->generic_dev.opts);
	}

	return 0;
}

int ubbd_map(struct ubbd_map_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = { 0 };
	int ret;

	ubbd_request_header_init(&req.header);
	ret = validate_map_opts(opts);
	if (ret)
		return ret;

	req.cmd = UBBDD_MGMT_CMD_MAP;
	ret = dev_info_setup(&req.u.add.info, str_to_type(opts->type), opts);
	if (ret)
		return ret;

	return request_and_wait(&req, rsp);
}

static int validate_ubbdid(int ubbdid) {
	if (ubbdid < 0) {
		fprintf(stderr, "invalid ubbdid: %d\n", ubbdid);
		return -EINVAL;
	}

	return 0;
}

static int validate_unmap_opts(struct ubbd_unmap_options *opts) {
	int ret;

	ret = validate_ubbdid(opts->ubbdid);

	return ret;
}

int ubbd_unmap(struct ubbd_unmap_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = { 0 };
	int ret;

	ret = validate_unmap_opts(opts);
	if (ret)
		return ret;

	ubbd_request_header_init(&req.header);
	req.cmd = UBBDD_MGMT_CMD_UNMAP;
	req.u.remove.dev_id = opts->ubbdid;
	req.u.remove.force = opts->force;
	req.u.remove.detach = opts->detach;

	return generic_request_and_wait(&req, rsp);
}

static int validate_config_opts(struct ubbd_config_options *opts) {
	int ret;

	ret = validate_ubbdid(opts->ubbdid);

	return ret;
}

int ubbd_config(struct ubbd_config_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = { 0 };
	int ret;

	ret = validate_config_opts(opts);
	if (ret)
		return ret;

	ubbd_request_header_init(&req.header);
	req.cmd = UBBDD_MGMT_CMD_CONFIG;
	req.u.config.dev_id = opts->ubbdid;
	req.u.config.data_pages_reserve_percnt = opts->data_pages_reserve_percnt;

	return generic_request_and_wait(&req, rsp);
}

static int validate_list_opts(struct ubbd_list_options *opts) {
	if (opts->type >= UBBD_DEV_TYPE_MAX && opts->type != -1) {
		fprintf(stderr, "invalid type for list: %d\n", opts->type);
		return -EINVAL;
	}

	return 0;
}

int ubbd_list(struct ubbd_list_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = { 0 };
	int ret;

	ret = validate_list_opts(opts);
	if (ret)
		return ret;

	ubbd_request_header_init(&req.header);
	req.cmd = UBBDD_MGMT_CMD_LIST;
	req.u.list.type = opts->type;

	return generic_request_and_wait(&req, rsp);
}

static int validate_req_stats_opts(struct ubbd_req_stats_options *opts) {
	int ret;

	ret = validate_ubbdid(opts->ubbdid);

	return ret;
}

int ubbd_req_stats(struct ubbd_req_stats_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = { 0 };
	int ret;

	ret = validate_req_stats_opts(opts);
	if (ret)
		return ret;

	ubbd_request_header_init(&req.header);
	req.cmd = UBBDD_MGMT_CMD_REQ_STATS;
	req.u.req_stats.dev_id = opts->ubbdid;

	return generic_request_and_wait(&req, rsp);
}

static int validate_req_stats_reset_opts(struct ubbd_req_stats_reset_options *opts) {
	int ret;

	ret = validate_ubbdid(opts->ubbdid);

	return ret;
}

int ubbd_req_stats_reset(struct ubbd_req_stats_reset_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = { 0 };
	int ret;

	ret = validate_req_stats_reset_opts(opts);
	if (ret)
		return ret;

	ubbd_request_header_init(&req.header);
	req.cmd = UBBDD_MGMT_CMD_REQ_STATS_RESET;
	req.u.req_stats_reset.dev_id = opts->ubbdid;

	return generic_request_and_wait(&req, rsp);
}

static int validate_dev_restart_opts(struct ubbd_dev_restart_options *opts) {
	int ret;

	ret = validate_ubbdid(opts->ubbdid);

	return ret;
}

int ubbd_device_restart(struct ubbd_dev_restart_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = { 0 };
	int ret;

	ret = validate_dev_restart_opts(opts);
	if (ret)
		return ret;

	ubbd_request_header_init(&req.header);
	req.cmd = UBBDD_MGMT_CMD_DEV_RESTART;
	req.u.dev_restart.dev_id = opts->ubbdid;
	if (!opts->restart_mode)
		opts->restart_mode = "default";
	req.u.dev_restart.restart_mode = str_to_restart_mode(opts->restart_mode);

	return generic_request_and_wait(&req, rsp);
}

static int validate_info_opts(struct ubbd_info_options *opts) {
	int ret;

	ret = validate_ubbdid(opts->ubbdid);

	return ret;
}

int ubbd_device_info(struct ubbd_info_options *opts, struct ubbdd_mgmt_rsp *rsp)
{
	struct ubbdd_mgmt_request req = { 0 };
	int ret;

	ret = validate_info_opts(opts);
	if (ret)
		return ret;

	ubbd_request_header_init(&req.header);
	req.cmd = UBBDD_MGMT_CMD_DEV_INFO;
	req.u.dev_info.dev_id = opts->ubbdid;

	return generic_request_and_wait(&req, rsp);
}
