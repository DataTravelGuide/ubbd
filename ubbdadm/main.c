#define _GNU_SOURCE
#include <getopt.h>
#include <sys/types.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>

#include "libubbd.h"


#define UBBD_MAP_OPT(prefix, name)					\
	{#prefix"-"#name, required_argument, NULL, 0},			\
	{"cache-dev-"#prefix"-"#name, required_argument, NULL, 0},	\
	{"backing-dev-"#prefix"-"#name, required_argument, NULL, 0},

#define UBBD_MAP_NOPRE_OPT(name)					\
	{#name, required_argument, NULL, 0},				\
	{"cache-dev-"#name, required_argument, NULL, 0},		\
	{"backing-dev-"#name, required_argument, NULL, 0},


static struct option const long_options[] =
{
	{"command", required_argument, NULL, 'c'},
	{"force", no_argument, NULL, 'o'},
	{"ubbdid", required_argument, NULL, 'u'},
	{"data-pages-reserve-percnt", required_argument, NULL, 'r'},
	{"restart-mode", required_argument, NULL, 'm'},
	{"detach", no_argument, NULL, 'd'},

	UBBD_MAP_NOPRE_OPT(type)
	UBBD_MAP_NOPRE_OPT(devsize)
	UBBD_MAP_NOPRE_OPT(dev-share-memory-size)
	UBBD_MAP_NOPRE_OPT(num-queues)

	UBBD_MAP_OPT(file, filepath)

	UBBD_MAP_OPT(rbd, pool)
	UBBD_MAP_OPT(rbd, image)
	UBBD_MAP_OPT(rbd, ceph-conf)
	UBBD_MAP_OPT(rbd, user-name)
	UBBD_MAP_OPT(rbd, cluster-name)

	UBBD_MAP_OPT(ssh, hostname)
	UBBD_MAP_OPT(ssh, filepath)

	UBBD_MAP_OPT(s3, block-size)
	UBBD_MAP_OPT(s3, port)
	UBBD_MAP_OPT(s3, hostname)
	UBBD_MAP_OPT(s3, accessid)
	UBBD_MAP_OPT(s3, accesskey)
	UBBD_MAP_OPT(s3, volume-name)
	UBBD_MAP_OPT(s3, bucket-name)

	UBBD_MAP_OPT(cache, mode)

	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static char *short_options = "c:o:u:r:m:d:h";

static void print_map_opt_msg(char *name, char *msg)
{
	printf("\t\t--%-35s %s.\n", name, msg);
	printf("\t\t--cache-dev-%-25s %s for cache device.\n", name, msg);
	printf("\t\t--backing-dev-%-23s %s for backing device.\n", name, msg);
}

static void print_opt_msg(char *name, char *msg)
{
	printf("\t\t--%-35s %s.\n", name, msg);
}

static void usage(int status)
{ 
	if (status != 0)
		fprintf(stderr, "Try `ubbdadm --help' for more information.\n");
	else {
		printf("Usage:\n");
		printf("\tubbdadm --command <cmd> [options]\n\n");
		printf("\t--command	subcmd for ubbdadm: map, unmap, list, info, config, req-stats, req-stats-reset, dev-restart.\n");

		/* generic options */
		printf("\n\t[generic options]:\n");
		print_opt_msg("ubbdid", "id of ubbd device command operating on");

		/* unmap options */
		printf("\n\t[unmap options]:\n");
		print_opt_msg("force", "force unmap a device, that means this command will fail inflight IO and unmap device");
		print_opt_msg("detach", "this option works for cache type device, if detach is specified, cache device will be detached from backing in unmap");

		/* list options */
		printf("\n\t[list options]:\n");

		/* info options */
		printf("\n\t[info options]:\n");

		/* config options */
		printf("\n\t[config options]:\n");
		print_opt_msg("data-pages-reserve-percnt", "update the data pages reserved for each queue: [0 - 100]");

		/* dev-restart options */
		printf("\n\t[dev-restart options ]");
		print_opt_msg("restart-mode", "mode to restart device: dev, queue, default");

		/* map options */
		printf("\n\t[map options]:\n");

		print_map_opt_msg("type", "device type for mapping: file, rbd, null, ssh, cache, s3");
		print_map_opt_msg("devsize", "size of device to map, range is [4194304 (4M) - 1073741824 (1G)], --devsize is required except rbd type");
		print_map_opt_msg("dev-share-memory-size", "share memory for each queue between userspace and kernel space");
		print_map_opt_msg("num-queues", "number of queues for block layer multiqueue");

		printf("\n");

		print_map_opt_msg("file-filepath", "file path for file type mapping");

		printf("\n");

		print_map_opt_msg("rbd-pool", "pool for rbd type mapping");
		print_map_opt_msg("rbd-image", "image for rbd type mapping");
		print_map_opt_msg("rbd-ceph-conf", "ceph config file path for rbd type mapping");
		print_map_opt_msg("rbd-user-name", "user name to connect ceph for rbd type mapping");
		print_map_opt_msg("rbd-cluster-name", "ceph cluster name for rbd type mapping");

		printf("\n");

		print_map_opt_msg("ssh-hostname", "hostname for ssh type mapping");
		print_map_opt_msg("ssh-filepath", "filepath in remote host for ssh type mapping");

		printf("\n");

		print_map_opt_msg("s3-block-size", "block size in s3 cluster, s3 type ubbd data is stored in block");
		print_map_opt_msg("s3-hostname", "hostname to connect s3 cluster");
		print_map_opt_msg("s3-port", "port to connect s3 cluster");
		print_map_opt_msg("s3-accessid", "accessid to connect s3 cluster");
		print_map_opt_msg("s3-accesskey", "accesskey to connect s3 cluster");
		print_map_opt_msg("s3-volume-name", "create a volume in s3 cluster");
		print_map_opt_msg("s3-bucket-name", "data is stored in s3 cluster bucket");

		printf("\n");

		print_map_opt_msg("cache-mode", "cache mode for cache type mapping: writeback, writethrough");
	}
}

static int parse_map_options(struct ubbd_map_options *opts, const char *name, char *optarg)
{
	if (!strcmp(name, "type")) {
		opts->type = optarg;
	} else if (!strcmp(name, "devsize")) {
		opts->dev_size = atoll(optarg);
	} else if (!strcmp(name, "dev-share-memory-size")) {
		opts->dev_share_memory_size = atoi(optarg);
		if (opts->dev_share_memory_size % PAGE_SIZE) {
			printf("dev-share-memory-size: %d is not multiple of 4096.\n",
				       opts->dev_share_memory_size);
			return -1;
		}

		if (opts->dev_share_memory_size < 4194304) {
			printf("dev-share-memory-size: %d is not in range of [4194304 (4M) - 1073741824 (1G)]\n",
					opts->dev_share_memory_size);
			return -1;
		}
	} else if (!strcmp(name, "num-queues")) {
		opts->num_queues = atoi(optarg);
	} else if (!strcmp(name, "file-filepath")) {
		opts->u.file.filepath = optarg;
	} else if (!strcmp(name, "rbd-pool")) {
		opts->u.rbd.pool = optarg;
	} else if (!strcmp(name, "rbd-image")) {
		opts->u.rbd.image = optarg;
	} else if (!strcmp(name, "rbd-ceph-conf")) {
		opts->u.rbd.ceph_conf = optarg;
	} else if (!strcmp(name, "rbd-user-name")) {
		opts->u.rbd.user_name = optarg;
	} else if (!strcmp(name, "rbd-cluster-name")) {
		opts->u.rbd.cluster_name = optarg;
	} else if (!strcmp(name, "ssh-hostname")) {
		opts->u.ssh.hostname = optarg;
	} else if (!strcmp(name, "ssh-filepath")) {
		opts->u.ssh.path = optarg;
	} else if (!strcmp(name, "s3-hostname")) {
		opts->u.s3.hostname = optarg;
	} else if (!strcmp(name, "s3-accessid")) {
		opts->u.s3.accessid = optarg;
	} else if (!strcmp(name, "s3-accesskey")) {
		opts->u.s3.accesskey = optarg;
	} else if (!strcmp(name, "s3-volume-name")) {
		opts->u.s3.volume_name = optarg;
	} else if (!strcmp(name, "s3-bucket-name")) {
		opts->u.s3.bucket_name = optarg;
	} else if (!strcmp(name, "s3-port")) {
		opts->u.s3.port = atoi(optarg);
	} else if (!strcmp(name, "s3-block-size")) {
		opts->u.s3.block_size = atoi(optarg);
	} else if (!strcmp(name, "cache-mode")) {
		opts->u.cache.cache_mode = optarg;
	} else {
		printf("unrecognized option: %s\n", name);
		return -1;
	}

	return 0;
}


static char *type_to_str(enum ubbd_dev_type type)
{
	if (type == UBBD_DEV_TYPE_FILE)
		return "file";
	else if (type == UBBD_DEV_TYPE_RBD)
		return "rbd";
	else if (type == UBBD_DEV_TYPE_NULL)
		return "null";
	else if (type == UBBD_DEV_TYPE_SSH)
		return "ssh";
	else if (type == UBBD_DEV_TYPE_CACHE)
		return "cache";
	else if (type == UBBD_DEV_TYPE_S3)
		return "s3";
	else
		return "Unknown type";
}


static void output_dev_generic_info(struct ubbdd_mgmt_rsp *rsp)
{
	printf("UBBD: /dev/ubbd%d:\n", rsp->u.dev_info.devid);
	printf("\ttype: %s\n", type_to_str(rsp->u.dev_info.type));
	printf("\tsize: %lu\n",	rsp->u.dev_info.size);
	printf("\tqueues: %u\n", rsp->u.dev_info.num_queues);
}

static int __output_dev_info_detail(struct ubbd_dev_info *dev_info)
{
	int dev_type = dev_info->type;
	int ret = 0;

	if (dev_type == UBBD_DEV_TYPE_FILE) {
		printf("\tfilepath: %s\n", dev_info->generic_dev.info.file.path);
	} else if (dev_type == UBBD_DEV_TYPE_RBD) {
		printf("\tceph_conf: %s\n", dev_info->generic_dev.info.rbd.ceph_conf);
		printf("\tpool: %s\n", dev_info->generic_dev.info.rbd.pool);
		printf("\timage: %s\n", dev_info->generic_dev.info.rbd.image);
		printf("\tcluster_name: %s\n", dev_info->generic_dev.info.rbd.cluster_name);
		printf("\tuser_name: %s\n", dev_info->generic_dev.info.rbd.user_name);
	} else if (dev_type == UBBD_DEV_TYPE_NULL) {
	} else if (dev_type == UBBD_DEV_TYPE_SSH) {
		printf("\thostname: %s\n", dev_info->generic_dev.info.ssh.hostname);
		printf("\tpath: %s\n", dev_info->generic_dev.info.ssh.path);
	} else if (dev_type == UBBD_DEV_TYPE_S3) {
		printf("\thostname: %s\n", dev_info->generic_dev.info.s3.hostname);
		printf("\tport: %d\n", dev_info->generic_dev.info.s3.port);
		printf("\tblock_size: %d\n", dev_info->generic_dev.info.s3.block_size);
		printf("\taccessid: %s\n", dev_info->generic_dev.info.s3.accessid);
		printf("\taccesskey: %s\n", dev_info->generic_dev.info.s3.accesskey);
		printf("\tvolume_name: %s\n", dev_info->generic_dev.info.s3.volume_name);
		printf("\tbucket_name: %s\n", dev_info->generic_dev.info.s3.bucket_name);
	} else {
		printf("error type: %d\n", dev_type);
		ret = -1;
	}

	return ret;
}

static int output_dev_info_detail(int dev_type, struct ubbdd_mgmt_rsp_dev_info *mgmt_dev_info)
{
	int ret = 0;

	if (dev_type == UBBD_DEV_TYPE_CACHE) {
		printf("\tcache_mode: %s\n", cache_mode_to_str(mgmt_dev_info->cache.cache_mode));
		printf("\n\tcache_dev: type %s\n", type_to_str(mgmt_dev_info->extra_info.type));
		ret = __output_dev_info_detail(&mgmt_dev_info->extra_info);
		if (ret)
			goto out;

		printf("\n\tbacking_dev: type %s\n", type_to_str(mgmt_dev_info->dev_info.type));
		ret = __output_dev_info_detail(&mgmt_dev_info->dev_info);
	} else {
		ret = __output_dev_info_detail(&mgmt_dev_info->dev_info);
	}

out:
	return ret;
}

static int output_dev_info(struct ubbdd_mgmt_rsp *rsp)
{
	int ret = 0;

	output_dev_generic_info(rsp);
	ret = output_dev_info_detail(rsp->u.dev_info.type, &rsp->u.dev_info);

	return ret;
}

struct ubbd_map_options cache_opts, backing_opts, opts;

int main(int argc, char **argv)
{
	int ch, longindex;
	char *command;
	int ubbdid;
	int data_pages_reserve_percnt;
	bool force = false;
	int ret = 0;
	bool detach = false;
	char *restart_mode;
	struct ubbdd_mgmt_rsp rsp = { 0 };

	optopt = 0;
	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 0:
			if (!strncmp(long_options[longindex].name, "cache-dev-", 10)) {
				ret = parse_map_options(&cache_opts,
						long_options[longindex].name + 10,
						optarg);
			} else if (!strncmp(long_options[longindex].name, "backing-dev-", 12)) {
				ret = parse_map_options(&backing_opts,
						long_options[longindex].name + 12,
						optarg);
			} else {
				ret = parse_map_options(&opts, long_options[longindex].name, optarg);
			}
			if (ret) {
				return -1;
			}
			break;
		case 'c':
			command = optarg;
			break;
		case 'o':
			force = true;
			break;
		case 'u':
			ubbdid = atoi(optarg);
			break;
		case 'r':
			data_pages_reserve_percnt = atoi(optarg);
			break;
		case 'm':
			restart_mode = optarg;
			break;
		case 'd':
			detach = true;
			break;
		case 'h':
			usage(0);
			return 0;
		default:
			printf("unrecognized ubbd option.\n");
			return -1;
		}
	}

	if (optopt) {
		printf("unrecognized character '%c'\n", optopt);
		return -1;
	}

	/* action for command */
	if (!strcmp("map", command)) {
		if (!strcmp("cache", opts.type)) {
			opts.u.cache.cache_opts = &cache_opts;
			opts.u.cache.backing_opts = &backing_opts;
		} else if (strcmp("rbd", opts.type)) {
			if (!opts.dev_size) {
				printf("--devsize is required.\n");
				ret = -1;
				goto out;
			}
		}

		ret = ubbd_map(&opts, &rsp);
		if (ret)
			goto out;

		fprintf(stdout, "%s\n", rsp.u.add.path);
	} else if (!strcmp("unmap", command)) {
		struct ubbd_unmap_options unmap_opts = { .ubbdid = ubbdid,
			.force = force, .detach = detach};

		ret = ubbd_unmap(&unmap_opts, &rsp);
	} else if (!strcmp("config", command)) {
		struct ubbd_config_options config_opts = { .ubbdid = ubbdid,
			.data_pages_reserve_percnt = data_pages_reserve_percnt };

		ret = ubbd_config(&config_opts, &rsp);
	} else if (!strcmp("list", command)) {
		struct ubbd_list_options list_opts = {};
		int i;

		ret = ubbd_list(&list_opts, &rsp);
		if (ret)
			goto out;

		for (i = 0; i < rsp.u.list.dev_num; i++) {
			fprintf(stdout, "/dev/ubbd%d\n", rsp.u.list.dev_list[i]);
		}
	} else if (!strcmp("req-stats", command)) {
		struct ubbd_req_stats_options req_stats_opts = { .ubbdid = ubbdid };
		struct ubbd_req_stats *req_stats;
		int i;

		ret = ubbd_req_stats(&req_stats_opts, &rsp);
		if (ret)
			goto out;

		for (i = 0; i < rsp.u.req_stats.num_queues; i++) {
			req_stats = &rsp.u.req_stats.req_stats[i];
			fprintf(stdout, "Queue-%d:\n", i);
			fprintf(stdout, "\tRequests:%lu\n", req_stats->reqs);
			fprintf(stdout, "\tHandle_time:%lu\n", req_stats->reqs? req_stats->handle_time / req_stats->reqs : 0);
		}
	} else if (!strcmp("req-stats-reset", command)) {
		struct ubbd_req_stats_reset_options req_stats_reset_opts = { .ubbdid = ubbdid };

		ret = ubbd_req_stats_reset(&req_stats_reset_opts, &rsp);
	} else if (!strcmp("dev-restart", command)) {
		struct ubbd_dev_restart_options dev_restart_opts = { .ubbdid = ubbdid,
	       					.restart_mode = restart_mode};

		ret = ubbd_device_restart(&dev_restart_opts, &rsp);
	} else if (!strcmp("info", command)) {
		struct ubbd_info_options info_opts = { .ubbdid = ubbdid };

		ret = ubbd_device_info(&info_opts, &rsp);
		if (ret)
			goto out;

		ret = output_dev_info(&rsp);
	} else {
		printf("error command: %s\n", command);
	}

out:
	return ret;
}
