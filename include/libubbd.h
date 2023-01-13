// -*- mode:C; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * ubbd - Userspace Backend Block Device
 *
 * Copyright (C) 2023 Dongsheng Yang
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#ifndef LIBUBBD_H
#define LIBUBBD_H
#include <stdint.h>
#include <limits.h>
#include <stdbool.h>
#include <fcntl.h>

/* include the ubbd kernel module header */
#include <ubbd.h>

#define UBBD_S3_LEN_MAX	1024

#define UBBD_DEV_MAX	1024
#define UBBD_QUEUE_MAX	1024

#define UBBD_POOLNAME_LEN_MAX	1024
#define UBBD_IMAGENAME_LEN_MAX	1024

#define PAGE_SIZE	4096

struct ubbd_req_stats {
	uint64_t reqs;
	uint64_t handle_time;
};

struct ubbdd_mgmt_rsp {
	/* ret must be the first member */
	int ret;
	union {
		struct {
			char path[PATH_MAX];
		} add;
		struct {
			int dev_num;
			int dev_list[UBBD_DEV_MAX];
		} list;
		struct {
			int num_queues;
			struct ubbd_req_stats req_stats[UBBD_QUEUE_MAX];
		} req_stats;
	} u;
};

typedef struct ubbd_map_options {
	char *type;
	uint64_t dev_size;
	uint32_t dev_share_memory_size;
	int num_queues;
	union {
		struct {
			char *filepath;
		} file;
		struct {
			char *pool;
			char *image;
			char *ceph_conf;
		} rbd;
		struct {
		} null;
		struct {
			char *hostname;
			char *path;
		} ssh;
		struct {
			uint32_t block_size;
			int port;
			char *hostname;
			char *accessid;
			char *accesskey;
			char *volume_name;
			char *bucket_name;
		} s3;
		struct {
			char *cache_mode;
			struct ubbd_map_options *cache_opts;
			struct ubbd_map_options *backing_opts;
		} cache;

	} u;
} ubbd_map_options;

struct ubbd_unmap_options {
	int ubbdid;
	bool force;
	bool detach;
};

struct ubbd_config_options {
	int ubbdid;
	int data_pages_reserve;
};

struct ubbd_dev_restart_options {
	int ubbdid;
	char *restart_mode;
};

struct ubbd_list_options {
};

struct ubbd_req_stats_options {
	int ubbdid;
};

struct ubbd_req_stats_reset_options {
	int ubbdid;
};

int ubbd_map(struct ubbd_map_options *opts, struct ubbdd_mgmt_rsp *rsp);
int ubbd_unmap(struct ubbd_unmap_options *opts, struct ubbdd_mgmt_rsp *rsp);
int ubbd_config(struct ubbd_config_options *opts, struct ubbdd_mgmt_rsp *rsp);
int ubbd_list(struct ubbd_list_options *opts, struct ubbdd_mgmt_rsp *rsp);
int ubbd_req_stats(struct ubbd_req_stats_options *opts, struct ubbdd_mgmt_rsp *rsp);
int ubbd_req_stats_reset(struct ubbd_req_stats_reset_options *opts, struct ubbdd_mgmt_rsp *rsp);
int ubbd_device_restart(struct ubbd_dev_restart_options *opts, struct ubbdd_mgmt_rsp *rsp);
#endif /*LIBUBBD_H*/
