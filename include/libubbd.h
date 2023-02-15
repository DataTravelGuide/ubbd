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

#define UBBD_NAME_MAX	255
#define UBBD_PATH_MAX	1024

#define UBBD_DEV_MAX	1024
#define UBBD_QUEUE_MAX	1024

#define PAGE_SIZE	4096

#define COMPILE_ASSERT(predicate, name) _impl_COMPILE_ASSERT_LINE(predicate,__LINE__, name)

#define _impl_PASTE(a,b) a##b
#define _impl_COMPILE_ASSERT_LINE(predicate, line, file) \
	    typedef char _impl_PASTE(assertion_failed_##file##_,line)[2*!!(predicate)-1];

enum ubbd_dev_type {
	UBBD_DEV_TYPE_FILE,
	UBBD_DEV_TYPE_RBD,
	UBBD_DEV_TYPE_NULL,
	UBBD_DEV_TYPE_SSH,
	UBBD_DEV_TYPE_CACHE,
	UBBD_DEV_TYPE_S3,
	UBBD_DEV_TYPE_MAX,
};


#define UBBD_DEV_INFO_RBD_FLAGS_SNAP	1 << 0	/* map snapshot of rbd image */

struct __dev_info {
	enum ubbd_dev_type type;
	uint64_t size;
	uint32_t io_timeout;
	union {
		struct {
			char path[UBBD_PATH_MAX];
		} file;
		struct {
			uint64_t  flags;
			char pool[UBBD_NAME_MAX];
			char ns[UBBD_NAME_MAX];
			char image[UBBD_NAME_MAX];
			char snap[UBBD_NAME_MAX];
			char ceph_conf[UBBD_NAME_MAX];
			char cluster_name[UBBD_NAME_MAX];
			char user_name[UBBD_NAME_MAX];
		} rbd;
		struct {
		} null;
		struct {
			char hostname[UBBD_NAME_MAX];
			char path[UBBD_PATH_MAX];
		} ssh;
		struct {
			uint32_t block_size;
			int port;
			char hostname[UBBD_NAME_MAX];
			char accessid[UBBD_NAME_MAX];
			char accesskey[UBBD_NAME_MAX];
			char volume_name[UBBD_NAME_MAX];
			char bucket_name[UBBD_NAME_MAX];
		} s3;
	};
};

struct ubbd_dev_info {
	enum ubbd_dev_type type;
	uint32_t num_queues;
	uint32_t sh_mem_size;
	bool read_only;
	union {
		struct {
			struct __dev_info info;
		} generic_dev;
		struct {
			int cache_mode;
			struct __dev_info backing_info;
			struct __dev_info cache_info;
		} cache_dev;
	};
};

COMPILE_ASSERT(sizeof(struct ubbd_dev_info) < UBBD_INFO_SIZE, ubbd_dev_info_too_large);

struct ubbd_req_stats {
	uint64_t reqs;
	uint64_t handle_time;
};

struct ubbdd_mgmt_rsp_dev_info {
	int devid;
	struct ubbd_dev_info dev_info;
};

struct ubbdd_mgmt_rsp {
	/* ret must be the first member */
	int ret;
	union {
		struct {
			char path[UBBD_PATH_MAX];
		} add;
		struct {
			int dev_num;
			int dev_list[UBBD_DEV_MAX];
		} list;
		struct {
			int num_queues;
			struct ubbd_req_stats req_stats[UBBD_QUEUE_MAX];
		} req_stats;
		struct ubbdd_mgmt_rsp_dev_info dev_info;
	};
};

struct __ubbd_map_opts {
	const char *type;
	uint64_t dev_size;
	uint32_t io_timeout;
	union {
		struct {
			const char *filepath;
		} file;
		struct {
			const char *pool;
			const char *ns;
			const char *image;
			const char *snap;
			const char *ceph_conf;
			const char *cluster_name;
			const char *user_name;
		} rbd;
		struct {
		} null;
		struct {
			const char *hostname;
			const char *path;
		} ssh;
		struct {
			uint32_t block_size;
			int port;
			const char *hostname;
			const char *accessid;
			const char *accesskey;
			const char *volume_name;
			const char *bucket_name;
		} s3;

	};
};

struct ubbd_map_options {
	const char *type;
	int num_queues;
	uint32_t dev_share_memory_size;
	bool read_only;
	union {
		struct {
			struct __ubbd_map_opts opts;
		} generic_dev;

		struct {
			const char *cache_mode;
			struct __ubbd_map_opts cache_opts; 
			struct __ubbd_map_opts backing_opts; 
		} cache_dev;
	};
};

struct ubbd_unmap_options {
	int ubbdid;
	bool force;
	bool detach;
};

struct ubbd_config_options {
	int ubbdid;
	int data_pages_reserve_percnt;
};

struct ubbd_dev_restart_options {
	int ubbdid;
	const char *restart_mode;
};

struct ubbd_list_options {
};

struct ubbd_req_stats_options {
	int ubbdid;
};

struct ubbd_req_stats_reset_options {
	int ubbdid;
};

struct ubbd_info_options {
	int ubbdid;
};

const char* cache_mode_to_str(int cache_mode);

int ubbd_map(struct ubbd_map_options *opts, struct ubbdd_mgmt_rsp *rsp);
int ubbd_unmap(struct ubbd_unmap_options *opts, struct ubbdd_mgmt_rsp *rsp);
int ubbd_config(struct ubbd_config_options *opts, struct ubbdd_mgmt_rsp *rsp);
int ubbd_list(struct ubbd_list_options *opts, struct ubbdd_mgmt_rsp *rsp);
int ubbd_req_stats(struct ubbd_req_stats_options *opts, struct ubbdd_mgmt_rsp *rsp);
int ubbd_req_stats_reset(struct ubbd_req_stats_reset_options *opts, struct ubbdd_mgmt_rsp *rsp);
int ubbd_device_restart(struct ubbd_dev_restart_options *opts, struct ubbdd_mgmt_rsp *rsp);
int ubbd_device_info(struct ubbd_info_options *opts, struct ubbdd_mgmt_rsp *rsp);
#endif /*LIBUBBD_H*/
