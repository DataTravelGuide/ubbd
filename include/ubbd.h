#ifndef __USER_BLOCKE_DEVICE_H
#define __USER_BLOCKE_DEVICE_H

/* This header will be used by application too */

#include <linux/types.h>

#define UBBD_VERSION "1.0"

#define UBBD_SB_VERSION 1
#define ALIGN_SIZE sizeof(__u64)

#define RING_SIZE (1024 * 4096)
#define CMDR_RESERVED ALIGN_SIZE
#define CMPR_RESERVED sizeof(struct ubbd_ce)
/* Offset of cmd ring is size of sb */

#define UBBD_INFO_OFF (sizeof(struct ubbd_sb))
#define UBBD_INFO_SIZE (4096 * 8)
#define COMPR_OFF (UBBD_INFO_OFF + UBBD_INFO_SIZE)
#define COMPR_SIZE (sizeof(struct ubbd_ce) * 1024)
#define CMDR_OFF (COMPR_OFF + COMPR_SIZE)
#define CMDR_SIZE (RING_SIZE - CMDR_OFF)

#define UBBD_MAGIC	0x676896C596EFULL

#define UBBD_REQUEST_STATS

struct ubbd_sb {
	__u64  magic;
	__u16 version;
	__u16 flags;

	__u32 info_off;
	__u32 info_size;

	__u32 cmdr_off;
	__u32 cmdr_size;
	__u32 cmd_head;
	__u32 cmd_tail;

	__u32 compr_head;
	__u32 compr_tail;
	__u32 compr_off;
	__u32 compr_size;

} __attribute__((packed)) __attribute__((__aligned__(ALIGN_SIZE)));


enum ubbd_op {
	UBBD_OP_PAD = 0,
	UBBD_OP_WRITE,
	UBBD_OP_READ,
	UBBD_OP_DISCARD,
	UBBD_OP_WRITE_ZEROS,
	UBBD_OP_FLUSH,
};

struct ubbd_se_hdr {
	__u32 len_op;
	__u32 flags;

} __attribute__((packed));

struct ubbd_se {
	struct ubbd_se_hdr	header;
	__u64			priv_data;	// pointer to ubbd_request

	__u64			offset;
	__u32			len;
	__u32			iov_cnt;
	struct iovec		iov[0];
};


struct ubbd_ce {
	__u64		priv_data;	// copied from submit entry
	__s32		result;
	__u32		flags;
};


#define UBBD_OP_MASK 0xff
#define UBBD_OP_SHIFT 8

static inline enum ubbd_op ubbd_se_hdr_get_op(__u32 len_op)
{
       return len_op & UBBD_OP_MASK;
}

static inline void ubbd_se_hdr_set_op(__u32 *len_op, enum ubbd_op op)
{
       *len_op &= ~UBBD_OP_MASK;
       *len_op |= (op & UBBD_OP_MASK);
}

static inline __u32 ubbd_se_hdr_get_len(__u32 len_op)
{
	return len_op >> UBBD_OP_SHIFT;
}

static inline void ubbd_se_hdr_set_len(__u32 *len_op, __u32 len)
{
	*len_op &= UBBD_OP_MASK;
	*len_op |= (len << UBBD_OP_SHIFT);
}

#define UBBD_SE_HDR_DONE	1

static inline bool ubbd_se_hdr_flags_test(struct ubbd_se *se, __u32 bit)
{
	return (se->header.flags & bit);
}

static inline void ubbd_se_hdr_flags_set(struct ubbd_se *se, __u32 bit)
{
	se->header.flags |= bit;
}

#define UBBD_OP_ALIGN_SIZE sizeof(__u64)

enum ubbd_genl_cmd {
	UBBD_CMD_ADD_DEV,
	UBBD_CMD_ADD_DISK,
	UBBD_CMD_REMOVE_DEV,
	UBBD_CMD_REMOVE_DISK,
	UBBD_CMD_STATUS,
	UBBD_CMD_CONFIG,
	UBBD_CMD_QUEUE_OP,
	UBBD_CMD_LIST,
	__UBBD_CMD_MAX,
};
#define UBBD_CMD_MAX (__UBBD_CMD_MAX - 1)

/* queue op */
#define UBBD_ATTR_FLAGS_QUEUE_OP_STOP	1 << 0
#define UBBD_ATTR_FLAGS_QUEUE_OP_START	2 << 0

enum ubbd_genl_attr {
	UBBD_ATTR_PAD,
	UBBD_ATTR_DEV_ID,
	UBBD_ATTR_DEV_OPTS,
	UBBD_ATTR_DEV_INFO,
	UBBD_ATTR_DEV_LIST,
	UBBD_ATTR_FLAGS,
	UBBD_ATTR_RETVAL,
	UBBD_ATTR_QUEUE_ID,
	__UBBD_ATTR_MAX,
};

/*
 * remove related flags
 */
#define UBBD_ATTR_FLAGS_REMOVE_FORCE	1 << 0

/*
 * add related flags
 */
#define UBBD_ATTR_FLAGS_ADD_WRITECACHE	1 << 0
#define UBBD_ATTR_FLAGS_ADD_FUA		1 << 1
#define UBBD_ATTR_FLAGS_ADD_DISCARD	1 << 2
#define UBBD_ATTR_FLAGS_ADD_WRITE_ZEROS	1 << 3

#define UBBD_ATTR_MAX (__UBBD_ATTR_MAX - 1)

/*
 * Format of nested UBBD_ATTR_DEV_LIST
 *
 * [UBBD_ATTR_DEV_LIST]
 * 	[UBBD_LIST_DEV_ID]
 * 		...
 * 	[UBBD_LIST_DEV_ID]
 * 		...
 */
enum {
	UBBD_LIST_DEV_ID,
	__UBBD_LIST_MAX,
};
#define UBBD_LIST_MAX (__UBBD_LIST_MAX - 1)

/*
 * Fromat of nested UBBD_ATTR_DEV_INFO
 * [UBBD_ATTR_DEV_INFO]
 * 	[UBBD_STATUS_DEV_ID]
 * 	[UBBD_STATUS_QUEUE_INFO]
 * 		[UBBD_QUEUE_INFO_ITEM]
 * 			[UBBD_QUEUE_INFO_UIO_ID]
 * 			[UBBD_QUEUE_INFO_UIO_MAP_SIZE]
 * 			[UBBD_QUEUE_INFO_CPU_LIST]
 *				[UBBD_QUEUE_INFO_CPU_ID]
 *				[UBBD_QUEUE_INFO_CPU_ID]
 *				[UBBD_QUEUE_INFO_CPU_ID]
 * 		[UBBD_QUEUE_INFO_ITEM]
 * 			[UBBD_QUEUE_INFO_UIO_ID]
 * 			[UBBD_QUEUE_INFO_UIO_MAP_SIZE]
 * 			[UBBD_QUEUE_INFO_CPU_LIST]
 * 				[UBBD_QUEUE_INFO_CPU_ID]
 * 	[UBBD_STATUS_STATUS]
 */
enum {
	UBBD_STATUS_DEV_ID,
	UBBD_STATUS_QUEUE_INFO,
	UBBD_STATUS_STATUS,
	__UBBD_STATUS_MAX,
};
#define UBBD_STATUS_ATTR_MAX (__UBBD_STATUS_MAX - 1)

enum {
	UBBD_QUEUE_INFO_ITEM,
	__UBBD_QUEUE_INFO_ITEM_MAX,
};
#define UBBD_QUEUE_INFO_ITEM_MAX (__UBBD_QUEUE_INFO_ITEM_MAX - 1)

enum {
	UBBD_QUEUE_INFO_CPU_ID,
	__UBBD_QUEUE_INFO_CPU_MAX,
};
#define UBBD_QUEUE_INFO_CPU_MAX (__UBBD_QUEUE_INFO_CPU_MAX - 1)

enum {
	UBBD_QUEUE_INFO_UIO_ID,
	UBBD_QUEUE_INFO_UIO_MAP_SIZE,
	UBBD_QUEUE_INFO_CPU_LIST,
	UBBD_QUEUE_INFO_B_PID,
	UBBD_QUEUE_INFO_STATUS,
	__UBBD_QUEUE_INFO_MAX,
};
#define UBBD_QUEUE_INFO_ATTR_MAX (__UBBD_QUEUE_INFO_MAX - 1)

/*
                             +-----+
                             |start|
                             +--+--+
                                |
                                |
+-------------------------------+------------------------------------------------------------------------------------+
|                               |                                                                                    |
|                   +-----------v-------------+                                                                      |
|                   | UBBD_QUEUE_KSTATUS_INIT |                                                                      |
|                   +-----------+-------------+                                                                      |
|                               |                                                                                    |
|                               |                                                                                    |
|                   +-----------v---------------+                            +------------------------------+        |
|                   | UBBD_QUEUE_KSTATUS_RUNNING+--------stop_queue----------+  UBBD_QUEUE_KSTATUS_STOPPING |        |
|                   +-----------^---------------+                            +---------------+--------------+        |
|                               |                                                            |                       |
|                               |                                                            |                       |
|                               |                                                         inf|ight done              |
|                               |                                                            |                       |
|                               |                                                            |                       |
|                               |                                                            |                       |
|                               |                                            +---------------v--------------+        |
|                               +------------start_queue---------------------+  UBBD_QUEUE_KSTATUS_STOPPED  |        |
|                                                                            +------------------------------+        |
|                                                                                                                    |
+--------------------------------+-----------------------------------------------------------------------------------+
                                 |
                                 |
                                 |
                                 |
                              remove
                                 |
                                 |
                                 |
                 +---------------v--------------+
                 |  UBBD_QUEUE_KSTATUS_REMOVING |
                 +---------------+--------------+
                                 |
                                 |
                              +--v--+
                              |done |
                              +-----+
*/

enum ubbd_queue_kstatus {
	UBBD_QUEUE_KSTATUS_INIT = 0,
	UBBD_QUEUE_KSTATUS_RUNNING,
	UBBD_QUEUE_KSTATUS_STOPPING,
	UBBD_QUEUE_KSTATUS_STOPPED,
	UBBD_QUEUE_KSTATUS_REMOVING,
};

/*
                      +-----+
                      |start|
                      +--+--+
                         |
                      create
                         |
               +---------v------------+
               |UBBD_DEV_KSTATUS_INIT |
               +---------+------------+
                         |
                      add_dev
                         |
             +-----------v---------------+                +---------------------------+
    +--------+UBBD_DEV_KSTATUS_PREPARED  +----add_disk---->UBBD_DEV_KSTATUS_RUNNING   |
    |        +-----------+---------------+                +---------------+-----------+
    |                    |                                                |
    |                    |                                                |
    |                 remove_disk                                         |
    |                    |                                                |
    |                    |                                                |
remove_dev   +-----------v---------------+                                |
    |        |UBBD_DEV_KSTATUS_REMOVING  <--------------------remove_disk-+
    |        +-----------+---------------+
    |                    |
    |                    |
    |                  remove_dev
    |                    |
    |                 +--v---+
    +-----------------> end  |
                      +------+
*/

enum ubbd_dev_kstatus {
	UBBD_DEV_KSTATUS_INIT = 0,
	UBBD_DEV_KSTATUS_PREPARED,
	UBBD_DEV_KSTATUS_RUNNING,
	UBBD_DEV_KSTATUS_REMOVING,
};

/*
 * Format of nested UBBD_ATTR_DEV_OPTS
 *
 * [UBBD_ATTR_DEV_OPTS]
 * 	[UBBD_DEV_OPTS_DP_RESERVE]
 *	[UBBD_DEV_OPTS_DATA_PAGES]
 *	[UBBD_DEV_OPTS_DEV_SIZE]
 *	...
 */
enum {
	UBBD_DEV_OPTS_DP_RESERVE,
	UBBD_DEV_OPTS_DATA_PAGES,
	UBBD_DEV_OPTS_DEV_SIZE,
	UBBD_DEV_OPTS_DEV_QUEUES,
	__UBBD_DEV_OPTS_MAX,
};
#define UBBD_DEV_OPTS_MAX (__UBBD_DEV_OPTS_MAX - 1)

#endif
