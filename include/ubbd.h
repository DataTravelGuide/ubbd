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
#define UBBD_INFO_SIZE (4096)
#define COMPR_OFF (UBBD_INFO_OFF + UBBD_INFO_SIZE)
#define COMPR_SIZE (sizeof(struct ubbd_ce) * 1024)
#define CMDR_OFF (COMPR_OFF + COMPR_SIZE)
#define CMDR_SIZE (RING_SIZE - CMDR_OFF)

#define UBBD_MAGIC	0x676896C596EF

struct ubbd_sb {
	__u8  magic[8];
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

#define UBBD_OP_ALIGN_SIZE sizeof(__u64)

enum ubbd_genl_cmd {
	UBBD_CMD_ADD_PREPARE,
	UBBD_CMD_ADD,
	UBBD_CMD_REMOVE_PREPARE,
	UBBD_CMD_REMOVE,
	UBBD_CMD_STATUS,
	__UBBD_CMD_MAX,
};
#define UBBD_CMD_MAX (__UBBD_CMD_MAX - 1)

enum ubbd_genl_attr {
	UBBD_ATTR_PAD,
	UBBD_ATTR_DEV_SIZE,
	UBBD_ATTR_DEV_ID,
	UBBD_ATTR_UIO_ID,
	UBBD_ATTR_UIO_MAP_SIZE,
	UBBD_ATTR_PRIV_DATA,
	UBBD_ATTR_DEV_LIST,
	UBBD_ATTR_FLAGS,
	UBBD_ATTR_RETVAL,
	UBBD_ATTR_DATA_PAGES,
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
 * 	[UBBD_STATUS_ITEM]
 * 		[UBBD_STATUS_DEV_ID]
 * 		[UBBD_STATUS_UIO_ID]
 * 		[UBBD_STATUS_STATUS]
 * 	[UBBD_STATUS_ITEM]
 * 		[UBBD_STATUS_DEV_ID]
 * 		[UBBD_STATUS_UIO_ID]
 * 		[UBBD_STATUS_STATUS]
 */
enum {
	UBBD_STATUS_ITEM,
	__UBBD_STATUS_ITEM_MAX,
};
#define UBBD_STATUS_ITEM_MAX (__UBBD_STATUS_ITEM_MAX - 1)

enum {
	UBBD_STATUS_DEV_ID,
	UBBD_STATUS_UIO_ID,
	UBBD_STATUS_UIO_MAP_SIZE,
	UBBD_STATUS_STATUS,
	__UBBD_STATUS_MAX,
};
#define UBBD_STATUS_ATTR_MAX (__UBBD_STATUS_MAX - 1)

#endif
