#ifndef CACHE_BACKEND_INTERNAL_H
#define CACHE_BACKEND_INTERNAL_H

#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "ubbd_kring.h"
#include "ubbd_backend.h"
#include "utils.h"
#include "ubbd_bitmap.h"
#include "ubbd_mempool.h"

#define CACHE_BACKEND(ubbd_b) ((struct ubbd_cache_backend *)container_of(ubbd_b, struct ubbd_cache_backend, ubbd_b))

#define USKIPLIST_MAXLEVEL		6

struct skiplist_node {
	void *next;
	pthread_mutex_t node_lock;
};

struct cache_key {
	int level:10;
	int deleted:1;
	int fullylinked:1;

	ubbd_atomic ref;

	struct skiplist_node node_list[USKIPLIST_MAXLEVEL];
	pthread_mutex_t lock;

	uint64_t	l_off;
	uint64_t	p_off;
	uint32_t	len;
	uint64_t	flags;
	uint64_t	seg_gen;
};

static inline uint64_t cache_key_lstart(struct cache_key *key)
{
	return key->l_off;
}

static inline uint64_t cache_key_lend(struct cache_key *key)
{
	return key->l_off + key->len;
}

static inline uint64_t cache_key_pstart(struct cache_key *key)
{
	return key->p_off;
}

static inline uint64_t cache_key_pend(struct cache_key *key)
{
	return key->p_off + key->len;
}

struct cache_key_ondisk {
	__u64	l_off;
	__u64	p_off;
	__u32	len;
	__u32	seq;
	__u64	seg_gen;
	__u64	flags;
};

#define CACHE_KSET_MAGIC	0x676894a6ULL

struct cache_kset_ondisk {
	__u64	csum;
	__u32	magic;
	__u16	version;
	__u16	res_1;
	__u32	key_epoch;
	__u64	flags;
	union {
		__u16	keys;
		__u64	next_seg;
	};
	__u32	kset_len;
	struct cache_key_ondisk	data[];
};


#define CACHE_KSET_FLAGS_LASTKSET	1 << 0

struct segment {
	uint8_t	type;
	uint64_t index;
	uint32_t used;
	uint32_t dirty;
	uint64_t flags;
	uint64_t gen;
	ubbd_atomic inflight;
	pthread_mutex_t lock;
};

#define CACHE_SEG_FLAGS_INVALIDATE	1 >> 0

struct seg_pos {
	uint64_t seg;
	uint32_t off_in_seg;
};

#define CACHE_KEY_WRITE_MAX	128

struct cache_key_ondisk_write_data {
	int key_used;
	bool write_pending;
	pthread_mutex_t write_lock;
	struct cache_key_ondisk keys[CACHE_KEY_WRITE_MAX];
};

struct data_head {
	struct seg_pos data_head_pos;
	pthread_mutex_t	data_head_lock;
};


#define CACHE_DATA_HEAD_MAX	32

struct cache_key_pool {
	struct ubbd_mempool *key_pool;
	ubbd_atomic seq;
};

struct cache_super {
	uint64_t	n_segs;
	uint64_t	segs_per_device;
	struct segment *segments;

	pthread_mutex_t		bitmap_lock;
	struct ubbd_bitmap	*seg_bitmap;
	uint64_t last_bit;

	struct data_head	data_heads[CACHE_DATA_HEAD_MAX];
	ubbd_atomic	data_head_index;
	struct seg_pos	key_head_pos;
	struct seg_pos	key_tail_pos;
	struct seg_pos	dirty_tail_pos;

	uint32_t last_key_epoch;

	struct cache_key_ondisk_write_data **key_ondisk_w_list;

	int num_queues;
	struct ubbd_mempool **ctx_pools;
	struct cache_key_pool *key_pools;
};

struct cache_super cache_sb;

struct cache_super_ondisk {
	__u64	csum;
	__u64	magic;
	__u64	n_segs;
	__u64	key_tail_seg;
	__u32	tail_off_in_seg;
	__u64	dirty_tail_seg;
	__u32	dirty_tail_off_in_seg;
	__u32	last_key_epoch;
};

#define CACHE_SB_OFF	4096
#define CACHE_SB_SIZE	4096

#define CACHE_SB_MAGIC		0x753358eb4f1aaULL

#define CACHE_SEG_SIZE	(4 * 1024 * 1024)
#define CACHE_SEG_SHIFT	22
#define CACHE_SEG_MASK	0x3FFFFF

#define CACHE_KSET_SIZE	8192

#define CACHE_KEY_LIST_SIZE	(4 * 1024 * 1024ULL)
#define CACHE_KEY_LIST_SHIFT	22
#define CACHE_KEY_LIST_MASK	0x3FFFFF

static inline struct segment *cache_key_seg(struct cache_key *key)
{
	return &cache_sb.segments[key->p_off >> CACHE_SEG_SHIFT];
}

static uint64_t seg_pos_to_addr(struct seg_pos *pos)
{
	return ((pos->seg << CACHE_SEG_SHIFT) + pos->off_in_seg);
}

static int new_usl_random_level(uint64_t i);
static inline struct cache_key *cache_key_alloc(int queue_id)
{
	struct cache_key_pool *c_key_pool = &cache_sb.key_pools[queue_id];
	struct ubbd_mempool *key_pool = c_key_pool->key_pool;
	struct cache_key *key;
	int ret;
	int i;

	ret = ubbd_mempool_get(key_pool, (void **)&key);
	if (ret) {
		ubbd_err("failed to alloc cache_key\n");
		return NULL;
	}

	for (i = 0; i < USKIPLIST_MAXLEVEL; i++) {
		pthread_mutex_init(&key->node_list[i].node_lock, NULL);
	}

	pthread_mutex_init(&key->lock, NULL);

	key->level = new_usl_random_level(ubbd_atomic_inc_return(&c_key_pool->seq));
	ubbd_atomic_set(&key->ref, 1);

	return key;
}

static inline void cache_key_get(struct cache_key *key)
{
	if (!key)
		return;

	ubbd_atomic_inc(&key->ref);
}

static inline void cache_key_put(struct cache_key *key)
{
	if (!ubbd_atomic_dec_and_test(&key->ref)) {
		return;
	}

	ubbd_mempool_put(key);
}


static inline bool cache_key_can_merge(struct cache_key *key_1,
		struct cache_key *key_2)
{
	return (cache_key_lend(key_1) == cache_key_lstart(key_2) &&
			cache_key_pend(key_1) == cache_key_pstart(key_2));
}

static inline void cache_key_merge(struct cache_key *key_1,
		struct cache_key *key_2)
{
	key_1->len += key_2->len;
	cache_key_put(key_2);
}

struct cache_key_ondisk;
static inline struct cache_key *cache_key_decode(struct cache_key_ondisk *key_disk)
{
	struct cache_key *key;

	key = cache_key_alloc(0);
	if (!key) {
		return NULL;
	}

	key->l_off = key_disk->l_off;
	key->p_off = key_disk->p_off;
	key->len = key_disk->len;
	key->flags = key_disk->flags;
	key->seg_gen = key_disk->seg_gen;

	return key;
}

static inline int cache_key_encode(struct cache_key *key, struct cache_key_ondisk *key_disk)
{
	key_disk->l_off = key->l_off;
	key_disk->p_off = key->p_off;
	key_disk->len = key->len;
	key_disk->flags = key->flags;
	key_disk->seg_gen = key->seg_gen;

	return 0;
}

static inline void cache_key_copy(struct cache_key *key_dst, struct cache_key *key_src)
{
	key_dst->l_off = key_src->l_off;
	key_dst->p_off = key_src->p_off;
	key_dst->len = key_src->len;
	key_dst->flags = key_src->flags;
	key_dst->seg_gen = key_src->seg_gen;
	key_dst->level = key_src->level;
}

static inline void cache_key_cutfront(struct cache_key *key, uint32_t cut_len)
{
	key->p_off += cut_len;
	key->l_off += cut_len;
	key->len -= cut_len;
}

static inline void cache_key_cutback(struct cache_key *key, uint32_t cut_len)
{
	key->len -= cut_len;
}

static inline void cache_key_delete(struct cache_key *key)
{
	key->deleted = 1;
}


/*
 * There are about 1/4 bits in random_data are 1 and others are 0, that
 * means, we can get a random about percent of 25% possibility.
 * */
static uint64_t u64_random_data[256] = {
	0x101010001       , 0x1               , 0x10100000000     , 0x101010000010001 ,
       	0x100000000000000 , 0x1               , 0x100010000000000 , 0x1000101000000   ,
	0x100000000       , 0x100000000000000 , 0x101010101000100 , 0x100010000000000 ,
	0x100000000000101 , 0x0               , 0x0               , 0x10000000100     ,
	0x100000101010000 , 0x1010100000000   , 0x1000000000000   , 0x1000100000000   ,
	0x1000000000000   , 0x101000001010000 , 0x1010001         , 0x100000101010001 ,
	0x10000000001     , 0x10000000000     , 0x0               , 0x10000           ,
	0x100             , 0x0               , 0x10000           , 0x1000000000000   ,
	0x1000001000000   , 0x1000000010100   , 0x101000000       , 0x101000000000001 ,
	0x100             , 0x1000000         , 0x10000010100     , 0x10000000000     ,
	0x0               , 0x0               , 0x10000010001     , 0x1               ,
	0x100000000010000 , 0x100010001       , 0x100000000000000 , 0x0               ,
	0x101010100000000 , 0x101000000       , 0x100000000010000 , 0x100             ,
	0x100010001000000 , 0x10000           , 0x100010001000100 , 0x10100000000     ,
	0x10001           , 0x10001000000     , 0x0               , 0x101000000000000 ,
	0x101010001       , 0x100000000000001 , 0x100010000000000 , 0x0               ,
	0x100010100       , 0x100000000010000 , 0x1000000         , 0x1               ,
	0x100000000000000 , 0x100000000010100 , 0x1000000         , 0x1000100010100   ,
	0x1000100000000   , 0x100000000       , 0x1               , 0x101000000010100 ,
	0x100000101       , 0x10000           , 0x100000001000101 , 0x1000100         ,
	0x0               , 0x101010000       , 0x10000010100     , 0x100000101       ,
	0x100000000000100 , 0x1               , 0x10001000000     , 0x1000000010000   ,
	0x100000000000001 , 0x10101           , 0x10000000001     , 0x100000000000000 ,
	0x1000000         , 0x1               , 0x10001000000     , 0x10100010101     ,
	0x1000100000000   , 0x100             , 0x101000000000000 , 0x1               ,
	0x101000001010100 , 0x10000000101     , 0x100000000       , 0x0               ,
	0x1000100         , 0x1000000         , 0x100000001       , 0x101010000000001 ,
	0x1               , 0x10100000100     , 0x100010000000000 , 0x100000000010001 ,
	0x101010000000101 , 0x10000           , 0x100000000000000 , 0x101010001       ,
	0x10001010100     , 0x1000000010000   , 0x100000101000001 , 0x1000000         ,
	0x10000000000     , 0x10101           , 0x10000000000     , 0x1               ,
	0x10000000000     , 0x1               , 0x10000000000     , 0x1000100         ,
};

static inline int new_usl_random_level(uint64_t i)
{
	int l;
	uint8_t *u8_random_data = (uint8_t *)u64_random_data;

	for (l = 1; l < USKIPLIST_MAXLEVEL; l++) {
		if (u8_random_data[i % 1024] == 1) {
			i = i * 0.618;
		} else {
			break;
		}
	}

	return l;
}

#endif /* CACHE_BACKEND_INTERNAL_H */
