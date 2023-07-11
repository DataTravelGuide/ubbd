#define _GNU_SOURCE
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "ubbd_uio.h"
#include "ubbd_backend.h"
#include "utils.h"
#include "ubbd_bitmap.h"

#define CACHE_BACKEND(ubbd_b) ((struct ubbd_cache_backend *)container_of(ubbd_b, struct ubbd_cache_backend, ubbd_b))
#define USKIPLIST_MAXLEVEL		10

struct ubbd_skiplist_head {
	struct list_head nodes[USKIPLIST_MAXLEVEL];
	int level;
};

struct ubbd_skiplist {
	struct ubbd_skiplist_head cache_key_list;
	pthread_mutex_t cache_key_list_mutex;
};

static struct ubbd_skiplist *cache_key_lists;
static uint64_t cache_key_list_num;
pthread_mutex_t cache_io_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t cache_disk_append_mutex = PTHREAD_MUTEX_INITIALIZER;

struct ubbd_backend *cache_backend;
struct ubbd_backend *backing_backend;

static bool verify = false;
static int verify_fd;
#define CACHE_VERIFY_PATH	""

static bool writearound = false;

static int lcache_debug = 0;

struct cache_key {
	struct ubbd_skiplist_head key_node;
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

static inline bool cache_key_can_merge(struct cache_key *key_1,
		struct cache_key *key_2)
{
	return (cache_key_lend(key_1) == cache_key_lstart(key_2) &&
			cache_key_pend(key_1) == cache_key_pstart(key_2));
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

static struct cache_super cache_sb;

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

struct cache_key_ondisk_write {
	struct cache_key_ondisk keys[CACHE_KEY_WRITE_MAX];
	int key_used;
};

struct data_head {
	struct seg_pos data_head_pos;
	pthread_mutex_t	data_head_lock;
};


#define CACHE_DATA_HEAD_MAX	32

struct cache_super {
	uint64_t	n_segs;
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

	struct cache_key_ondisk_write *key_ondisk_w;
};

static void dump_bitmap(struct ubbd_bitmap *bitmap)
{
	int i = 0;

	return;

	ubbd_err("bitmap weight: %lu\n", ubbd_bitmap_weight(bitmap));
	for (i = 0; i < bitmap->size; i++) {
		if (ubbd_bit_test(bitmap, i)) {
			ubbd_err(" %d\n", i);
		}
	}
	ubbd_err("\n");
}

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

static char sb_buf[4096] __attribute__ ((__aligned__ (4096)));

#define CACHE_SB_OFF	4096
#define CACHE_SB_SIZE	4096

#define CACHE_SB_MAGIC		0x753358eb4f1aaULL

#define CACHE_SEG_SIZE	(4 * 1024 * 1024)
#define CACHE_SEG_SHIFT	22
#define CACHE_SEG_MASK	0x3FFFFF

#define CACHE_KSET_SIZE	8192

#define CACHE_KEY_LIST_SIZE	(8 * 1024 * 1024ULL)
#define CACHE_KEY_LIST_SHIFT	23
#define CACHE_KEY_LIST_MASK	0x7FFFFF

static char seg_buf[CACHE_SEG_SIZE] __attribute__ ((__aligned__ (4096)));

static inline struct segment *cache_key_seg(struct cache_key *key)
{
	return &cache_sb.segments[key->p_off >> CACHE_SEG_SHIFT];
}

static void ubbd_skiplist_init(struct ubbd_skiplist_head *skiplist_node)
{
	int i;

	for (i = 0; i < USKIPLIST_MAXLEVEL; i++) {
		INIT_LIST_HEAD(&skiplist_node->nodes[i]);
	}

	return;
}

static void ubbd_skiplist_delete(struct ubbd_skiplist_head *skiplist_node)
{
	int i;

	for (i = 0; i < USKIPLIST_MAXLEVEL; i++) {
		list_del_init(&skiplist_node->nodes[i]);
	}

	return;
}

static struct cache_key *cache_key_alloc()
{
	struct cache_key *key;

	key = calloc(1, sizeof(struct cache_key));
	if (!key) {
		ubbd_err("failed to alloc cache_key\n");
		return NULL;
	}

	ubbd_skiplist_init(&key->key_node);

	return key;
}

static struct cache_key *cache_key_decode(struct cache_key_ondisk *key_disk)
{
	struct cache_key *key;

	key = cache_key_alloc();
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

static int cache_key_encode(struct cache_key *key, struct cache_key_ondisk *key_disk)
{
	key_disk->l_off = key->l_off;
	key_disk->p_off = key->p_off;
	key_disk->len = key->len;
	key_disk->flags = key->flags;
	key_disk->seg_gen = key->seg_gen;

	return 0;
}


static void cache_key_merge(struct cache_key *key_1,
		struct cache_key *key_2)
{
	BUG_ON(!list_empty(&key_2->key_node.nodes[0]), "key_2 should be not in list\n");
	key_1->len += key_2->len;
	free(key_2);
}

static void cache_key_copy(struct cache_key *key_dst, struct cache_key *key_src)
{
	key_dst->l_off = key_src->l_off;
	key_dst->p_off = key_src->p_off;
	key_dst->len = key_src->len;
	key_dst->flags = key_src->flags;
	key_dst->seg_gen = key_src->seg_gen;
	key_dst->key_node.level = key_src->key_node.level;
}

static void cache_key_cutfront(struct cache_key *key, uint32_t cut_len)
{
	key->p_off += cut_len;
	key->l_off += cut_len;
	key->len -= cut_len;
}

static void cache_key_cutback(struct cache_key *key, uint32_t cut_len)
{
	key->len -= cut_len;
}

static void cache_key_delete(struct cache_key *key)
{
	if (lcache_debug) {
		ubbd_err("delete cache_key: key->seg_gen: %lu, seg->gen: %lu.\n", key->seg_gen, cache_key_seg(key)->gen);
		ubbd_err("free key: %p\n", key);
	}

	ubbd_skiplist_delete(&key->key_node);
	free(key);
}

static void cache_seg_invalidate(uint64_t index)
{
	int ret = 0;

	cache_sb.segments[index].gen++;

	ubbd_err("yds gc seg: %lu\n", index);

	if (0)
		ret = ubbd_backend_write(cache_backend, index << CACHE_SEG_SHIFT, CACHE_SEG_SIZE, seg_buf);
	else
		ret = 0;

	if (ret) {
		ubbd_err("failed to write zero to gc seg\n");
	}

	pthread_mutex_lock(&cache_sb.bitmap_lock);
	ubbd_bit_clear(cache_sb.seg_bitmap, index);
	dump_bitmap(cache_sb.seg_bitmap);
	pthread_mutex_unlock(&cache_sb.bitmap_lock);
}

static void cache_seg_get(uint64_t index)
{
	if (lcache_debug)
		ubbd_err("seg: %lu inflight: %d\n", index, ubbd_atomic_read(&cache_sb.segments[index].inflight));

	ubbd_atomic_inc(&cache_sb.segments[index].inflight);
}

static void cache_seg_put(uint64_t index)
{
	if (lcache_debug)
		ubbd_err("seg %lu inflight: %d\n", index, ubbd_atomic_read(&cache_sb.segments[index].inflight));

	ubbd_atomic_dec(&cache_sb.segments[index].inflight);
}


static uint64_t seg_pos_to_addr(struct seg_pos *pos);
static int cache_sb_write(void);
static int cache_key_ondisk_write(void)
{
	static char kset_buf[CACHE_KSET_SIZE] __attribute__ ((__aligned__ (4096))) = { 0 };
	struct cache_kset_ondisk *kset = (struct cache_kset_ondisk *)kset_buf;
	uint64_t addr, space_required;
	uint64_t next_seg;
	int ret;

	if (!cache_sb.key_ondisk_w->key_used)
		return 0;

	if (lcache_debug)
		ubbd_err("key_used: %d\n", cache_sb.key_ondisk_w->key_used);
again:
	addr = seg_pos_to_addr(&cache_sb.key_head_pos);
	memset(kset_buf, 0, CACHE_KSET_SIZE);

	space_required = sizeof(struct cache_kset_ondisk) +
		cache_sb.key_ondisk_w->key_used * sizeof(struct cache_key_ondisk);

	if (lcache_debug)
		ubbd_err("space_required: %lu, key_used: %u\n", space_required, cache_sb.key_ondisk_w->key_used);

	space_required = ubbd_roundup(space_required, 4096);

	/* reserve 4096 for each segment for last kset */
	if (CACHE_SEG_SIZE - cache_sb.key_head_pos.off_in_seg - 4096 < space_required) {
		/* there is no enough free space */
		kset->magic = CACHE_KSET_MAGIC;
		kset->version = 0;
		kset->kset_len = 4096;
		kset->key_epoch = cache_sb.last_key_epoch;
		kset->flags |= CACHE_KSET_FLAGS_LASTKSET;
		pthread_mutex_lock(&cache_sb.bitmap_lock);
		ret = ubbd_bit_find_next_zero(cache_sb.seg_bitmap, random() % cache_sb.n_segs, &next_seg);
		if (ret) {
			pthread_mutex_unlock(&cache_sb.bitmap_lock);
			ubbd_err("cant find segment for data\n");
			return ret;
		}
		cache_sb.last_bit = next_seg;
		kset->next_seg = next_seg;
		ubbd_bit_set(cache_sb.seg_bitmap, next_seg);
		pthread_mutex_unlock(&cache_sb.bitmap_lock);

		dump_bitmap(cache_sb.seg_bitmap);
		ret = ubbd_backend_write(cache_backend, addr, 4096, kset_buf);
		if (ret) {
			ubbd_err("failed to write last kset\n");
			return ret;
		}
		cache_sb.key_head_pos.seg = next_seg;
		cache_sb.key_head_pos.off_in_seg = 0;;
		cache_sb.last_key_epoch++;
		if (lcache_debug)
			ubbd_err("new key seg: %lu, epoch: %u\n", next_seg, cache_sb.last_key_epoch);

		cache_sb_write();
		goto again;
	}

	kset->magic = CACHE_KSET_MAGIC;
	kset->version = 0;
	kset->keys = cache_sb.key_ondisk_w->key_used;
	kset->kset_len = space_required;
	kset->key_epoch = cache_sb.last_key_epoch;
	memcpy(kset->data, cache_sb.key_ondisk_w->keys, sizeof(struct cache_key_ondisk) * cache_sb.key_ondisk_w->key_used);

	if (lcache_debug)
		ubbd_err("write normal kset: %lu\n", addr);

	ret = ubbd_backend_write(cache_backend, addr, CACHE_KSET_SIZE, kset_buf);
	if (ret) {
		ubbd_err("failed to write normal kset\n");
		return ret;
	}
	cache_sb.key_head_pos.off_in_seg += space_required;
	cache_sb.key_ondisk_w->key_used = 0;

	return 0;
}

static int cache_key_ondisk_append(struct cache_key *key)
{
	int ret;

	pthread_mutex_lock(&cache_disk_append_mutex);
	cache_key_encode(key, &cache_sb.key_ondisk_w->keys[cache_sb.key_ondisk_w->key_used++]);
	if (cache_sb.key_ondisk_w->key_used >= CACHE_KEY_WRITE_MAX) {
		ret = cache_key_ondisk_write();
		if (ret) {
			ubbd_err("failed to write ondisk key.\n");
			goto out;
		}
	}
	ret = 0;

out:
	pthread_mutex_unlock(&cache_disk_append_mutex);

	return ret;
}

static void cache_key_list_release(struct ubbd_skiplist *skiplist)
{
	struct cache_key *key_tmp, *next;
	int l;

	pthread_mutex_lock(&skiplist->cache_key_list_mutex);
	for (l = 0; l >= 0; l--) {
		list_for_each_entry_safe(key_tmp, next, &skiplist->cache_key_list.nodes[l], key_node.nodes[l]) {
			cache_key_delete(key_tmp);
		}
	}
	pthread_mutex_unlock(&skiplist->cache_key_list_mutex);
}

static void cache_key_lists_release()
{
	int i;

	for (i = 0; i < cache_key_list_num; i++) {
		cache_key_list_release(&cache_key_lists[i]);
	}

	free(cache_key_lists);
}

static void __cache_key_list_dump(struct ubbd_skiplist_head *cache_key_list, int index)
{
	struct cache_key *key_tmp;
	int l;
	uint64_t crc = 0;

	for (l = 0; l >= 0; l--) {
		list_for_each_entry(key_tmp, &cache_key_list->nodes[l], key_node.nodes[l]) {
			ubbd_err("skiplist: %p index: %d, l_off: %lu, p_off: %lu, len: %u, gen: %lu.\n", cache_key_list, index,  key_tmp->l_off, key_tmp->p_off, key_tmp->len, key_tmp->seg_gen);
			crc += (key_tmp->l_off + key_tmp->p_off + key_tmp->len);
		}
	}
	if (crc) {
		ubbd_err("crc: %lx\n", crc);
	}
}

static void cache_key_list_dump()
{
	int i;

	return;
	for (i = 0; i < cache_key_list_num; i++) {
		struct ubbd_skiplist *skiplist = &cache_key_lists[i];

		pthread_mutex_lock(&skiplist->cache_key_list_mutex);
		__cache_key_list_dump(&skiplist->cache_key_list, i);
		pthread_mutex_unlock(&skiplist->cache_key_list_mutex);
	}
}

#define USKIPLIST_P	0.25

static int usl_random_level(void) {
    int level = 1;

    while ((random()&0xFFFF) < (USKIPLIST_P * 0xFFFF))
        level += 1;

    return (level < USKIPLIST_MAXLEVEL) ? level : USKIPLIST_MAXLEVEL;
}

static void seg_used_add(struct cache_key *key);
static int cache_key_insert(struct cache_key *key)
{
	struct ubbd_skiplist_head *sl_node_tmp, *sl_node_next;
	struct cache_key *key_tmp, *next;
	struct list_head *prev_key_node;
	struct cache_key *prev_key = NULL;
	struct cache_key *key_fixup;
	struct list_head *head;
	struct list_head *update_nodes[USKIPLIST_MAXLEVEL];
	int l;
	int ret = 0;
	uint64_t start_time = get_ns();
	struct ubbd_skiplist *skiplist = &cache_key_lists[key->l_off >> CACHE_KEY_LIST_SHIFT];

	seg_used_add(key);
	if ((key->l_off & CACHE_KEY_LIST_MASK) + key->len > CACHE_KEY_LIST_SIZE)
		ubbd_err("insert l_off: %lu, p_off: %lu, len: %u.\n", key->l_off, key->p_off, key->len);

	pthread_mutex_lock(&skiplist->cache_key_list_mutex);
	for (l = USKIPLIST_MAXLEVEL - 1; l >= 0; l--) {
		if (prev_key) {
			prev_key_node = &prev_key->key_node.nodes[l];
			head = prev_key_node->prev;
		} else {
			head = prev_key_node = &skiplist->cache_key_list.nodes[l];
		}

		list_for_each_entry_range_safe(key_tmp, next, head, &skiplist->cache_key_list.nodes[l], key_node.nodes[l]) {
			if (key_tmp->seg_gen < cache_key_seg(key_tmp)->gen) {
				cache_key_delete(key_tmp);
				continue;
			}

			if (cache_key_lstart(key_tmp) < cache_key_lstart(key)) {
				prev_key_node = &key_tmp->key_node.nodes[l];
				prev_key = key_tmp;
				continue;
			}
			break;
		}
		update_nodes[l] = prev_key_node;
	}

	if (prev_key) {
		head = update_nodes[0]->prev;
	} else {
		head = &skiplist->cache_key_list.nodes[0];
	}

	if (lcache_debug)
		ubbd_err("search time: %lu\n", get_ns() - start_time);

	/*fix the overlap up*/
	list_for_each_entry_range_safe(sl_node_tmp, sl_node_next, head, &skiplist->cache_key_list.nodes[0], nodes[0]) {
		key_tmp = ubbd_container_of(sl_node_tmp, struct cache_key, key_node);
		/*
		 * |----------|
		 *		|=====|
		 * */
		if (cache_key_lend(key_tmp) <= cache_key_lstart(key)) {
			continue;
		}

		/*
		 *	  |--------|
		 * |====|
		 */
		if (cache_key_lstart(key_tmp) >= cache_key_lend(key)) {
			break;
		}

		/* overlap */
		if (cache_key_lstart(key_tmp) >= cache_key_lstart(key)) {
			/*
			 *     |----------------|	key_tmp
			 * |===========|		key
			 */
			if (cache_key_lend(key_tmp) >= cache_key_lend(key)) {
				cache_key_cutfront(key_tmp, cache_key_lend(key) - cache_key_lstart(key_tmp));
				if (key_tmp->len == 0) {
					cache_key_delete(key_tmp);
				}
				continue;
			}

			/*
			 *    |----|		key_tmp
			 * |==========|		key
			 */
			cache_key_delete(key_tmp);
			continue;
		}


		/*
		 * |-----------|	key_tmp
		 *   |====|		key
		 */
		if (cache_key_lend(key_tmp) > cache_key_lend(key)) {
			key_fixup = cache_key_alloc();
			if (!key_fixup) {
				ret = -ENOMEM;
				goto out;
			}
			cache_key_copy(key_fixup, key_tmp);

			cache_key_cutback(key_tmp, cache_key_lend(key_tmp) - cache_key_lstart(key));
			cache_key_cutfront(key_fixup, cache_key_lend(key) - cache_key_lstart(key_tmp));

			for (l = 0; l < key_fixup->key_node.level; l++) {
				list_add(&key_fixup->key_node.nodes[l], &key_tmp->key_node.nodes[l]);
			}
			break;
		}


		/*
		 * |--------|		key_tmp
		 *   |==========|	key
		 */
		cache_key_cutback(key_tmp, cache_key_lend(key_tmp) - cache_key_lstart(key));
		continue;
	}

	if (lcache_debug)
		ubbd_err("insert time: %lu\n", get_ns() - start_time);

	if (false && prev_key && cache_key_can_merge(prev_key, key)) {
		cache_key_merge(prev_key, key);
	} else{
		key->key_node.level = usl_random_level();
		for (l = 0; l < key->key_node.level; l++) {
			list_add(&key->key_node.nodes[l], update_nodes[l]);
		}
	}
	ret = 0;
out:
	pthread_mutex_unlock(&skiplist->cache_key_list_mutex);

	if (lcache_debug) {
		ubbd_err("after insert\n");
		cache_key_list_dump();
	}

	return ret;
}

static void seg_used_add(struct cache_key *key)
{
	uint64_t index = key->p_off >> CACHE_SEG_SHIFT;

	pthread_mutex_lock(&cache_sb.segments[index].lock);
	cache_sb.segments[index].used += key->len;

	pthread_mutex_lock(&cache_sb.bitmap_lock);
	if (!ubbd_bit_test(cache_sb.seg_bitmap, index)) {
		ubbd_bit_set(cache_sb.seg_bitmap, index);
	}
	pthread_mutex_unlock(&cache_sb.bitmap_lock);
	pthread_mutex_unlock(&cache_sb.segments[index].lock);
}

static void seg_used_remove(struct cache_key *key)
{
	uint64_t index = key->p_off >> CACHE_SEG_SHIFT;
	bool invalidate = false;

	pthread_mutex_lock(&cache_sb.segments[index].lock);
	cache_sb.segments[index].used -= key->len;
	invalidate = (cache_sb.segments[index].used == 0);
	pthread_mutex_unlock(&cache_sb.segments[index].lock);

	if (lcache_debug)
		ubbd_err("seg%lu used: %u\n", index, cache_sb.segments[index].used);

	if (invalidate) {
		// FIXME set flag of seg to clean
again:
		pthread_mutex_lock(&cache_io_mutex);
		if (ubbd_atomic_read(&cache_sb.segments[index].inflight)) {
			pthread_mutex_unlock(&cache_io_mutex);
			usleep(100);
			goto again;
		}
		cache_seg_invalidate(index);
		pthread_mutex_unlock(&cache_io_mutex);
	}

}

static int cache_data_head_init(struct data_head *data_head);
static int cache_replay_keys(struct ubbd_cache_backend *cache_b)
{
	static char kset_buf[CACHE_KSET_SIZE] __attribute__ ((__aligned__ (4096)));
	uint64_t seg = cache_sb.key_tail_pos.seg;
	uint32_t off_in_seg = cache_sb.key_tail_pos.off_in_seg;
	uint64_t addr;
	struct cache_kset_ondisk *kset_disk;
	struct cache_key_ondisk *key_disk;
	struct cache_key *key = NULL;
	struct data_head *data_head;
	int data_head_index = 0;
	bool data_head_updated = false;
	int i, h;
	int ret = 0;
	uint32_t key_epoch;
	bool key_epoch_found = false;
	bool cache_key_written = false;

	while (true) {
again:
		addr = seg * CACHE_SEG_SIZE + off_in_seg; 
		ret = ubbd_backend_read(cache_backend, addr, CACHE_KSET_SIZE, kset_buf);
		if (ret) {
			ubbd_err("failed to read kset: %d\n", ret);
			goto err;
		}
		kset_disk = (struct cache_kset_ondisk *)kset_buf;
		if (kset_disk->magic != CACHE_KSET_MAGIC) {
			ubbd_err("magic is unexpected.\n");
			break;
		}

		if (kset_disk->kset_len > CACHE_KSET_SIZE) {
			/*FIXME: to support large kset*/
			ubbd_err("kset len larger than CACHE_KSET_SIZE\n");
			ret = -EFAULT;
			goto err;
		}

		if (key_epoch_found) {
			if (key_epoch != kset_disk->key_epoch) {
				ubbd_err("not expected epoch: expected: %u, got: %u\n", key_epoch, kset_disk->key_epoch);
				break;
			}
		} else {
			key_epoch = kset_disk->key_epoch;
			key_epoch_found = true;
		}

		if (kset_disk->flags & CACHE_KSET_FLAGS_LASTKSET) {
			seg = kset_disk->next_seg;
			off_in_seg = 0;
			key_epoch++;
			ubbd_info("goto next seg: %lu, epoch: %u\n", seg, key_epoch);
			ubbd_bit_set(cache_sb.seg_bitmap, seg);
			dump_bitmap(cache_sb.seg_bitmap);
			continue;
		}

		ubbd_bit_set(cache_sb.seg_bitmap, seg);
		dump_bitmap(cache_sb.seg_bitmap);

		for (i = 0; i < kset_disk->keys; i++) {
			key_disk = &kset_disk->data[i];
			key = cache_key_decode(key_disk);
			if (!key) {
				ret = -ENOMEM;
				goto err;
			}

			/* update the data_head_key */
			data_head_updated = false;
			for (h = 0; h < CACHE_DATA_HEAD_MAX; h++) {
				data_head = &cache_sb.data_heads[h];
				if (data_head->data_head_pos.seg == 0)
					continue;

				if (data_head->data_head_pos.seg == (key->p_off >> CACHE_SEG_SHIFT)) {
					data_head->data_head_pos.off_in_seg = (key->p_off & CACHE_SEG_MASK) + key->len;
					data_head_updated = true;
				}
			}

			if (!data_head_updated) {
				data_head = &cache_sb.data_heads[data_head_index];
				data_head->data_head_pos.seg = key->p_off >> CACHE_SEG_SHIFT;
				data_head->data_head_pos.off_in_seg = (key->p_off & CACHE_SEG_MASK) + key->len;
				data_head_index = (data_head_index + 1) % CACHE_DATA_HEAD_MAX;
			}

			if (cache_key_seg(key)->gen < key->seg_gen)
				cache_key_seg(key)->gen = key->seg_gen;
			ret = cache_key_insert(key);
			if (ret) {
				free(key);
				goto err;
			}
		}
		off_in_seg += kset_disk->kset_len;
	}

	cache_sb.key_head_pos.seg = seg;
	cache_sb.key_head_pos.off_in_seg = off_in_seg;
	ubbd_bit_set(cache_sb.seg_bitmap, seg);

	if (!cache_key_written) {
		cache_key_ondisk_write();
		cache_key_written = true;
		goto again;
	}

	dump_bitmap(cache_sb.seg_bitmap);

	/* init data head which is empty */
	for (i = 0; i < CACHE_DATA_HEAD_MAX; i++) {
		data_head = &cache_sb.data_heads[i];
		pthread_mutex_init(&data_head->data_head_lock, NULL);
		if (data_head->data_head_pos.seg == 0) {
			cache_data_head_init(data_head);
		}
	}

	ubbd_atomic_set(&cache_sb.data_head_index, 0);
err:
	return ret;
}

static char writeback_buf[CACHE_SEG_SIZE] __attribute__ ((__aligned__ (4096)));
static char verify_buf[CACHE_SEG_SIZE] __attribute__ ((__aligned__ (4096)));

static int cache_sb_write(void)
{
	int ret;
	struct cache_super_ondisk *sb = (struct cache_super_ondisk *)sb_buf;

	sb->magic = CACHE_SB_MAGIC;
	sb->n_segs = cache_sb.n_segs;
	sb->key_tail_seg = cache_sb.key_tail_pos.seg;
	sb->tail_off_in_seg = cache_sb.key_tail_pos.off_in_seg;
	sb->dirty_tail_seg = cache_sb.dirty_tail_pos.seg;
	sb->dirty_tail_off_in_seg = cache_sb.dirty_tail_pos.off_in_seg;
	sb->last_key_epoch = cache_sb.last_key_epoch;

	ret = ubbd_backend_write(cache_backend, CACHE_SB_OFF, CACHE_SB_SIZE, sb_buf);

	return ret;
}

static bool gc_stop = false;

static bool need_gc(void)
{
	if (cache_sb.key_tail_pos.seg == cache_sb.dirty_tail_pos.seg)
		return false;

	if (ubbd_bitmap_weight(cache_sb.seg_bitmap) < 10)
		return false;

	return true;
}

static void *cache_gc_thread_fn(void* args)
{
	int ret = 0;
	int *retp = args;
	uint64_t addr;
	static char kset_buf[CACHE_KSET_SIZE] __attribute__ ((__aligned__ (4096))) = { 0 };
	struct cache_kset_ondisk *kset_disk = (struct cache_kset_ondisk *)kset_buf;
	struct cache_key_ondisk *key_disk;
	struct cache_key *key;
	int i;

	while (true) {
		if (gc_stop)
			break;

		if (lcache_debug)
			ubbd_err("key_tail_pos: %lu, off: %u, dirty_tail_pos: %lu, off: %u\n", cache_sb.key_tail_pos.seg, cache_sb.key_tail_pos.off_in_seg, cache_sb.dirty_tail_pos.seg, cache_sb.dirty_tail_pos.off_in_seg);

		if (!need_gc()) {
			usleep(100000);
			continue;
		}

		addr = seg_pos_to_addr(&cache_sb.key_tail_pos);
		if (lcache_debug)
			ubbd_err("read kset : %lu\n", addr);

		ret = ubbd_backend_read(cache_backend, addr, CACHE_KSET_SIZE, kset_buf);
		if (ret) {
			ubbd_err("failed to read cache.\n");
			break;
		}

		if (kset_disk->magic != CACHE_KSET_MAGIC) {
			ret = -EIO;
			ubbd_err("unexpected kset magic in writeback.\n");
			break;
		}

		if (kset_disk->kset_len > CACHE_KSET_SIZE) {
			/*FIXME: to support large kset*/
			ubbd_err("kset len larger than CACHE_KSET_SIZE\n");
			ret = -EIO;
			break;
		}

		if (kset_disk->flags & CACHE_KSET_FLAGS_LASTKSET) {
			ubbd_err("gc got last kset %lu\n", cache_sb.key_tail_pos.seg);

			if (1) {
				ret = ubbd_backend_write(cache_backend, cache_sb.key_tail_pos.seg << CACHE_SEG_SHIFT, CACHE_SEG_SIZE, seg_buf);
				if (ret) {
					ubbd_err("failed to write zero to old key segment.\n");
				}
			}

			pthread_mutex_lock(&cache_sb.bitmap_lock);
			ubbd_bit_clear(cache_sb.seg_bitmap, cache_sb.key_tail_pos.seg);
			pthread_mutex_unlock(&cache_sb.bitmap_lock);
			dump_bitmap(cache_sb.seg_bitmap);

			cache_sb.key_tail_pos.seg = kset_disk->next_seg;
			cache_sb.key_tail_pos.off_in_seg = 0;

			cache_sb_write();
			continue;
		}

		for (i = 0; i < kset_disk->keys; i++) {
			key_disk = &kset_disk->data[i];
			key = cache_key_decode(key_disk);
			if (!key) {
				ret = -ENOMEM;
				break;
			}

			seg_used_remove(key);
			free(key);
		}

		cache_sb.key_tail_pos.off_in_seg += kset_disk->kset_len;
		cache_sb_write();
	}

	ubbd_info("gc thread exit: %d\n", ret);
	*retp = ret;

	return NULL;
}

pthread_t cache_writeback_thread;

static bool writeback_stop = false;

static void *cache_writeback_thread_fn(void* args)
{
	int ret = 0;
	int *retp = args;
	uint64_t addr;
	static char kset_buf[CACHE_KSET_SIZE] __attribute__ ((__aligned__ (4096))) = { 0 };
	struct cache_kset_ondisk *kset_disk = (struct cache_kset_ondisk *)kset_buf;
	struct cache_key_ondisk *key_disk;
	struct cache_key *key;
	int i;

	while (true) {
		if (writeback_stop)
			break;

		if (lcache_debug)
			ubbd_err("dirty_tail_pos.seg: %lu, off: %u, key_head_pos.seg: %lu, off: %u\n", cache_sb.dirty_tail_pos.seg, cache_sb.dirty_tail_pos.off_in_seg, cache_sb.key_head_pos.seg, cache_sb.key_head_pos.off_in_seg);
		addr = seg_pos_to_addr(&cache_sb.dirty_tail_pos);
		if (addr == seg_pos_to_addr(&cache_sb.key_head_pos)) {
			usleep(100000);
			continue;
		}

		if (lcache_debug)
			ubbd_err("read kset : %lu\n", addr);

		ret = ubbd_backend_read(cache_backend, addr, CACHE_KSET_SIZE, kset_buf);
		if (ret) {
			ubbd_err("failed to read cache.\n");
			break;
		}

		if (kset_disk->magic != CACHE_KSET_MAGIC) {
			ret = -EIO;
			ubbd_err("unexpected kset magic in writeback.\n");
			break;
		}

		if (kset_disk->kset_len > CACHE_KSET_SIZE) {
			/*FIXME: to support large kset*/
			ubbd_err("kset len larger than CACHE_KSET_SIZE\n");
			ret = -EIO;
			break;
		}

		if (kset_disk->flags & CACHE_KSET_FLAGS_LASTKSET) {
			if (lcache_debug)
				ubbd_err("got last kset %lu\n", cache_sb.dirty_tail_pos.seg);

			cache_sb.dirty_tail_pos.seg = kset_disk->next_seg;
			cache_sb.dirty_tail_pos.off_in_seg = 0;

			cache_sb_write();
			continue;
		}

		for (i = 0; i < kset_disk->keys; i++) {
			key_disk = &kset_disk->data[i];
			key = cache_key_decode(key_disk);
			if (!key) {
				ret = -ENOMEM;
				break;
			}
			ret = ubbd_backend_read(cache_backend, key->p_off, key->len, writeback_buf);
			if (ret) {
				ubbd_err("failed to read data from cache in writeback.\n");
				free(key);
				break;
			}

			ret = ubbd_backend_write(backing_backend, key->l_off, key->len, writeback_buf);
			if (ret) {
				ubbd_err("failed to write data to backing in writeback.\n");
				free(key);
				break;
			}

			free(key);
		}

		cache_sb.dirty_tail_pos.off_in_seg += kset_disk->kset_len;
		cache_sb_write();
	}

	ubbd_info("writeback thread exit: %d\n", ret);
	*retp = ret;

	return NULL;
}

pthread_t cache_writeback_thread;

static int thread_ret = 0;

static int cache_start_writeback(struct ubbd_cache_backend *cache_b)
{
	if (1) {
		return pthread_create(&cache_writeback_thread, NULL, cache_writeback_thread_fn, &thread_ret);
	}

	return 0;
}

pthread_t cache_gc_thread;

static int cache_start_gc(struct ubbd_cache_backend *cache_b)
{
	if (1) {
		return pthread_create(&cache_gc_thread, NULL, cache_gc_thread_fn, &thread_ret);
	}

	return 0;
}

static int cache_stop_writeback()
{
	int ret;

	writeback_stop = true;

	ret = pthread_join(cache_writeback_thread, NULL);
	if (ret) {
		ubbd_err("failed to wait cache_writeback_thread joing: %d\n", ret);
		return ret;
	}

	return 0;
}

static int cache_stop_gc()
{
	int ret;

	gc_stop = true;

	ret = pthread_join(cache_gc_thread, NULL);
	if (ret) {
		ubbd_err("failed to wait cache_gc_thread joing: %d\n", ret);
		return ret;
	}

	return 0;
}

static int cache_key_lists_init(struct ubbd_backend *ubbd_b)
{
	uint64_t size = ubbd_backend_size(ubbd_b);
	int i;

	cache_key_list_num = size >> CACHE_KEY_LIST_SHIFT;
	if (size % CACHE_KEY_LIST_MASK)
		cache_key_list_num++;

	cache_key_lists = calloc(cache_key_list_num, sizeof(struct ubbd_skiplist));
	if (!cache_key_lists) {
		ubbd_err("failed to allocate memory for cache_key_lists.\n");
		return -ENOMEM;
	}

	for (i = 0; i < cache_key_list_num; i++) {
		ubbd_skiplist_init(&cache_key_lists[i].cache_key_list);
		pthread_mutex_init(&cache_key_lists[i].cache_key_list_mutex, NULL);
	}

	return 0;
}

static int cache_backend_open(struct ubbd_backend *ubbd_b)
{
	int ret = 0;
	struct ubbd_cache_backend *cache_b = CACHE_BACKEND(ubbd_b);
	struct cache_super_ondisk *sb;
	char *verify_name;

	cache_key_lists_init(ubbd_b);

	cache_b->backing_backend->num_queues = 1;
	ret = ubbd_backend_open(cache_b->backing_backend);
	if (ret) {
		return ret;
	}

	cache_b->cache_backend->num_queues = ubbd_b->num_queues;
	ret = ubbd_backend_open(cache_b->cache_backend);
	if (ret) {
		goto close_backing;
	}

	cache_backend = cache_b->cache_backend;
	backing_backend = cache_b->backing_backend;


	if (verify) {
		if (asprintf(&verify_name, CACHE_VERIFY_PATH"%d", ubbd_b->dev_id) == -1)
			ubbd_err("error failed to setup verify_name\n");

		verify_fd = open(verify_name, O_RDWR | O_DIRECT);
		if (verify_fd < 0) {
			ubbd_err("error failed open verify fd.\n");
			goto close_cache;
		}
	}

	ret = ubbd_backend_read(cache_backend, CACHE_SB_OFF, CACHE_SB_SIZE, sb_buf);
	if (ret) {
		ubbd_err("failed to read cache sb\n");
		goto close_cache;
	}

	sb = (struct cache_super_ondisk *)sb_buf;

	if (sb->magic != CACHE_SB_MAGIC) {
		sb->magic = CACHE_SB_MAGIC;
		sb->key_tail_seg = 1;
		sb->tail_off_in_seg = 0;
		sb->dirty_tail_seg = 1;
		sb->dirty_tail_off_in_seg = 0;
		sb->last_key_epoch = 0;
		sb->n_segs = ubbd_backend_size(cache_b->cache_backend) / CACHE_SEG_SIZE;

		ret = ubbd_backend_write(cache_backend, CACHE_SB_OFF, CACHE_SB_SIZE, sb_buf);
		if (ret) {
			ubbd_err("failed to write cache sb.\n");
			goto close_cache;
		}
	}

	/* initialize cache sb */
	cache_sb.key_tail_pos.seg = sb->key_tail_seg;
	cache_sb.key_tail_pos.off_in_seg = sb->tail_off_in_seg;
	cache_sb.dirty_tail_pos.seg = sb->dirty_tail_seg;
	cache_sb.dirty_tail_pos.off_in_seg = sb->dirty_tail_off_in_seg;
	cache_sb.n_segs = sb->n_segs;
	cache_sb.last_key_epoch = sb->last_key_epoch;


	ret = ubbd_open_uio(&ubbd_b->queues[0].uio_info);
	if (ret) {
		ubbd_err("failed to open uio for queue 0: %d\n", ret);
		goto close_cache;
	}

	cache_sb.key_ondisk_w = ubbd_uio_get_info(&ubbd_b->queues[0].uio_info);

	cache_sb.segments = calloc(cache_sb.n_segs, sizeof(struct segment));
	if (!cache_sb.segments) {
		ubbd_err("failed to alloc mem for segments.\n");
		ret = -ENOMEM;
		goto close_cache;
	}

	int i;
	for (i = 0; i < cache_sb.n_segs; i++) {
		pthread_mutex_init(&cache_sb.segments[i].lock, NULL);
		atomic_set(&cache_sb.segments[i].inflight, 0);
	}

	cache_sb.seg_bitmap = ubbd_bitmap_alloc(cache_sb.n_segs);
	if (!cache_sb.seg_bitmap) {
		ubbd_err("failed to alloc mem for seg_bitmap\n");
		ret = -ENOMEM;
		goto free_segments;
	}

	pthread_mutex_init(&cache_sb.bitmap_lock, NULL);
	/* first segment is reserved */
	ubbd_bit_set(cache_sb.seg_bitmap, 0);
	dump_bitmap(cache_sb.seg_bitmap);


	if (1) {
		ubbd_err("before replay\n");
		ret = cache_replay_keys(cache_b);
		if (ret) {
			goto free_seg_bitmap;
		}
		ubbd_err("replay ending\n");

		if (lcache_debug)
			cache_key_list_dump();
	}


	cache_start_writeback(cache_b);
	cache_start_gc(cache_b);

	return 0;

free_seg_bitmap:
	ubbd_bitmap_free(cache_sb.seg_bitmap);
free_segments:
	free(cache_sb.segments);
close_cache:
	ubbd_backend_close(cache_b->cache_backend);
close_backing:
	ubbd_backend_close(cache_b->backing_backend);
	return ret;
}

static void wait_for_cache_clean(struct ubbd_cache_backend *cache_b)
{
	uint64_t addr;

	while (true) {
		addr = seg_pos_to_addr(&cache_sb.dirty_tail_pos);
		if (addr != seg_pos_to_addr(&cache_sb.key_head_pos)) {
			usleep(100000);
			continue;
		}
		break;
	}

	return;
}

static void cache_backend_close(struct ubbd_backend *ubbd_b)
{
	struct ubbd_cache_backend *cache_b = CACHE_BACKEND(ubbd_b);

	cache_key_ondisk_write();

	if (cache_b->detach_on_close) {
		wait_for_cache_clean(cache_b);
	}

	cache_stop_gc();
	cache_stop_writeback();

	cache_key_lists_release();
	ubbd_bitmap_free(cache_sb.seg_bitmap);
	free(cache_sb.segments);
	ubbd_close_uio(&ubbd_b->queues[0].uio_info);
	ubbd_backend_close(cache_b->cache_backend);
	ubbd_backend_close(cache_b->backing_backend);
}

static void cache_backend_release(struct ubbd_backend *ubbd_b)
{
	struct ubbd_cache_backend *cache_b = CACHE_BACKEND(ubbd_b);

	if (!cache_b)
		return;

	if (cache_b->cache_backend)
		ubbd_backend_release(cache_b->cache_backend);

	if (cache_b->backing_backend)
		ubbd_backend_release(cache_b->backing_backend);

	free(cache_b);
}

struct cache_backend_io_ctx_data {
	struct ubbd_backend *ubbd_b;
	struct ubbd_backend_io *io;
	struct ubbd_backend_io *orig_io;
	uint64_t backing_off;
	bool cache_io;
	struct cache_key *key;
};

/*
static int compare_iov_and_buf(struct iovec *iov, int iov_cnt, void *buf, int len)
{
	int i = 0;
	int io_done = 0;

	for (i = 0; i < iov_cnt; i++) {
		if (crc64(iov[i].iov_base, iov[i].iov_len) != crc64(buf + io_done, iov[i].iov_len)) {
			return -1;
		}

		io_done += iov[i].iov_len;

		if (io_done >= len)
			return 0;
	}
	if (io_done != len) {
		return -1;
	}

	return 0;
}
*/

static int cache_backend_write_io_finish(struct context *ctx, int ret)
{
	struct cache_backend_io_ctx_data *data = (struct cache_backend_io_ctx_data *)ctx->data;
	struct ubbd_backend_io *io = (struct ubbd_backend_io *)data->io;
	struct ubbd_backend_io *orig_io = (struct ubbd_backend_io *)data->orig_io;
	struct cache_key *key = data->key;

	if (ret) {
		ubbd_err("ret of cache_backend_io: type %d, %lu:%u: %s\n",
				io->io_type, io->offset, io->len, strerror(-ret));
	}

	if (lcache_debug)
		ubbd_err("finish io: %p, orig_io: %p\n", io, orig_io);

	ret = cache_key_insert(key);
	if (ret) {
		ubbd_err("failed to insert cache key: %d.\n", ret);
		free(key);
		goto finish;
	}

	cache_key_ondisk_append(key);

finish:
	if (lcache_debug)
		ubbd_err("finish cache write: %lu\n", io->offset >> CACHE_SEG_SHIFT);

	cache_seg_put(io->offset >> CACHE_SEG_SHIFT);
	ubbd_backend_free_backend_io(data->ubbd_b, io);;
	ubbd_backend_io_finish(orig_io, ret);

	return 0;
}

static int cache_backend_read_io_finish(struct context *ctx, int ret)
{
	struct cache_backend_io_ctx_data *data = (struct cache_backend_io_ctx_data *)ctx->data;
	struct ubbd_backend_io *io = (struct ubbd_backend_io *)data->io;
	struct ubbd_backend_io *orig_io = (struct ubbd_backend_io *)data->orig_io;

	if (ret) {
		ubbd_err("ret of cache_backend_io: type %d, %lu:%u: %s\n",
				io->io_type, io->offset, io->len, strerror(-ret));
	}

	if (lcache_debug)
		ubbd_err("finish io: %p, orig_io: %p\n", io, orig_io);

	if (data->cache_io) {
		if (lcache_debug)
			ubbd_err("finish cache read: %lu\n", io->offset >> CACHE_SEG_SHIFT);
		cache_seg_put(io->offset >> CACHE_SEG_SHIFT);
	}

	ubbd_backend_free_backend_io(data->ubbd_b, io);;
	ubbd_backend_io_finish(orig_io, ret);

	return 0;
}

static struct ubbd_backend_io* prepare_backend_io(struct ubbd_backend *ubbd_b,
		struct ubbd_backend_io *io,
		uint64_t off, uint32_t size, ubbd_ctx_finish_t finish_fn)
{
	struct ubbd_backend_io *clone_io;
	struct cache_backend_io_ctx_data *data;

	clone_io = ubbd_backend_io_clone(ubbd_b, io, off, size);
	if (!clone_io) {
		ubbd_err("failed to clone backend_io\n");
		return NULL;
	}

	clone_io->ctx = context_alloc(sizeof(struct cache_backend_io_ctx_data));
	if (!clone_io->ctx) {
		ubbd_err("failed to alloc ctx for clone io\n");
		free(clone_io);
		return NULL;
	}

	clone_io->ctx->finish = finish_fn;

	data = (struct cache_backend_io_ctx_data *)clone_io->ctx->data;
	context_get(io->ctx);
	data->io = clone_io;
	data->orig_io = io;
	data->ubbd_b = ubbd_b;

	return clone_io;
}

#define	CACHE_LIMIT	4190208

static uint64_t seg_pos_to_addr(struct seg_pos *pos)
{
	return ((pos->seg << CACHE_SEG_SHIFT) + pos->off_in_seg);
}

static int cache_data_head_init(struct data_head *data_head)
{
	int ret;

again:
	pthread_mutex_lock(&cache_sb.bitmap_lock);
	ret = ubbd_bit_find_next_zero(cache_sb.seg_bitmap, random() % cache_sb.n_segs, &data_head->data_head_pos.seg);
	if (ret) {
		pthread_mutex_unlock(&cache_sb.bitmap_lock);
		ubbd_err("cant find segment for data\n");
		usleep(1000000);
		goto again;
	}

	cache_sb.last_bit = data_head->data_head_pos.seg;
	ubbd_bit_set(cache_sb.seg_bitmap, data_head->data_head_pos.seg);

	pthread_mutex_unlock(&cache_sb.bitmap_lock);

	data_head->data_head_pos.off_in_seg = 0;
	if (lcache_debug) {
		ubbd_err("new data head: %lu\n", data_head->data_head_pos.seg);
		dump_bitmap(cache_sb.seg_bitmap);
	}

	return 0;
}

struct data_head *cache_get_data_head(struct ubbd_backend_io *io)
{
	return &cache_sb.data_heads[io->queue_id % CACHE_DATA_HEAD_MAX];
}

static int cache_data_alloc(struct cache_key *key, struct ubbd_backend_io *io)
{
	int ret = 0;

	struct data_head *data_head = cache_get_data_head(io);

again:
	pthread_mutex_lock(&data_head->data_head_lock);
	if (CACHE_SEG_SIZE - data_head->data_head_pos.off_in_seg >= key->len) {
		key->p_off = seg_pos_to_addr(&data_head->data_head_pos);
		key->seg_gen = cache_key_seg(key)->gen;
		data_head->data_head_pos.off_in_seg += key->len;

		ret = 0;;
		goto out;
	} else if (CACHE_SEG_SIZE > data_head->data_head_pos.off_in_seg) {
		key->p_off = seg_pos_to_addr(&data_head->data_head_pos);
		key->len = CACHE_SEG_SIZE - data_head->data_head_pos.off_in_seg;
		key->seg_gen = cache_key_seg(key)->gen;
		data_head->data_head_pos.off_in_seg += key->len;
	} else {
		ret = cache_data_head_init(data_head);
		if (ret) {
			goto out;
		}
		pthread_mutex_unlock(&data_head->data_head_lock);
		goto again;
	}

out:
	pthread_mutex_unlock(&data_head->data_head_lock);
	return ret;
}

static int cache_backend_writev(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct ubbd_cache_backend *cache_b = CACHE_BACKEND(ubbd_b);
	struct ubbd_backend_io *cache_io;
	struct cache_key *key;
	uint32_t io_done = 0;
	int ret = 0;

	if (lcache_debug)
		ubbd_err("cache writev: %lu:%u,  iov_len: %lu, iocnt: %u crc: %lu crc512: %lu\n",
				io->offset, io->len, io->iov[0].iov_len, io->iov_cnt,
				crc64(io->iov[0].iov_base, io->iov[0].iov_len),
				crc64(io->iov[0].iov_base, 512));

	if (writearound)
		goto write_backing;

	while (true) {
		if (io_done >= io->len) {
			break;
		}

		key = cache_key_alloc();
		if (!key) {
			ret = -ENOMEM;
			goto finish;
		}

		key->l_off = io->offset + io_done;
		key->len = io->len - io_done;
		if (key->len > CACHE_KEY_LIST_SIZE - (key->l_off & CACHE_KEY_LIST_MASK))
			key->len = CACHE_KEY_LIST_SIZE - (key->l_off & CACHE_KEY_LIST_MASK);

		ret = cache_data_alloc(key, io);
		if (ret) {
			free(key);
			goto finish;
		}

		if (!key->len) {
			ubbd_err("len of key is 0\n");
			free(key);
			continue;
		}

		cache_io = prepare_backend_io(cache_backend, io, io_done, key->len, cache_backend_write_io_finish);
		if (!cache_io) {
			free(key);
			ret = -ENOMEM;
			goto finish;
		}
		cache_io->offset = key->p_off;

		struct cache_backend_io_ctx_data *data;

		data = (struct cache_backend_io_ctx_data *)cache_io->ctx->data;
		data->cache_io = true;
		data->key = key;
		cache_seg_get(key->p_off >> CACHE_SEG_SHIFT);

		if (lcache_debug)
			ubbd_err("yds submit write cache io: %lu:%u seg: %lu\n",
					cache_io->offset, cache_io->len,
					cache_io->offset >> CACHE_SEG_SHIFT);

		ret = cache_b->cache_backend->backend_ops->writev(cache_b->cache_backend, cache_io);
		if (ret) {
			ubbd_err("cache io failed.\n");
			cache_seg_put(key->p_off >> CACHE_SEG_SHIFT);
			free(key);
			goto finish;
		}

		io_done += key->len;
	}

write_backing:
	if (writearound) {
		struct ubbd_backend_io *backing_io;
		backing_io = prepare_backend_io(backing_backend, io, 0, io->len, cache_backend_read_io_finish);
		if (lcache_debug)
			ubbd_err("yds submit write backing io: %lu:%u crc: %lu, iov_len: %lu, iocnt: %d\n",
					backing_io->offset, backing_io->len,
					crc64(backing_io->iov[0].iov_base, backing_io->iov[0].iov_len),
					backing_io->iov[0].iov_len, backing_io->iov_cnt);

		ret = backing_backend->backend_ops->writev(backing_backend, backing_io);
		if (ret) {
			ubbd_err("failed to submit backing io\n");
		}
	}

	if (verify) {
		ret = pwritev(verify_fd, io->iov, io->iov_cnt, io->offset);
		if (ret != io->len) {
			ubbd_err("error to write verify: %d\n", ret);
		}
	}

	ret = 0;
finish:
	ubbd_backend_io_finish(io, ret);
	return 0;
}

static int submit_backing_io(struct ubbd_backend_io *io,
		uint64_t off, uint32_t len)
{
	struct ubbd_backend_io *backing_io;
	int ret;

	if (len == 0)
		return 0;

	if (verify) {
		uint64_t backing_crc, verify_crc;

		ret = ubbd_backend_read(backing_backend, io->offset + off, len, verify_buf);
		if (ret) {
			ubbd_err("error: failed to read data from cache for verify.\n");
			return ret;
		}
		
		backing_crc = crc64(verify_buf, len);

		ret = pread(verify_fd, verify_buf, len, io->offset + off);
		if (ret != len) {
			ubbd_err("error: failed to read data from backing for verify.\n");
			return ret;
		}

		verify_crc = crc64(verify_buf, len);
		if (verify_crc != backing_crc) {
			ubbd_err("verify crc error: backing_off: %lu, len: %u, backing_crc: %lu, verify_crc: %lu\n",
					io->offset + off, len, backing_crc, verify_crc);
		}
	}

	backing_io = prepare_backend_io(backing_backend, io, off, len, cache_backend_read_io_finish);
	if (!backing_io) {
		ret = -ENOMEM;
		goto out;
	}

	if (lcache_debug)
		ubbd_err("submit backing io: %lu:%u\n", backing_io->offset, backing_io->len);

	ret = backing_backend->backend_ops->readv(backing_backend, backing_io);
out:
	return ret;
}

static int submit_cache_io(struct ubbd_backend_io *io,
		uint32_t off, uint32_t len,
		uint64_t cache_off,
		uint64_t backing_off)
{
	struct ubbd_backend_io *cache_io;
	struct cache_backend_io_ctx_data *data;
	int ret;

	if (len == 0)
		return 0;

	if (verify) {
		uint64_t cache_crc, verify_crc;

		ret = ubbd_backend_read(cache_backend, cache_off, len, verify_buf);
		if (ret) {
			ubbd_err("error: failed to read data from cache for verify.\n");
			return ret;
		}
		
		cache_crc = crc64(verify_buf, len);

		ret = pread(verify_fd, verify_buf, len, backing_off);
		if (ret != len) {
			ubbd_err("error: failed to read data from backing for verify.\n");
			return ret;
		}

		verify_crc = crc64(verify_buf, len);
		if (cache_crc != verify_crc) {
			ubbd_err("verify crc error: cache_off: %lu, backing_off: %lu, len: %u, cache_crc: %lu, verify_crc: %lu\n",
					cache_off, backing_off, len, cache_crc, verify_crc);
			__cache_key_list_dump(&cache_key_lists[backing_off >> CACHE_KEY_LIST_SHIFT].cache_key_list, backing_off >> CACHE_KEY_LIST_SHIFT);
		}
	}

	cache_io = prepare_backend_io(cache_backend, io, off, len, cache_backend_read_io_finish);
	if (!cache_io) {
		ret = -ENOMEM;
		goto out;
	}
	cache_io->offset = cache_off;

	data = (struct cache_backend_io_ctx_data *)cache_io->ctx->data;
	data->backing_off = backing_off;
	if (lcache_debug) {
		ubbd_err("yds submit cache io: %lu:%u seg: %lu, logic off: %lu:%u\n",
				cache_io->offset, cache_io->len, cache_io->offset >> CACHE_SEG_SHIFT,
				backing_off, len);
	}

	cache_seg_get(cache_io->offset >> CACHE_SEG_SHIFT);
	data->cache_io = true;
	ret = cache_backend->backend_ops->readv(cache_backend, cache_io);
out:
	return ret;
}


static int cache_backend_readv(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	int ret = 0;
	struct ubbd_skiplist_head *sl_node_tmp, *sl_node_next;
	struct cache_key key_data = { .l_off = io->offset, .len = io->len };
	struct cache_key *key = &key_data;
	uint32_t io_done = 0, total_io_done = 0;
	uint32_t io_len;
	struct list_head *head;
	struct cache_key *key_tmp, *next;
	struct cache_key *prev_key = NULL;
	struct list_head *update_nodes[USKIPLIST_MAXLEVEL];
	struct list_head *prev_key_node;
	struct ubbd_skiplist *skiplist;
	int l;

	if (lcache_debug) {
		cache_key_list_dump();
		ubbd_err("cache readv: %lu:%u\n", io->offset, io->len);
	}

	if (writearound)
		goto read_backing;


	pthread_mutex_lock(&cache_io_mutex);

next_skiplist:
	prev_key = NULL;
	io_done = 0;
	key->l_off = io->offset + total_io_done;
	key->len = io->len - total_io_done;

	if (key->len > CACHE_KEY_LIST_SIZE - (key->l_off & CACHE_KEY_LIST_MASK))
		key->len = CACHE_KEY_LIST_SIZE - (key->l_off & CACHE_KEY_LIST_MASK);

	skiplist = &cache_key_lists[key->l_off >> CACHE_KEY_LIST_SHIFT];
	if (lcache_debug) {
		ubbd_err("readv from skiplist %p %ld, %lu:%u\n", &skiplist->cache_key_list, key->l_off >> CACHE_KEY_LIST_SHIFT, key->l_off, key->len);
		cache_key_list_dump();
	}

	pthread_mutex_lock(&skiplist->cache_key_list_mutex);

	for (l = USKIPLIST_MAXLEVEL - 1; l >= 0; l--) {
		if (prev_key) {
			prev_key_node = &prev_key->key_node.nodes[l];
			head = prev_key_node->prev;
		} else {
			head = prev_key_node = &skiplist->cache_key_list.nodes[l];
		}

		list_for_each_entry_range_safe(key_tmp, next, head, &skiplist->cache_key_list.nodes[l], key_node.nodes[l]) {
			if (key_tmp->seg_gen < cache_key_seg(key_tmp)->gen) {
				cache_key_delete(key_tmp);
				continue;
			}

			if (cache_key_lstart(key_tmp) <= cache_key_lstart(key)) {
				prev_key = key_tmp;
				prev_key_node = &key_tmp->key_node.nodes[l];
				continue;
			}
			break;
		}
		update_nodes[l] = prev_key_node;
	}

	if (prev_key) {
		head = update_nodes[0]->prev;
	} else {
		head = &skiplist->cache_key_list.nodes[0];
	}

	list_for_each_entry_range_safe(sl_node_tmp, sl_node_next, head, &skiplist->cache_key_list.nodes[0], nodes[0]) {
		key_tmp = ubbd_container_of(sl_node_tmp, struct cache_key, key_node);
		if (lcache_debug)
			ubbd_err("gen: %lu, key_gen: %lu, seg: %lu, l_off: %lu\n",
					cache_key_seg(key_tmp)->gen, key_tmp->seg_gen,
					key_tmp->p_off >> CACHE_SEG_SHIFT, key_tmp->l_off);

		if (key_tmp->seg_gen < cache_key_seg(key_tmp)->gen) {
			cache_key_delete(key_tmp);
			continue;
		}
		if (io_done >= io->len)
			goto out;
		/*
		 * |----------|
		 *		|=====|
		 * */
		if (cache_key_lend(key_tmp) <= cache_key_lstart(key)) {
			continue;
		}

		/*
		 *	  |--------|
		 * |====|
		 */
		if (cache_key_lstart(key_tmp) >= cache_key_lend(key)) {
			submit_backing_io(io, total_io_done + io_done, key->len);
			io_done += key->len;
			cache_key_cutfront(key, key->len);
			goto out;
		}

		/* overlap */
		if (cache_key_lstart(key_tmp) >= cache_key_lstart(key)) {
			/*
			 *     |----------------|	key_tmp
			 * |===========|		key
			 */
			if (cache_key_lend(key_tmp) >= cache_key_lend(key)) {
				io_len = cache_key_lstart(key_tmp) - cache_key_lstart(key);
				if (io_len) {
					submit_backing_io(io, total_io_done + io_done, io_len);
					io_done += io_len;
					cache_key_cutfront(key, io_len);
				}

				io_len = cache_key_lend(key) - cache_key_lstart(key_tmp);
				ret = submit_cache_io(io, total_io_done + io_done, io_len, key_tmp->p_off, key_tmp->l_off);
				if (ret)
					ret = 0;
				io_done += io_len;
				cache_key_cutfront(key, io_len);
				goto out;
			}

			/*
			 *    |----|		key_tmp
			 * |==========|		key
			 */
			io_len = cache_key_lstart(key_tmp) - cache_key_lstart(key);
			if (io_len) {
				submit_backing_io(io, total_io_done + io_done, io_len);
				io_done += io_len;
				cache_key_cutfront(key, io_len);
			}

			io_len = key_tmp->len;
			ret = submit_cache_io(io, total_io_done + io_done, io_len, key_tmp->p_off, key_tmp->l_off);
			if (ret)
				ret = 0;
			io_done += io_len;
			cache_key_cutfront(key, io_len);
			continue;
		}


		/*
		 * |-----------|	key_tmp
		 *   |====|		key
		 */
		if (cache_key_lend(key_tmp) >= cache_key_lend(key)) {
			ret = submit_cache_io(io, total_io_done + io_done, key->len, key_tmp->p_off + cache_key_lstart(key) - cache_key_lstart(key_tmp),
					key_tmp->l_off + cache_key_lstart(key) - cache_key_lstart(key_tmp));
			io_done += key->len;
			if (ret)
				ret = 0;

			cache_key_cutfront(key, key->len);
			goto out;
		}


		/*
		 * |--------|		key_tmp
		 *   |==========|	key
		 */
		io_len = cache_key_lend(key_tmp) - cache_key_lstart(key);
		ret = submit_cache_io(io, total_io_done + io_done, io_len, key_tmp->p_off + cache_key_lstart(key) - cache_key_lstart(key_tmp),
					key_tmp->l_off + cache_key_lstart(key) - cache_key_lstart(key_tmp));
		if (ret)
			ret = 0;
		io_done += io_len;
		cache_key_cutfront(key, io_len);
		continue;
	}
read_backing:
	if (!writearound) {
		submit_backing_io(io, total_io_done + io_done, key->len);
		io_done += key->len;
	} else {
		ret = backing_backend->backend_ops->readv(backing_backend, io);
		return ret;
	}
out:
	pthread_mutex_unlock(&skiplist->cache_key_list_mutex);

	total_io_done += io_done;
	io_done = 0;

	if (!ret && total_io_done < io->len)
		goto next_skiplist;

	pthread_mutex_unlock(&cache_io_mutex);
	ubbd_backend_io_finish(io, ret);
	return 0;
}

static int cache_backend_flush(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct ubbd_cache_backend *cache_b = CACHE_BACKEND(ubbd_b);

	cache_key_ondisk_write();
	cache_b->cache_backend->backend_ops->flush(cache_b->cache_backend, io);
	cache_b->backing_backend->backend_ops->flush(cache_b->backing_backend, io);
	return 0;
}

static int cache_backend_set_opts(struct ubbd_backend *ubbd_b, struct ubbd_backend_opts *opts)
{
	struct ubbd_cache_backend *cache_b = CACHE_BACKEND(ubbd_b);

	cache_b->detach_on_close = opts->cache.detach_on_close;

	return 0;
}

struct ubbd_backend_ops cache_backend_ops = {
	.open = cache_backend_open,
	.close = cache_backend_close,
	.release = cache_backend_release,
	.writev = cache_backend_writev,
	.readv = cache_backend_readv,
	.flush = cache_backend_flush,
	.set_opts = cache_backend_set_opts,
};
