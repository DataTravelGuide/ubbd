#define _GNU_SOURCE

#include "cache_backend_internal.h"

static struct cache_key *cache_key_lists;
static uint64_t cache_key_list_num;
pthread_mutex_t cache_io_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t cache_disk_append_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t sb_write_lock = PTHREAD_MUTEX_INITIALIZER;

struct ubbd_backend *cache_backend;
struct ubbd_backend *backing_backend;

struct ubbd_backend *cache_backends[4];

/* used to do data verify, just for debugging. */
static bool verify = false;
static int verify_fd;
#define CACHE_VERIFY_PATH	""

static bool writearound = false;

static int lcache_debug = 0;

static char sb_buf[4096] __attribute__ ((__aligned__ (4096)));
static char seg_buf[CACHE_SEG_SIZE] __attribute__ ((__aligned__ (4096)));

static void cache_seg_invalidate(uint64_t index)
{
	int ret = 0;

	cache_sb.segments[index].gen++;

	if (lcache_debug)
		ubbd_err("gc seg: %lu\n", index);

	if (0)
		ret = ubbd_backend_write(cache_backend, index << CACHE_SEG_SHIFT, CACHE_SEG_SIZE, seg_buf);
	else
		ret = 0;

	if (ret) {
		ubbd_err("failed to write zero to gc seg\n");
	}

	pthread_mutex_lock(&cache_sb.bitmap_lock);
	ubbd_bit_clear(cache_sb.seg_bitmap, index);
	//dump_bitmap(cache_sb.seg_bitmap);
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

static int cache_sb_write(void);
static int get_cache_backend(uint64_t off);
static int cache_key_ondisk_write(struct cache_key_ondisk_write_data *key_ondisk_w)
{
	static char kset_buf[CACHE_KSET_SIZE] __attribute__ ((__aligned__ (4096))) = { 0 };
	struct cache_kset_ondisk *kset = (struct cache_kset_ondisk *)kset_buf;
	uint64_t addr, space_required;
	uint64_t next_seg;
	int backend_index = 0;
	struct ubbd_backend *backend;
	int ret;

	if (!key_ondisk_w->key_used)
		return 0;

	if (lcache_debug)
		ubbd_err("key_used: %d\n", key_ondisk_w->key_used);
again:
	addr = seg_pos_to_addr(&cache_sb.key_head_pos);
	memset(kset_buf, 0, CACHE_KSET_SIZE);

	space_required = sizeof(struct cache_kset_ondisk) +
		key_ondisk_w->key_used * sizeof(struct cache_key_ondisk);

	if (lcache_debug)
		ubbd_err("space_required: %lu, key_used: %u\n", space_required, key_ondisk_w->key_used);

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

		//dump_bitmap(cache_sb.seg_bitmap);
		backend_index = get_cache_backend(addr);
		backend = cache_backends[backend_index];
		ret = ubbd_backend_write(backend, addr - (backend_index * (cache_sb.segs_per_device << CACHE_SEG_SHIFT)), 4096, kset_buf);
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
	kset->keys = key_ondisk_w->key_used;
	kset->kset_len = space_required;
	kset->key_epoch = cache_sb.last_key_epoch;
	memcpy(kset->data, key_ondisk_w->keys, sizeof(struct cache_key_ondisk) * key_ondisk_w->key_used);

	if (lcache_debug)
		ubbd_err("write normal kset: %lu\n", addr);

	backend_index = get_cache_backend(addr);
	backend = cache_backends[backend_index];
	ret = ubbd_backend_write(backend, addr - (backend_index * (cache_sb.segs_per_device << CACHE_SEG_SHIFT)), CACHE_KSET_SIZE, kset_buf);
	if (ret) {
		ubbd_err("failed to write normal kset\n");
		return ret;
	}
	cache_sb.key_head_pos.off_in_seg += space_required;
	key_ondisk_w->key_used = 0;

	return 0;
}

static int cache_key_ondisk_write_all(void)
{
	int i;
	int ret = 0;

	pthread_mutex_lock(&cache_disk_append_mutex);
	for (i = 0; i < cache_sb.num_queues; i++) {
		ret = cache_key_ondisk_write(cache_sb.key_ondisk_w_list[i]);
		if (ret) {
			ubbd_err("failed to write ondisk.\n");
			goto out;
		}
	}
out:
	pthread_mutex_unlock(&cache_disk_append_mutex);

	return ret;
}

static int cache_key_ondisk_append(struct cache_key *key)
{
	int ret;
	struct cache_key_ondisk key_disk;
	struct cache_key_ondisk_write_data *key_ondisk_w;

	cache_key_encode(key, &key_disk);
	key_ondisk_w = cache_sb.key_ondisk_w_list[(key->l_off >> CACHE_KEY_LIST_SHIFT) % cache_sb.num_queues];

	pthread_mutex_lock(&key_ondisk_w->write_lock);
	memcpy(&key_ondisk_w->keys[key_ondisk_w->key_used++], &key_disk, sizeof(struct cache_key_ondisk));

	if (key_ondisk_w->key_used >= CACHE_KEY_WRITE_MAX) {
		pthread_mutex_lock(&cache_disk_append_mutex);
		ret = cache_key_ondisk_write(key_ondisk_w);
		pthread_mutex_unlock(&cache_disk_append_mutex);
		if (ret) {
			ubbd_err("failed to write ondisk key.\n");
		}
	}
	pthread_mutex_unlock(&key_ondisk_w->write_lock);

	return ret;
}

static void cache_key_list_release(struct cache_key *skiplist)
{
	return;
}

static void cache_key_lists_release()
{
	int i;

	for (i = 0; i < cache_key_list_num; i++) {
		cache_key_list_release(&cache_key_lists[i]);
	}

	free(cache_key_lists);
}

static void __cache_key_list_dump(struct cache_key *skiplist, int index)
{
	struct cache_key *key_tmp;
	int i = 0;
	int l = 0;

	return;
	//for (l = USKIPLIST_MAXLEVEL - 1; l >= 0; l--) {
	for (l = 1; l >= 0; l--) {
		ubbd_err("level: %d\n", l);
		i = 0;
		key_tmp = skiplist->node_list[l].next;

		while (key_tmp) {
			if (true || !key_tmp->deleted) {
				ubbd_err("index: %d, l_off: %lu, p_off: %lu, len: %u, deleted: %d\n", i, cache_key_lstart(key_tmp), cache_key_pstart(key_tmp), key_tmp->len, key_tmp->deleted);
				i++;
			}
			key_tmp = key_tmp->node_list[l].next;
		};
		ubbd_err("index: %d\n", i);
	}
}

static void cache_key_list_dump()
{
	int i;

	return;
	for (i = 0; i < cache_key_list_num; i++) {
		struct cache_key *skiplist = &cache_key_lists[i];

		__cache_key_list_dump(skiplist, i);
	}
}

static void seg_used_add(struct cache_key *key);

static int skiplist_find(struct cache_key *skiplist, struct cache_key *key,
		struct cache_key **prev_list, struct cache_key **next_list)
{
	struct cache_key *prev_key, *next_key, *key_tmp;
	int l;
	bool retry = false;

	while (true) {
retry:
		retry = false;
		prev_key = key_tmp = NULL;
		prev_key = skiplist;

		for (l = USKIPLIST_MAXLEVEL - 1; l >= 0; l--) {
			key_tmp = prev_key->node_list[l].next;

			while (true) {
				if (key_tmp == NULL)
					break;

				if (key_tmp->deleted) {
					pthread_mutex_lock(&prev_key->node_list[l].node_lock);
					pthread_mutex_lock(&key_tmp->node_list[l].node_lock);
					if (prev_key->node_list[l].next == key_tmp) {
						next_key = key_tmp->node_list[l].next;
						prev_key->node_list[l].next = next_key;
						pthread_mutex_unlock(&key_tmp->node_list[l].node_lock);
						cache_key_put(key_tmp);
						key_tmp = next_key;
					} else {
						retry = true;
						pthread_mutex_unlock(&key_tmp->node_list[l].node_lock);
					}

					pthread_mutex_unlock(&prev_key->node_list[l].node_lock);
					if (retry)
						goto retry;
					continue;
				}

				if (cache_key_lstart(key_tmp) < cache_key_lstart(key)) {
					prev_key = key_tmp;
					key_tmp = key_tmp->node_list[l].next;
					continue;
				}
				break;
			}
			prev_list[l] = prev_key;
			next_list[l] = key_tmp;
		}
		break;
	}

	return 0;
}

static int skiplist_add(struct cache_key *skiplist, struct cache_key *key)
{
	struct cache_key *prev_list[USKIPLIST_MAXLEVEL] = { 0 }, *next_list[USKIPLIST_MAXLEVEL] = { 0 };
	struct cache_key *prev_key, *next_key, *key_tmp, *key_next, *key_fixup;
	int locked_level = -1;
	bool valid;
	int i, l;
	int ret;

	//ubbd_err("level: %d\n", key->level);

again:
	locked_level = -1;
	memset(prev_list, 0, sizeof(struct cache_key *) * USKIPLIST_MAXLEVEL);
	memset(next_list, 0, sizeof(struct cache_key *) * USKIPLIST_MAXLEVEL);

	ret = skiplist_find(skiplist, key, prev_list, next_list);
	if (ret) {
		ubbd_err("failed to find key\n");
		goto out;
	}

relock:
	for (i = 0; i < key->level; i++) {
		prev_key = prev_list[i];
		next_key = next_list[i];

		if (pthread_mutex_trylock(&prev_key->node_list[i].node_lock)) {
			//ubbd_err("lock conflict\n");
			if (locked_level >= 0 ) {
				for (i = locked_level; i >= 0; i--) {
					prev_key = prev_list[i];
					pthread_mutex_unlock(&prev_key->node_list[i].node_lock);
				}
			}
			locked_level = -1;
			goto relock;
		}

		locked_level = i;
		valid = !prev_key->deleted;
		if (next_key) {
			valid &= !next_key->deleted;
		}
		valid &= prev_key->node_list[i].next == next_key;

		if (!valid) {
			//ubbd_err("invalide\n");
			ret = -EAGAIN;
			goto unlock;;
		}
	}

	/*fix the overlap up*/
	prev_key = prev_list[0];
	next_key = next_list[0];

	key_tmp = prev_key;

	while (true) {
		if (key_tmp == NULL)
			break;

		if (key_tmp == skiplist) {
			goto next;
		}

		if (key_tmp != prev_key) {
			pthread_mutex_lock(&key_tmp->node_list[0].node_lock);
		}

		if (key_tmp->deleted) {
			goto next;
		}

		/*
		 * |----------|
		 *		|=====|
		 * */
		if (cache_key_lend(key_tmp) <= cache_key_lstart(key)) {
			goto next;
		}

		/*
		 *	  |--------|
		 * |====|
		 */
		if (cache_key_lstart(key_tmp) >= cache_key_lend(key)) {
			if (key_tmp != prev_key) {
				pthread_mutex_unlock(&key_tmp->node_list[0].node_lock);
				cache_key_put(key_tmp);
			}
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

				goto next;
			}

			/*
			 *    |----|		key_tmp
			 * |==========|		key
			 */
			cache_key_delete(key_tmp);
			goto next;
		}


		/*
		 * |-----------|	key_tmp
		 *   |====|		key
		 */
		if (cache_key_lend(key_tmp) > cache_key_lend(key)) {
			key_fixup = cache_key_alloc(0);
			if (!key_fixup) {
				ret = -ENOMEM;
				if (key_tmp != prev_key) {
					pthread_mutex_unlock(&key_tmp->node_list[0].node_lock);
					cache_key_put(key_tmp);
				}
				goto unlock;
			}
			key_fixup->deleted = 0;
			key_fixup->fullylinked = 0;

			cache_key_copy(key_fixup, key_tmp);

			cache_key_cutback(key_tmp, cache_key_lend(key_tmp) - cache_key_lstart(key));
			cache_key_cutfront(key_fixup, cache_key_lend(key) - cache_key_lstart(key_tmp));

			for (l = 0; l < key_fixup->level; l++) {
				key_fixup->node_list[l].next = key_tmp->node_list[l].next;
				key_tmp->node_list[l].next = key_fixup;
				next_list[l] = key_fixup;
				cache_key_get(key_fixup);
			}

			key_fixup->fullylinked = 1;

			if (key_tmp != prev_key) {
				pthread_mutex_unlock(&key_tmp->node_list[0].node_lock);
				cache_key_put(key_tmp);
			}
			break;
		}


		/*
		 * |--------|		key_tmp
		 *   |==========|	key
		 */
		cache_key_cutback(key_tmp, cache_key_lend(key_tmp) - cache_key_lstart(key));

next:
		key_next = key_tmp->node_list[0].next;
		cache_key_get(key_next);

		if (key_tmp != prev_key) {
			pthread_mutex_unlock(&key_tmp->node_list[0].node_lock);
			cache_key_put(key_tmp);
		}

		key_tmp = key_next;
	}

	for (i = 0; i < key->level; i++) {
		cache_key_get(key);
		key->node_list[i].next = next_list[i];
		prev_list[i]->node_list[i].next = key;
	}

	key->fullylinked = 1;

	ret = 0;
unlock:
	if (locked_level >= 0 ) {
		for (i = locked_level; i >= 0; i--) {
			prev_key = prev_list[i];
			pthread_mutex_unlock(&prev_key->node_list[i].node_lock);
		}
		locked_level = -1;
	}

	if (ret == -EAGAIN) {
		goto again;
	}

out:
	return ret;

}
static int cache_key_insert(struct cache_key *key)
{
	int ret = 0;
	struct cache_key *skiplist = &cache_key_lists[key->l_off >> CACHE_KEY_LIST_SHIFT];

	seg_used_add(key);

	if ((key->l_off & CACHE_KEY_LIST_MASK) + key->len > CACHE_KEY_LIST_SIZE)
		ubbd_err("insert l_off: %lu, p_off: %lu, len: %u.\n", key->l_off, key->p_off, key->len);

	ret = skiplist_add(skiplist, key);

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
			//dump_bitmap(cache_sb.seg_bitmap);
			continue;
		}

		ubbd_bit_set(cache_sb.seg_bitmap, seg);
		//dump_bitmap(cache_sb.seg_bitmap);

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
				cache_key_put(key);
				goto err;
			}
		}
		off_in_seg += kset_disk->kset_len;
	}

	cache_sb.key_head_pos.seg = seg;
	cache_sb.key_head_pos.off_in_seg = off_in_seg;
	ubbd_bit_set(cache_sb.seg_bitmap, seg);

	if (!cache_key_written) {
		cache_key_ondisk_write_all();
		cache_key_written = true;
		goto again;
	}

	//dump_bitmap(cache_sb.seg_bitmap);

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

	pthread_mutex_lock(&sb_write_lock);
	sb->magic = CACHE_SB_MAGIC;
	sb->n_segs = cache_sb.n_segs;
	sb->key_tail_seg = cache_sb.key_tail_pos.seg;
	sb->tail_off_in_seg = cache_sb.key_tail_pos.off_in_seg;
	sb->dirty_tail_seg = cache_sb.dirty_tail_pos.seg;
	sb->dirty_tail_off_in_seg = cache_sb.dirty_tail_pos.off_in_seg;
	sb->last_key_epoch = cache_sb.last_key_epoch;

	ret = ubbd_backend_write(cache_backend, CACHE_SB_OFF, CACHE_SB_SIZE, sb_buf);

	pthread_mutex_unlock(&sb_write_lock);

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
			//dump_bitmap(cache_sb.seg_bitmap);

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
			cache_key_put(key);
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
				cache_key_put(key);
				break;
			}

			ret = ubbd_backend_write(backing_backend, key->l_off, key->len, writeback_buf);
			if (ret) {
				ubbd_err("failed to write data to backing in writeback.\n");
				cache_key_put(key);
				break;
			}

			cache_key_put(key);
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
	int l;
	struct cache_key *key;

	cache_key_list_num = size >> CACHE_KEY_LIST_SHIFT;
	if (size % CACHE_KEY_LIST_MASK)
		cache_key_list_num++;

	cache_key_lists = calloc(cache_key_list_num, sizeof(struct cache_key));
	if (!cache_key_lists) {
		ubbd_err("failed to allocate memory for cache_key_lists.\n");
		return -ENOMEM;
	}

	for (i = 0; i < cache_key_list_num; i++) {
		key = &cache_key_lists[i];
		for (l = 0; l < USKIPLIST_MAXLEVEL; l++) {
			pthread_mutex_init(&key->node_list[l].node_lock, NULL);
		}
	}

	return 0;
}

struct cache_backend_io_ctx_data {
	struct ubbd_backend *ubbd_b;
	struct ubbd_backend_io *io;
	struct ubbd_backend_io *orig_io;
	uint64_t backing_off;
	bool cache_io;
	struct cache_key *key;
};


static int cache_backend_open(struct ubbd_backend *ubbd_b)
{
	int ret = 0;
	struct ubbd_cache_backend *cache_b = CACHE_BACKEND(ubbd_b);
	struct cache_super_ondisk *sb;
	char *verify_name;

	ubbd_err("sizeof(cache_key): %ld\n", sizeof(struct cache_key));
	cache_key_lists_init(ubbd_b);

	cache_b->backing_backend->num_queues = 1;
	ret = ubbd_backend_open(cache_b->backing_backend);
	if (ret) {
		return ret;
	}

	int i = 0;
	for (i = 0; i < 1; i++) {
		cache_b->cache_backends[i]->num_queues = ubbd_b->num_queues;

		ret = ubbd_backend_open(cache_b->cache_backends[i]);
		if (ret) {
			goto close_backing;
		}
		cache_backends[i] = cache_b->cache_backends[i];
	}

	cache_backend = cache_b->cache_backends[0];
	cache_b->cache_backend = cache_backend;
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
		sb->n_segs = ubbd_backend_size(cache_b->cache_backends[0]) / CACHE_SEG_SIZE * 1;

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
	cache_sb.segs_per_device = cache_sb.n_segs / 1;
	cache_sb.num_queues = ubbd_b->num_queues;

	cache_sb.key_ondisk_w_list = calloc(cache_sb.num_queues, sizeof(struct cache_kset_ondisk_write_data *));
	if (!cache_sb.key_ondisk_w_list) {
		ubbd_err("failed to alloc \n");
		goto close_cache;
	}

	for (i = 0; i < cache_sb.num_queues; i++) {
		ret = ubbd_open_kring(&ubbd_b->queues[i].kring_info);
		if (ret) {
			ubbd_err("failed to open kring for queue 0: %d\n", ret);
			goto close_cache;
		}
	}

	cache_sb.ctx_pools = calloc(ubbd_b->num_queues, sizeof(struct ubbd_mempool *));
	if (!cache_sb.ctx_pools) {
		goto close_cache;
	}

	for (i = 0; i < ubbd_b->num_queues; i++) {
		cache_sb.ctx_pools[i] = ubbd_mempool_alloc(sizeof(struct context) + sizeof(struct cache_backend_io_ctx_data), 10240);
		if (!cache_sb.ctx_pools[i]) {
			ubbd_err("failed to alloc mempool for ctxpool.\n");
			goto close_cache;
		}
	}

	cache_sb.key_pools = calloc(ubbd_b->num_queues, sizeof(struct cache_key_pool));
	if (!cache_sb.key_pools) {
		goto close_cache;
	}

	for (i = 0; i < ubbd_b->num_queues; i++) {
		cache_sb.key_pools[i].key_pool = ubbd_unlimited_mempool_alloc(sizeof(struct cache_key), 10240);
		if (!cache_sb.key_pools[i].key_pool) {
			ubbd_err("failed to alloc mempool for keypool.\n");
			goto close_cache;
		}
		ubbd_atomic_set(&cache_sb.key_pools[i].seq, 0);
	}

	for (i = 0; i < cache_sb.num_queues; i++) {
		cache_sb.key_ondisk_w_list[i] = ubbd_kring_get_info(&ubbd_b->queues[i].kring_info);
		pthread_mutex_init(&cache_sb.key_ondisk_w_list[i]->write_lock, NULL);
	}

	cache_sb.segments = calloc(cache_sb.n_segs, sizeof(struct segment));
	if (!cache_sb.segments) {
		ubbd_err("failed to alloc mem for segments.\n");
		ret = -ENOMEM;
		goto close_cache;
	}

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
	//dump_bitmap(cache_sb.seg_bitmap);


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
	int i;

	cache_key_ondisk_write_all();

	if (cache_b->detach_on_close) {
		wait_for_cache_clean(cache_b);
	}

	cache_stop_gc();
	cache_stop_writeback();

	cache_key_lists_release();
	ubbd_bitmap_free(cache_sb.seg_bitmap);
	free(cache_sb.segments);
	for (i = 0; i < cache_sb.num_queues; i++) {
		ubbd_close_kring(&ubbd_b->queues[i].kring_info);
	}

	for (i = 0; i < 1; i++) {
		ubbd_backend_close(cache_b->cache_backends[i]);
	}

	ubbd_backend_close(cache_b->backing_backend);
}

static void cache_backend_release(struct ubbd_backend *ubbd_b)
{
	struct ubbd_cache_backend *cache_b = CACHE_BACKEND(ubbd_b);
	int i;

	if (!cache_b)
		return;

	for (i = 0; i < 1; i++) {
		ubbd_backend_release(cache_b->cache_backends[i]);
	}

	if (cache_b->backing_backend)
		ubbd_backend_release(cache_b->backing_backend);

	free(cache_b);
}

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
		cache_key_put(key);
		goto finish;
	}

	if (verify) {
		ret = pwritev(verify_fd, orig_io->iov, orig_io->iov_cnt, orig_io->offset);
		if (ret != orig_io->len) {
			ubbd_err("error to write verify: %d\n", ret);
		}
	}

	ret = 0;

	cache_key_ondisk_append(key);
finish:
	if (lcache_debug)
		ubbd_err("finish cache write: %lu\n", io->offset >> CACHE_SEG_SHIFT);

	cache_seg_put(io->offset >> CACHE_SEG_SHIFT);
	ubbd_backend_free_backend_io(data->ubbd_b, io);;
	ubbd_backend_io_finish(orig_io, ret);
	ubbd_mempool_put(ctx);

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
	ubbd_mempool_put(ctx);

	return 0;
}

static struct ubbd_backend_io* prepare_backend_io(struct ubbd_backend *ubbd_b,
		struct ubbd_backend_io *io,
		uint64_t off, uint32_t size, ubbd_ctx_finish_t finish_fn)
{
	struct ubbd_backend_io *clone_io;
	struct cache_backend_io_ctx_data *data;
	int bit;

	clone_io = ubbd_backend_io_clone(ubbd_b, io, off, size);
	if (!clone_io) {
		ubbd_err("failed to clone backend_io\n");
		return NULL;
	}

	bit = ubbd_mempool_get(cache_sb.ctx_pools[io->queue_id], (void **)(&clone_io->ctx));
	if (bit == -1) {
		ubbd_err("failed to alloc ctx for clone io\n");
		ubbd_backend_free_backend_io(ubbd_b, clone_io);;
		return NULL;
	}

	context_init(clone_io->ctx);
	clone_io->ctx->finish = finish_fn;
	clone_io->ctx->free_on_finish = 0;
	clone_io->ctx->from_pool = 1;

	data = (struct cache_backend_io_ctx_data *)clone_io->ctx->data;
	context_get(io->ctx);
	data->io = clone_io;
	data->orig_io = io;
	data->ubbd_b = ubbd_b;

	return clone_io;
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
		//dump_bitmap(cache_sb.seg_bitmap);
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

static int get_cache_backend(uint64_t off)
{
	return (off >> CACHE_SEG_SHIFT) / cache_sb.segs_per_device;
}

static int cache_backend_writev(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct ubbd_cache_backend *cache_b = CACHE_BACKEND(ubbd_b);
	struct ubbd_backend_io *cache_io;
	struct ubbd_backend *backend;
	int backend_index = 0;
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

		key = cache_key_alloc(io->queue_id);
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
			cache_key_put(key);
			goto finish;
		}

		if (!key->len) {
			ubbd_err("len of key is 0\n");
			cache_key_put(key);
			continue;
		}

		backend_index = get_cache_backend(key->p_off);
		backend = cache_b->cache_backends[backend_index];

		cache_io = prepare_backend_io(backend, io, io_done, key->len, cache_backend_write_io_finish);
		if (!cache_io) {
			cache_key_put(key);
			ret = -ENOMEM;
			goto finish;
		}
		cache_io->offset = key->p_off - (backend_index * (cache_sb.segs_per_device << CACHE_SEG_SHIFT));

		struct cache_backend_io_ctx_data *data;

		data = (struct cache_backend_io_ctx_data *)cache_io->ctx->data;
		data->cache_io = true;
		data->key = key;
		cache_seg_get(key->p_off >> CACHE_SEG_SHIFT);

		if (lcache_debug)
			ubbd_err("submit write cache io: %lu:%u seg: %lu\n",
					cache_io->offset, cache_io->len,
					cache_io->offset >> CACHE_SEG_SHIFT);

		ret = backend->backend_ops->writev(backend, cache_io);

		if (ret) {
			ubbd_err("cache io failed.\n");
			cache_seg_put(key->p_off >> CACHE_SEG_SHIFT);
			cache_key_put(key);
			goto finish;
		}

		io_done += key->len;
	}

write_backing:
	if (writearound) {
		struct ubbd_backend_io *backing_io;
		backing_io = prepare_backend_io(backing_backend, io, 0, io->len, cache_backend_read_io_finish);
		if (lcache_debug)
			ubbd_err("submit write backing io: %lu:%u crc: %lu, iov_len: %lu, iocnt: %d\n",
					backing_io->offset, backing_io->len,
					crc64(backing_io->iov[0].iov_base, backing_io->iov[0].iov_len),
					backing_io->iov[0].iov_len, backing_io->iov_cnt);

		ret = backing_backend->backend_ops->writev(backing_backend, backing_io);
		if (ret) {
			ubbd_err("failed to submit backing io\n");
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
	int backend_index = 0;
	struct ubbd_backend *backend;

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
			__cache_key_list_dump(&cache_key_lists[backing_off >> CACHE_KEY_LIST_SHIFT], backing_off >> CACHE_KEY_LIST_SHIFT);
		}
	}

	backend_index = get_cache_backend(cache_off);
	backend = cache_backends[backend_index];
	cache_io = prepare_backend_io(backend, io, off, len, cache_backend_read_io_finish);
	if (!cache_io) {
		ret = -ENOMEM;
		goto out;
	}
	cache_io->offset = cache_off - (backend_index * (cache_sb.segs_per_device << CACHE_SEG_SHIFT));

	data = (struct cache_backend_io_ctx_data *)cache_io->ctx->data;
	data->backing_off = backing_off;
	if (lcache_debug) {
		ubbd_err("submit cache io: %lu:%u seg: %lu, logic off: %lu:%u\n",
				cache_io->offset, cache_io->len, cache_io->offset >> CACHE_SEG_SHIFT,
				backing_off, len);
	}

	cache_seg_get(cache_io->offset >> CACHE_SEG_SHIFT);
	data->cache_io = true;
	ret = backend->backend_ops->readv(backend, cache_io);
out:
	return ret;
}


static int cache_backend_readv(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	int ret = 0;
	struct cache_key *prev_list[USKIPLIST_MAXLEVEL] = { 0 }, *next_list[USKIPLIST_MAXLEVEL] = { 0 };
	struct cache_key key_data = { .l_off = io->offset, .len = io->len };
	struct cache_key *key = &key_data;
	uint32_t io_done = 0, total_io_done = 0;
	struct cache_key *skiplist;
	struct cache_key *key_tmp, *key_next, *prev_key;
	uint32_t io_len;


next_skiplist:
	io_done = 0;
	key->l_off = io->offset + total_io_done;
	key->len = io->len - total_io_done;

	if (key->len > CACHE_KEY_LIST_SIZE - (key->l_off & CACHE_KEY_LIST_MASK))
		key->len = CACHE_KEY_LIST_SIZE - (key->l_off & CACHE_KEY_LIST_MASK);

	skiplist = &cache_key_lists[key->l_off >> CACHE_KEY_LIST_SHIFT];

	ret = skiplist_find(skiplist, key, prev_list, next_list);
	if (ret) {
		printf("failed to find key\n");
		goto out;
	}

	prev_key = prev_list[0];
	key_tmp = prev_key;

	while (true) {
		if (key_tmp == NULL)
			break;

		if (io_done >= io->len)
			break;;

		if (key_tmp != prev_key) {
			pthread_mutex_lock(&key_tmp->node_list[0].node_lock);
		}

		if (lcache_debug)
			ubbd_err("gen: %lu, key_gen: %lu, seg: %lu, l_off: %lu\n",
					cache_key_seg(key_tmp)->gen, key_tmp->seg_gen,
					key_tmp->p_off >> CACHE_SEG_SHIFT, key_tmp->l_off);

		if (key_tmp->deleted) {
			goto next;
		}

		if (key_tmp->seg_gen < cache_key_seg(key_tmp)->gen) {
			cache_key_delete(key_tmp);
			goto next;
		}
		/*
		 * |----------|
		 *		|=====|
		 * */
		if (cache_key_lend(key_tmp) <= cache_key_lstart(key)) {
			goto next;
		}

		/*
		 *	  |--------|
		 * |====|
		 */
		if (cache_key_lstart(key_tmp) >= cache_key_lend(key)) {
			submit_backing_io(io, total_io_done + io_done, key->len);
			io_done += key->len;
			cache_key_cutfront(key, key->len);

			if (key_tmp != prev_key) {
				pthread_mutex_unlock(&key_tmp->node_list[0].node_lock);
				cache_key_put(key_tmp);
			}
			break;
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
				if (key_tmp != prev_key) {
					pthread_mutex_unlock(&key_tmp->node_list[0].node_lock);
					cache_key_put(key_tmp);
				}
				break;
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
			goto next;
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
			if (key_tmp != prev_key) {
				pthread_mutex_unlock(&key_tmp->node_list[0].node_lock);
				cache_key_put(key_tmp);
			}
			break;
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
next:
		key_next = key_tmp->node_list[0].next;
		cache_key_get(key_next);

		if (key_tmp != prev_key) {
			pthread_mutex_unlock(&key_tmp->node_list[0].node_lock);
			cache_key_put(key_tmp);
		}

		key_tmp = key_next;
	}

	submit_backing_io(io, total_io_done + io_done, key->len);
	io_done += key->len;

	total_io_done += io_done;
	io_done = 0;

	if (!ret && total_io_done < io->len)
		goto next_skiplist;

out:
	ubbd_backend_io_finish(io, ret);

	return 0;
}

static int cache_backend_flush(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct ubbd_cache_backend *cache_b = CACHE_BACKEND(ubbd_b);

	cache_key_ondisk_write_all();
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
