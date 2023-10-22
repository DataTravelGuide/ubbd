#include "cache_backend_internal.h"

static void skiplist_node_add(struct skiplist_node *prev_node, struct skiplist_node *node, int level)
{
	node->next[level] = prev_node->next[level];
	prev_node->next[level] = node;
}

static void skiplist_node_del(struct skiplist_node *prev_node, struct skiplist_node *node, int level)
{
	if (prev_node->next[level] != node) {
		ubbd_err("node is not the next item of prev_node for level: %d\n", level);
		BUG_ON(1, "Logic Error\n");
	}

	prev_node->next[level] = node->next[level];
}

void cache_key_list_add(struct cache_key *prev_key, struct cache_key *key, int level)
{
	cache_key_get(key);
	skiplist_node_add(&prev_key->node, &key->node, level);
}

void cache_key_list_delete(struct cache_key *prev_key, struct cache_key *key, int level)
{
	skiplist_node_del(&prev_key->node, &key->node, level);
	cache_key_put(key);
}

static void cache_key_list_release(struct skiplist_head *skiplist)
{
	struct cache_key *key_tmp = NULL;
	struct skiplist_node *node_tmp;
	int l;

	for (l = USKIPLIST_MAXLEVEL - 1; l >= 0; l--) {
		while (true) {
			node_tmp = skiplist->node.next[l];
			if (node_tmp == NULL)
				break;

			key_tmp = CACHE_KEY(node_tmp);

			skiplist_node_del(&skiplist->node, node_tmp, l);
			cache_key_put(key_tmp);

			/* Check ref for the last link delete */
			if (l == 0) {
				BUG_ON(ubbd_atomic_read(&key_tmp->ref) != 0,
						"Reference Leak!!!");
			}
		}
	}

	return;
}

static void cache_key_lists_release(struct ubbd_cache_backend *cache_b)
{
	int i;

	for (i = 0; i < cache_b->cache_key_list_num; i++) {
		cache_key_list_release(&cache_b->cache_key_lists[i]);
	}

	free(cache_b->cache_key_lists);
}

static int cache_key_lists_init(struct ubbd_cache_backend *cache_b)
{
	cache_b->cache_key_list_num = cache_b->size >> CACHE_KEY_LIST_SHIFT;
	if (cache_b->size % CACHE_KEY_LIST_MASK)
		cache_b->cache_key_list_num++;

	cache_b->cache_key_lists = calloc(cache_b->cache_key_list_num, sizeof(struct skiplist_head));
	if (!cache_b->cache_key_lists) {
		ubbd_err("failed to allocate memory for cache_key_lists.\n");
		return -ENOMEM;
	}

	return 0;
}

static int cache_replay_keys(struct ubbd_cache_backend *cache_b)
{
	char kset_buf[CACHE_KSET_SIZE] __attribute__ ((__aligned__ (4096)));
	uint64_t seg = cache_b->cache_sb.key_tail_pos.seg;
	uint32_t off_in_seg = cache_b->cache_sb.key_tail_pos.off_in_seg;
	uint64_t addr;
	struct cache_kset_ondisk *kset_disk;
	struct cache_key_ondisk *key_disk;
	struct cache_key *key = NULL;
	int i;
	int ret = 0;
	uint32_t key_epoch;
	bool key_epoch_found = false;
	bool cache_key_written = false;

	while (true) {
again:
		addr = seg * CACHE_SEG_SIZE + off_in_seg; 
		ret = ubbd_backend_read(cache_b->cache_backend, addr, CACHE_KSET_SIZE, kset_buf);
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
				ret = -EFAULT;
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
			ubbd_bit_set(cache_b->cache_sb.seg_bitmap, seg);
			continue;
		}

		ubbd_bit_set(cache_b->cache_sb.seg_bitmap, seg);

		for (i = 0; i < kset_disk->keys; i++) {
			key_disk = &kset_disk->data[i];
			key = cache_key_decode(cache_b, key_disk);
			if (!key) {
				ret = -ENOMEM;
				goto err;
			}

			if (cache_key_seg(cache_b, key)->gen < key->seg_gen)
				cache_key_seg(cache_b, key)->gen = key->seg_gen;

			ret = cache_key_insert(cache_b, key);
			cache_key_put(key);
			if (ret) {
				goto err;
			}
		}
		off_in_seg += kset_disk->kset_len;
	}

	cache_b->cache_sb.key_head_pos.seg = seg;
	cache_b->cache_sb.key_head_pos.off_in_seg = off_in_seg;
	ubbd_bit_set(cache_b->cache_sb.seg_bitmap, seg);

	if (!cache_key_written) {
		cache_key_ondisk_write_all(cache_b);
		cache_key_written = true;
		goto again;
	}
err:
	return ret;
}

static void ondisk_w_list_release(struct ubbd_cache_backend *cache_b)
{
	struct ubbd_backend *ubbd_b = &cache_b->ubbd_b;
	int i;

	for (i = 0; i < cache_b->cache_sb.num_queues; i++) {
		ubbd_close_kring(&ubbd_b->queues[i].kring_info);
	}
	free(cache_b->cache_sb.key_ondisk_w_list);
}

static int ondisk_w_list_init(struct ubbd_cache_backend *cache_b)
{
	struct ubbd_backend *ubbd_b = &cache_b->ubbd_b;
	int ret;
	int i;

	cache_b->cache_sb.key_ondisk_w_list = calloc(cache_b->cache_sb.num_queues,
			sizeof(struct cache_kset_ondisk_write_data *));

	if (!cache_b->cache_sb.key_ondisk_w_list) {
		ret = -ENOMEM;
		ubbd_err("failed to alloc key_ondisk_w_list\n");
		goto out;
	}

	for (i = 0; i < cache_b->cache_sb.num_queues; i++) {
		ret = ubbd_open_kring(&ubbd_b->queues[i].kring_info);
		if (ret) {
			ubbd_err("failed to open kring for queue 0: %d\n", ret);
			goto list_release;
		}
		cache_b->cache_sb.key_ondisk_w_list[i] = ubbd_kring_get_info(&ubbd_b->queues[i].kring_info);
		pthread_mutex_init(&cache_b->cache_sb.key_ondisk_w_list[i]->write_lock, NULL);
	}
	return 0;

list_release:
	ondisk_w_list_release(cache_b);
out:
	return ret;
}

static void key_pools_release(struct ubbd_cache_backend *cache_b)
{
	struct ubbd_backend *ubbd_b = &cache_b->ubbd_b;
	int i;

	for (i = 0; i < ubbd_b->num_queues; i++) {
		if (cache_b->cache_sb.key_pools[i].key_pool)
			ubbd_mempool_free(cache_b->cache_sb.key_pools[i].key_pool);
	}
	free(cache_b->cache_sb.key_pools);
}

static int key_pools_init(struct ubbd_cache_backend *cache_b)
{
	struct ubbd_backend *ubbd_b = &cache_b->ubbd_b;
	int i;
	int ret;

	cache_b->cache_sb.key_pools = calloc(ubbd_b->num_queues, sizeof(struct cache_key_pool));
	if (!cache_b->cache_sb.key_pools) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < ubbd_b->num_queues; i++) {
		cache_b->cache_sb.key_pools[i].key_pool = ubbd_unlimited_mempool_alloc(sizeof(struct cache_key), 10240);
		if (!cache_b->cache_sb.key_pools[i].key_pool) {
			ret = -ENOMEM;
			ubbd_err("failed to alloc mempool for keypool.\n");
			goto key_pools_release;
		}
		ubbd_atomic_set(&cache_b->cache_sb.key_pools[i].seq, 0);
	}

	return 0;

key_pools_release:
	key_pools_release(cache_b);
out:
	return ret;
}

int cache_backend_key_init(struct ubbd_cache_backend *cache_b)
{
	int ret;

	ret = ondisk_w_list_init(cache_b);
	if (ret < 0) {
		goto out;
	}

	ret = key_pools_init(cache_b);
	if (ret < 0) {
		goto w_list_release;
	}

	ret = cache_key_lists_init(cache_b);
	if (ret < 0) {
		ubbd_err("failed to init key_lists\n");
		goto release_key_pools;
	}

	ret = cache_replay_keys(cache_b);
	if (ret) {
		goto key_lists_release;
	}

	if (cache_b->lcache_debug)
		cache_key_list_dump(cache_b);

	return 0;

key_lists_release:
	cache_key_lists_release(cache_b);
release_key_pools:
	key_pools_release(cache_b);
w_list_release:
	ondisk_w_list_release(cache_b);
out:
	return ret;
}

void cache_backend_key_exit(struct ubbd_cache_backend *cache_b)
{
	cache_key_lists_release(cache_b);
	key_pools_release(cache_b);
	ondisk_w_list_release(cache_b);
}

static void cache_key_print(struct cache_key *key_tmp)
{
	ubbd_info("l_off: %lu, p_off: %lu, len: %u, deleted: %d\n",
			cache_key_lstart(key_tmp), cache_key_pstart(key_tmp),
			key_tmp->len, key_tmp->deleted);
}

static int __cache_key_list_dump(struct skiplist_head *skiplist, int index)
{
	struct cache_key *key_tmp, *prev_key = NULL, *cur_key = NULL;
	struct skiplist_node *node;

	node = skiplist->node.next[index];
	while (true) {
		if (node == NULL)
			break;

		key_tmp = CACHE_KEY(node);
		if (!key_tmp->deleted) {
			cache_key_print(key_tmp);

			if (prev_key && cache_key_lend(prev_key) > cache_key_lstart(key_tmp)) {
				ubbd_err("error key_tmp: %lu\n", cache_key_lstart(key_tmp));
				cache_key_print(prev_key);
				cache_key_print(key_tmp);
			}
			prev_key = cur_key;
			cur_key = key_tmp;
		}
		node = node->next[index];
	}

	return 0;
}

void cache_key_list_dump(struct ubbd_cache_backend *cache_b)
{
	int i;

	for (i = 0; i < cache_b->cache_key_list_num; i++) {
		struct skiplist_head *skiplist = &cache_b->cache_key_lists[i];

		__cache_key_list_dump(skiplist, i);
	}
}


int skiplist_add(struct ubbd_cache_backend *cache_b, struct skiplist_head *skiplist, struct cache_key *key)
{
	struct skiplist_node *prev_list[USKIPLIST_MAXLEVEL] = { 0 }, *next_list[USKIPLIST_MAXLEVEL] = { 0 };
	struct cache_key *prev_key, *key_tmp, *key_fixup;
	struct skiplist_node *prev_node, *next_node, *node_tmp;
	int i, l;
	int ret;

	ret = skiplist_find(skiplist, key, prev_list, next_list);
	if (ret) {
		ubbd_err("failed to find key\n");
		goto out;
	}

	/*fix the overlap up*/
	prev_node = prev_list[0];
	node_tmp = prev_node;

	while (true) {
		if (node_tmp == NULL)
			break;

		if (node_tmp == &skiplist->node) {
			goto next;
		}

		key_tmp = CACHE_KEY(node_tmp);
		if (key_tmp->deleted || key_tmp->len == 0) {
			if (next_list[0] == node_tmp) {
				next_list[0] = node_tmp->next[0];
				skiplist_node_del(prev_node, node_tmp, 0);
				cache_key_put(key_tmp);
			}
			goto next;
		}

		/*
		 * |----------|
		 *		|=====|
		 * */
		if (cache_key_lend(key_tmp) <= cache_key_lstart(key)) {
			/* key_tmp must be prev_key */
			if (node_tmp != prev_node) {
				ubbd_err("prev_key changed after skiplist_find().\n");
				BUG_ON(1, "Logic error\n");
			}
			goto next;
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
					if (next_list[0] == node_tmp) {
						next_list[0] = node_tmp->next[0];
						skiplist_node_del(prev_node, node_tmp, 0);
						cache_key_put(key_tmp);
					}
				}

				goto next;
			}

			/*
			 *    |----|		key_tmp
			 * |==========|		key
			 */
			cache_key_delete(key_tmp);
			if (next_list[0] == node_tmp) {
				next_list[0] = node_tmp->next[0];
				skiplist_node_del(prev_node, node_tmp, 0);
				cache_key_put(key_tmp);
			}

			goto next;
		}

		/*
		 * |-----------|	key_tmp
		 *   |====|		key
		 */
		if (cache_key_lend(key_tmp) > cache_key_lend(key)) {
			key_fixup = cache_key_alloc(cache_b, 0);
			if (!key_fixup) {
				ret = -ENOMEM;
				goto out;
			}
			key_fixup->deleted = 0;
			key_fixup->fullylinked = 0;

			cache_key_copy(key_fixup, key_tmp);

			cache_key_cutback(key_tmp, cache_key_lend(key_tmp) - cache_key_lstart(key));
			cache_key_cutfront(key_fixup, cache_key_lend(key) - cache_key_lstart(key_tmp));

			for (l = 0; l < key_fixup->level; l++) {
				cache_key_list_add(key_tmp, key_fixup, l);
				/* update next_list */
				next_list[l] = &key_fixup->node;
			}

			key_fixup->fullylinked = 1;
			cache_key_put(key_fixup);
			break;
		}

		/*
		 * |--------|		key_tmp
		 *   |==========|	key
		 */
		cache_key_cutback(key_tmp, cache_key_lend(key_tmp) - cache_key_lstart(key));
next:
		next_node = node_tmp->next[0];
		if (next_node == NULL)
			break;
		node_tmp = next_node;
	}

	for (i = 0; i < key->level; i++) {
		if (cache_b->lcache_debug) {
			if (prev_list[i]->next[i] != next_list[i]) {
				ubbd_err("error list is changed. prev: %p next: %p, next_list: %p\n",
						prev_list[i], prev_list[i]->next[i], next_list[i]);
				BUG_ON(1, "Logic Error.");
			}

			if (prev_list[i] != &skiplist->node) {
				prev_key = CACHE_KEY(prev_list[i]);

				if ((cache_key_lstart(prev_key) != 0 && cache_key_lstart(prev_key) >= cache_key_lstart(key))) {
					ubbd_err("error key list changed at %d\n", i);
					cache_key_print(prev_key);
					cache_key_print(key);
				}
			}
		}

		skiplist_node_add(prev_list[i], &key->node, i);
		cache_key_get(key);
	}
	key->fullylinked = 1;

	ret = 0;
out:
	return ret;

}

int skiplist_find(struct skiplist_head *skiplist, struct cache_key *key,
		struct skiplist_node **prev_list, struct skiplist_node **next_list)
{
	struct cache_key *key_tmp;
	struct skiplist_node *prev_node, *next_node, *node_tmp;
	int l;
	bool retry = false;

	while (true) {
retry:
		retry = false;
		prev_node = node_tmp = NULL;
		prev_node = &skiplist->node;

		for (l = USKIPLIST_MAXLEVEL - 1; l >= 0; l--) {
			node_tmp = prev_node->next[l];
			while (true) {
				if (node_tmp == NULL)
					break;

				key_tmp = container_of(node_tmp, struct cache_key, node);
				if (key_tmp->deleted || key_tmp->len == 0) {
					cache_key_delete(key_tmp);
					if (prev_node->next[l] == node_tmp) {
						next_node = node_tmp->next[l];

						skiplist_node_del(prev_node, node_tmp, l);
						cache_key_put(key_tmp);

						node_tmp = next_node;
					} else {
						retry = true;
					}

					if (retry)
						goto retry;
					continue;
				}

				if (cache_key_lstart(key_tmp) < cache_key_lstart(key)) {
					prev_node = node_tmp;
					node_tmp = prev_node->next[l];
					continue;
				}
				break;
			}
			prev_list[l] = prev_node;
			next_list[l] = node_tmp;
		}
		break;
	}

	return 0;
}

static int cache_key_ondisk_write(struct ubbd_cache_backend *cache_b, struct cache_key_ondisk_write_data *key_ondisk_w)
{
	char kset_buf[CACHE_KSET_SIZE] __attribute__ ((__aligned__ (4096))) = { 0 };
	struct cache_kset_ondisk *kset = (struct cache_kset_ondisk *)kset_buf;
	uint64_t addr, space_required;
	uint64_t next_seg;
	int backend_index = 0;
	struct ubbd_backend *backend;
	int ret;

	if (!key_ondisk_w->key_used)
		return 0;

	if (cache_b->lcache_debug)
		ubbd_err("key_used: %d\n", key_ondisk_w->key_used);
again:
	addr = seg_pos_to_addr(&cache_b->cache_sb.key_head_pos);
	memset(kset_buf, 0, CACHE_KSET_SIZE);

	space_required = sizeof(struct cache_kset_ondisk) +
		key_ondisk_w->key_used * sizeof(struct cache_key_ondisk);

	if (cache_b->lcache_debug)
		ubbd_err("space_required: %lu, key_used: %u\n", space_required, key_ondisk_w->key_used);

	space_required = ubbd_roundup(space_required, 4096);

	/* reserve 4096 for each segment for last kset */
	if (CACHE_SEG_SIZE - cache_b->cache_sb.key_head_pos.off_in_seg - 4096 < space_required) {
		/* there is no enough free space */
		kset->magic = CACHE_KSET_MAGIC;
		kset->version = 0;
		kset->kset_len = 4096;
		kset->key_epoch = cache_b->cache_sb.last_key_epoch;
		kset->flags |= CACHE_KSET_FLAGS_LASTKSET;
		pthread_mutex_lock(&cache_b->cache_sb.bitmap_lock);
		ret = ubbd_bit_find_next_zero(cache_b->cache_sb.seg_bitmap, random() % cache_b->cache_sb.n_segs, &next_seg);
		if (ret) {
			pthread_mutex_unlock(&cache_b->cache_sb.bitmap_lock);
			ubbd_err("cant find segment for data\n");
			return ret;
		}
		cache_b->cache_sb.last_bit = next_seg;
		kset->next_seg = next_seg;
		ubbd_bit_set(cache_b->cache_sb.seg_bitmap, next_seg);
		pthread_mutex_unlock(&cache_b->cache_sb.bitmap_lock);

		//dump_bitmap(cache_b->cache_sb.seg_bitmap);
		backend_index = get_cache_backend(cache_b, addr);
		backend = cache_b->cache_backends[backend_index];
		ret = ubbd_backend_write(backend, addr - (backend_index * (cache_b->cache_sb.segs_per_device << CACHE_SEG_SHIFT)), 4096, kset_buf);
		if (ret) {
			ubbd_err("failed to write last kset\n");
			return ret;
		}
		cache_b->cache_sb.key_head_pos.seg = next_seg;
		cache_b->cache_sb.key_head_pos.off_in_seg = 0;;
		cache_b->cache_sb.last_key_epoch++;
		if (cache_b->lcache_debug)
			ubbd_err("new key seg: %lu, epoch: %u\n", next_seg, cache_b->cache_sb.last_key_epoch);

		cache_sb_write(cache_b);
		goto again;
	}

	kset->magic = CACHE_KSET_MAGIC;
	kset->version = 0;
	kset->keys = key_ondisk_w->key_used;
	kset->kset_len = space_required;
	kset->key_epoch = cache_b->cache_sb.last_key_epoch;
	memcpy(kset->data, key_ondisk_w->keys, sizeof(struct cache_key_ondisk) * key_ondisk_w->key_used);

	if (cache_b->lcache_debug)
		ubbd_err("write normal kset: %lu\n", addr);

	backend_index = get_cache_backend(cache_b, addr);
	backend = cache_b->cache_backends[backend_index];
	ret = ubbd_backend_write(backend, addr - (backend_index * (cache_b->cache_sb.segs_per_device << CACHE_SEG_SHIFT)), CACHE_KSET_SIZE, kset_buf);
	if (ret) {
		ubbd_err("failed to write normal kset\n");
		return ret;
	}
	cache_b->cache_sb.key_head_pos.off_in_seg += space_required;
	key_ondisk_w->key_used = 0;

	return 0;
}

int cache_key_ondisk_write_all(struct ubbd_cache_backend *cache_b)
{
	int i;
	int ret = 0;

	pthread_mutex_lock(&cache_b->cache_disk_append_mutex);
	for (i = 0; i < cache_b->cache_sb.num_queues; i++) {
		ret = cache_key_ondisk_write(cache_b, cache_b->cache_sb.key_ondisk_w_list[i]);
		if (ret) {
			ubbd_err("failed to write ondisk.\n");
			goto out;
		}
	}
out:
	pthread_mutex_unlock(&cache_b->cache_disk_append_mutex);

	return ret;
}

int cache_key_ondisk_append(struct ubbd_cache_backend *cache_b, struct cache_key *key)
{
	int ret = 0;
	struct cache_key_ondisk key_disk;
	struct cache_key_ondisk_write_data *key_ondisk_w;

	cache_key_encode(key, &key_disk);
	key_ondisk_w = cache_b->cache_sb.key_ondisk_w_list[(key->l_off >> CACHE_KEY_LIST_SHIFT) % cache_b->cache_sb.num_queues];

	pthread_mutex_lock(&key_ondisk_w->write_lock);
	memcpy(&key_ondisk_w->keys[key_ondisk_w->key_used++], &key_disk, sizeof(struct cache_key_ondisk));

	if (key_ondisk_w->key_used >= CACHE_KEY_WRITE_MAX) {
		pthread_mutex_lock(&cache_b->cache_disk_append_mutex);
		ret = cache_key_ondisk_write(cache_b, key_ondisk_w);
		pthread_mutex_unlock(&cache_b->cache_disk_append_mutex);
		if (ret) {
			ubbd_err("failed to write ondisk key.\n");
		}
	}
	pthread_mutex_unlock(&key_ondisk_w->write_lock);

	return ret;
}

int cache_key_insert(struct ubbd_cache_backend *cache_b, struct cache_key *key)
{
	int ret = 0;
	struct skiplist_head *skiplist = &cache_b->cache_key_lists[key->l_off >> CACHE_KEY_LIST_SHIFT];

	seg_used_add(cache_b, key);

	if ((key->l_off & CACHE_KEY_LIST_MASK) + key->len > CACHE_KEY_LIST_SIZE)
		ubbd_err("insert l_off: %lu, p_off: %lu, len: %u.\n", key->l_off, key->p_off, key->len);

	pthread_mutex_lock(&skiplist->lock);
	ret = skiplist_add(cache_b, skiplist, key);
	pthread_mutex_unlock(&skiplist->lock);

	if (cache_b->lcache_debug)
		__cache_key_list_dump(skiplist, 0);

	return ret;
}
