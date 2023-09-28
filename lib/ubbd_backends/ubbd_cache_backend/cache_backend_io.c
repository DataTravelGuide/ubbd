#define _GNU_SOURCE
#include "cache_backend_internal.h"

struct cache_backend_io_ctx_data {
	struct ubbd_backend *ubbd_b;
	struct ubbd_cache_backend *cache_b;
	struct ubbd_backend_io *io;
	struct ubbd_backend_io *orig_io;
	uint64_t backing_off;
	bool cache_io;
	struct cache_key *key;
};

int cache_backend_ioctx_size(void)
{
	return sizeof(struct cache_backend_io_ctx_data);
}

int cache_backend_io_init(struct ubbd_cache_backend *cache_b)
{
	int ret = 0;;
	int i;

	cache_b->cache_sb.ctx_pools = calloc(cache_b->ubbd_b.num_queues, sizeof(struct ubbd_mempool *));
	if (!cache_b->cache_sb.ctx_pools) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < cache_b->ubbd_b.num_queues; i++) {
		cache_b->cache_sb.ctx_pools[i] = ubbd_mempool_alloc(sizeof(struct context) + cache_backend_ioctx_size(), 1024);
		if (!cache_b->cache_sb.ctx_pools[i]) {
			ret = -ENOMEM;
			ubbd_err("failed to alloc mempool for ctxpool.\n");
			goto release_ctx_pools;
		}
	}

	cache_b->cache_sb.segments = calloc(cache_b->cache_sb.n_segs, sizeof(struct segment));
	if (!cache_b->cache_sb.segments) {
		ubbd_err("failed to alloc mem for segments.\n");
		ret = -ENOMEM;
		goto release_ctx_pools;
	}

	for (i = 0; i < cache_b->cache_sb.n_segs; i++) {
		pthread_mutex_init(&cache_b->cache_sb.segments[i].lock, NULL);
		atomic_set(&cache_b->cache_sb.segments[i].inflight, 0);
	}

	cache_b->cache_sb.seg_bitmap = ubbd_bitmap_alloc(cache_b->cache_sb.n_segs);
	if (!cache_b->cache_sb.seg_bitmap) {
		ubbd_err("failed to alloc mem for seg_bitmap\n");
		ret = -ENOMEM;
		goto free_segments;
	}

	pthread_mutex_init(&cache_b->cache_sb.bitmap_lock, NULL);
	/* first segment is reserved */
	ubbd_bit_set(cache_b->cache_sb.seg_bitmap, 0);

	return 0;

free_segments:
	free(cache_b->cache_sb.segments);
release_ctx_pools:
	for (i = 0; i < cache_b->ubbd_b.num_queues; i++) {
		if (cache_b->cache_sb.ctx_pools[i])
			ubbd_mempool_free(cache_b->cache_sb.ctx_pools[i]);
	}
	free(cache_b->cache_sb.ctx_pools);
out:
	return ret;
}

void cache_backend_io_exit(struct ubbd_cache_backend *cache_b)
{
	int i;

	ubbd_bitmap_free(cache_b->cache_sb.seg_bitmap);
	free(cache_b->cache_sb.segments);

	for (i = 0; i < cache_b->ubbd_b.num_queues; i++) {
		if (cache_b->cache_sb.ctx_pools[i])
			ubbd_mempool_free(cache_b->cache_sb.ctx_pools[i]);
	}
	free(cache_b->cache_sb.ctx_pools);
}

static int cache_backend_write_io_finish(struct context *ctx, int ret)
{
	struct cache_backend_io_ctx_data *data = (struct cache_backend_io_ctx_data *)ctx->data;
	struct ubbd_backend_io *io = (struct ubbd_backend_io *)data->io;
	struct ubbd_backend_io *orig_io = (struct ubbd_backend_io *)data->orig_io;
	struct cache_key *key = data->key;
	struct ubbd_cache_backend *cache_b = data->cache_b;

	if (ret) {
		ubbd_err("ret of cache_backend_io: type %d, %lu:%u: %s\n",
				io->io_type, io->offset, io->len, strerror(-ret));
	}

	if (cache_b->lcache_debug)
		ubbd_err("finish io: %p, orig_io: %p\n", io, orig_io);

	ret = cache_key_insert(cache_b, key);
	cache_key_put(key);
	if (ret) {
		ubbd_err("failed to insert cache key: %d.\n", ret);
		goto finish;
	}

	cache_key_ondisk_append(cache_b, key);
finish:
	if (cache_b->lcache_debug)
		ubbd_err("finish cache write: %lu\n", io->offset >> CACHE_SEG_SHIFT);

	cache_seg_put(cache_b, io->offset >> CACHE_SEG_SHIFT);
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

	if (data->cache_io) {
		cache_seg_put(data->cache_b, io->offset >> CACHE_SEG_SHIFT);
	}

	ubbd_backend_free_backend_io(data->ubbd_b, io);;
	ubbd_backend_io_finish(orig_io, ret);
	ubbd_mempool_put(ctx);

	return 0;
}


static struct ubbd_backend_io* prepare_backend_io(struct ubbd_cache_backend *cache_b,
		struct ubbd_backend *ubbd_b,
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

	bit = ubbd_mempool_get(cache_b->cache_sb.ctx_pools[io->queue_id], (void **)(&clone_io->ctx));
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

static int submit_backing_io(struct ubbd_cache_backend *cache_b,
		struct ubbd_backend_io *io,
		uint64_t off, uint32_t len)
{
	struct ubbd_backend_io *backing_io;
	int ret;

	if (len == 0)
		return 0;

	backing_io = prepare_backend_io(cache_b, cache_b->backing_backend, io, off, len, cache_backend_read_io_finish);
	if (!backing_io) {
		ret = -ENOMEM;
		goto out;
	}

	if (cache_b->lcache_debug)
		ubbd_err("submit backing io: %lu:%u\n", backing_io->offset, backing_io->len);

	ret = cache_b->backing_backend->backend_ops->readv(cache_b->backing_backend, backing_io);
out:
	return ret;
}


static int submit_cache_io(struct ubbd_cache_backend *cache_b,
		struct ubbd_backend_io *io,
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

	backend_index = get_cache_backend(cache_b, cache_off);
	backend = cache_b->cache_backends[backend_index];
	cache_io = prepare_backend_io(cache_b, backend, io, off, len, cache_backend_read_io_finish);
	if (!cache_io) {
		ret = -ENOMEM;
		goto out;
	}
	cache_io->offset = cache_off - (backend_index * (cache_b->cache_sb.segs_per_device << CACHE_SEG_SHIFT));

	data = (struct cache_backend_io_ctx_data *)cache_io->ctx->data;
	data->backing_off = backing_off;
	if (cache_b->lcache_debug) {
		ubbd_err("submit cache io: %lu:%u seg: %lu, logic off: %lu:%u\n",
				cache_io->offset, cache_io->len, cache_io->offset >> CACHE_SEG_SHIFT,
				backing_off, len);
	}

	cache_seg_get(cache_b, cache_io->offset >> CACHE_SEG_SHIFT);
	data->cache_io = true;
	data->cache_b = cache_b;
	ret = backend->backend_ops->readv(backend, cache_io);
out:
	return ret;
}


int cache_backend_io_readv(struct ubbd_cache_backend *cache_b, struct ubbd_backend_io *io)
{
	struct skiplist_node *prev_list[USKIPLIST_MAXLEVEL] = { 0 }, *next_list[USKIPLIST_MAXLEVEL] = { 0 };
	struct cache_key key_data = { .l_off = io->offset, .len = io->len };
	struct cache_key *key = &key_data;
	uint32_t io_done = 0, total_io_done = 0;
	struct skiplist_head *skiplist;
	struct cache_key *key_tmp;
	struct skiplist_node *prev_node, *node_tmp;
	uint32_t io_len;
	int ret = 0;

next_skiplist:
	io_done = 0;
	key->l_off = io->offset + total_io_done;
	key->len = io->len - total_io_done;

	if (key->len > CACHE_KEY_LIST_SIZE - (key->l_off & CACHE_KEY_LIST_MASK))
		key->len = CACHE_KEY_LIST_SIZE - (key->l_off & CACHE_KEY_LIST_MASK);

	skiplist = &cache_b->cache_key_lists[key->l_off >> CACHE_KEY_LIST_SHIFT];

	pthread_mutex_lock(&skiplist->lock);

	ret = skiplist_find(skiplist, key, prev_list, next_list);
	if (ret) {
		pthread_mutex_unlock(&skiplist->lock);
		printf("failed to find key\n");
		goto out;
	}

	prev_node = prev_list[0];
	node_tmp = prev_node;

	while (true) {
		if (node_tmp == NULL)
			break;

		if (io_done >= io->len)
			break;;

		if (node_tmp == &skiplist->node) {
			goto next;
		}

		key_tmp = CACHE_KEY(node_tmp);

		if (cache_b->lcache_debug)
			ubbd_err("gen: %lu, key_gen: %lu, seg: %lu, l_off: %lu\n",
					cache_key_seg(cache_b, key_tmp)->gen, key_tmp->seg_gen,
					key_tmp->p_off >> CACHE_SEG_SHIFT, key_tmp->l_off);

		if (key_tmp->deleted) {
			goto next;
		}

		if (key_tmp->seg_gen < cache_key_seg(cache_b, key_tmp)->gen) {
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
			submit_backing_io(cache_b, io, total_io_done + io_done, key->len);
			io_done += key->len;
			cache_key_cutfront(key, key->len);

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
					submit_backing_io(cache_b, io, total_io_done + io_done, io_len);
					io_done += io_len;
					cache_key_cutfront(key, io_len);
				}

				io_len = cache_key_lend(key) - cache_key_lstart(key_tmp);
				ret = submit_cache_io(cache_b, io, total_io_done + io_done, io_len, key_tmp->p_off, key_tmp->l_off);
				if (ret)
					ret = 0;
				io_done += io_len;
				cache_key_cutfront(key, io_len);
				break;
			}

			/*
			 *    |----|		key_tmp
			 * |==========|		key
			 */
			io_len = cache_key_lstart(key_tmp) - cache_key_lstart(key);
			if (io_len) {
				submit_backing_io(cache_b, io, total_io_done + io_done, io_len);
				io_done += io_len;
				cache_key_cutfront(key, io_len);
			}

			io_len = key_tmp->len;
			ret = submit_cache_io(cache_b, io, total_io_done + io_done, io_len, key_tmp->p_off, key_tmp->l_off);
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
			ret = submit_cache_io(cache_b, io, total_io_done + io_done, key->len, key_tmp->p_off + cache_key_lstart(key) - cache_key_lstart(key_tmp),
					key_tmp->l_off + cache_key_lstart(key) - cache_key_lstart(key_tmp));
			io_done += key->len;
			if (ret)
				ret = 0;

			cache_key_cutfront(key, key->len);
			break;
		}


		/*
		 * |--------|		key_tmp
		 *   |==========|	key
		 */
		io_len = cache_key_lend(key_tmp) - cache_key_lstart(key);
		ret = submit_cache_io(cache_b, io, total_io_done + io_done, io_len, key_tmp->p_off + cache_key_lstart(key) - cache_key_lstart(key_tmp),
					key_tmp->l_off + cache_key_lstart(key) - cache_key_lstart(key_tmp));
		if (ret)
			ret = 0;
		io_done += io_len;
		cache_key_cutfront(key, io_len);
next:
		node_tmp = node_tmp->next[0];
	}

	submit_backing_io(cache_b, io, total_io_done + io_done, key->len);
	io_done += key->len;

	total_io_done += io_done;
	io_done = 0;
	pthread_mutex_unlock(&skiplist->lock);

	if (!ret && total_io_done < io->len) {
		goto next_skiplist;
	}

out:
	ubbd_backend_io_finish(io, ret);

	return 0;
}

static struct data_head *cache_get_data_head(struct ubbd_cache_backend *cache_b, struct ubbd_backend_io *io)
{
	return &cache_b->cache_sb.data_heads[io->queue_id % CACHE_DATA_HEAD_MAX];
}

static int cache_data_head_init(struct ubbd_cache_backend *cache_b, struct data_head *data_head)
{
	int ret;

again:
	pthread_mutex_lock(&cache_b->cache_sb.bitmap_lock);
	ret = ubbd_bit_find_next_zero(cache_b->cache_sb.seg_bitmap, random() % cache_b->cache_sb.n_segs, &data_head->data_head_pos.seg);
	if (ret) {
		pthread_mutex_unlock(&cache_b->cache_sb.bitmap_lock);
		ubbd_err("cant find segment for data\n");
		usleep(1000000);
		goto again;
	}

	cache_b->cache_sb.last_bit = data_head->data_head_pos.seg;
	ubbd_bit_set(cache_b->cache_sb.seg_bitmap, data_head->data_head_pos.seg);

	pthread_mutex_unlock(&cache_b->cache_sb.bitmap_lock);

	data_head->data_head_pos.off_in_seg = 0;
	if (cache_b->lcache_debug) {
		ubbd_err("new data head: %lu\n", data_head->data_head_pos.seg);
	}

	return 0;
}

void cache_data_heads_init(struct ubbd_cache_backend *cache_b)
{
	int i;

	/* init data head which is empty */
	for (i = 0; i < CACHE_DATA_HEAD_MAX; i++) {
		struct data_head *data_head;

		data_head = &cache_b->cache_sb.data_heads[i];
		pthread_mutex_init(&data_head->data_head_lock, NULL);
		cache_data_head_init(cache_b, data_head);
	}

	ubbd_atomic_set(&cache_b->cache_sb.data_head_index, 0);
}

static int cache_data_alloc(struct ubbd_cache_backend *cache_b, struct cache_key *key, struct ubbd_backend_io *io)
{
	int ret = 0;

	struct data_head *data_head = cache_get_data_head(cache_b, io);

again:
	pthread_mutex_lock(&data_head->data_head_lock);
	if (CACHE_SEG_SIZE - data_head->data_head_pos.off_in_seg >= key->len) {
		key->p_off = seg_pos_to_addr(&data_head->data_head_pos);
		key->seg_gen = cache_key_seg(cache_b, key)->gen;
		data_head->data_head_pos.off_in_seg += key->len;

		ret = 0;;
		goto out;
	} else if (CACHE_SEG_SIZE > data_head->data_head_pos.off_in_seg) {
		key->p_off = seg_pos_to_addr(&data_head->data_head_pos);
		key->len = CACHE_SEG_SIZE - data_head->data_head_pos.off_in_seg;
		key->seg_gen = cache_key_seg(cache_b, key)->gen;
		data_head->data_head_pos.off_in_seg += key->len;
	} else {
		ret = cache_data_head_init(cache_b, data_head);
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

int cache_backend_io_writev(struct ubbd_cache_backend *cache_b, struct ubbd_backend_io *io)
{
	struct ubbd_backend_io *cache_io;
	struct ubbd_backend *backend;
	int backend_index = 0;
	struct cache_key *key;
	uint32_t io_done = 0;
	int ret = 0;

	if (cache_b->lcache_debug)
		ubbd_err("cache writev: %lu:%u,  iov_len: %lu, iocnt: %u crc: %lu crc512: %lu\n",
				io->offset, io->len, io->iov[0].iov_len, io->iov_cnt,
				crc64(io->iov[0].iov_base, io->iov[0].iov_len),
				crc64(io->iov[0].iov_base, 512));

	while (true) {
		if (io_done >= io->len) {
			break;
		}

		key = cache_key_alloc(cache_b, io->queue_id);
		if (!key) {
			ret = -ENOMEM;
			goto finish;
		}

		key->l_off = io->offset + io_done;
		key->len = io->len - io_done;
		if (key->len > CACHE_KEY_LIST_SIZE - (key->l_off & CACHE_KEY_LIST_MASK))
			key->len = CACHE_KEY_LIST_SIZE - (key->l_off & CACHE_KEY_LIST_MASK);

		ret = cache_data_alloc(cache_b, key, io);
		if (ret) {
			cache_key_put(key);
			goto finish;
		}

		if (!key->len) {
			ubbd_err("len of key is 0\n");
			cache_key_put(key);
			continue;
		}

		backend_index = get_cache_backend(cache_b, key->p_off);
		backend = cache_b->cache_backends[backend_index];

		cache_io = prepare_backend_io(cache_b, backend, io, io_done, key->len, cache_backend_write_io_finish);
		if (!cache_io) {
			cache_key_put(key);
			ret = -ENOMEM;
			goto finish;
		}
		cache_io->offset = key->p_off - (backend_index * (cache_b->cache_sb.segs_per_device << CACHE_SEG_SHIFT));

		struct cache_backend_io_ctx_data *data;

		data = (struct cache_backend_io_ctx_data *)cache_io->ctx->data;
		data->cache_io = true;
		data->key = key;
		data->cache_b = cache_b;
		cache_seg_get(cache_b, key->p_off >> CACHE_SEG_SHIFT);

		if (cache_b->lcache_debug)
			ubbd_err("submit write cache io: %lu:%u seg: %lu\n",
					cache_io->offset, cache_io->len,
					cache_io->offset >> CACHE_SEG_SHIFT);

		ret = backend->backend_ops->writev(backend, cache_io);

		if (ret) {
			ubbd_err("cache io failed.\n");
			cache_seg_put(cache_b, key->p_off >> CACHE_SEG_SHIFT);
			cache_key_put(key);
			goto finish;
		}

		io_done += key->len;
	}

	if (cache_b->cache_mode == UBBD_CACHE_MODE_WT) {
		struct ubbd_backend_io *backing_io;
		backing_io = prepare_backend_io(cache_b, cache_b->backing_backend, io, 0, io->len, cache_backend_read_io_finish);
		if (cache_b->lcache_debug)
			ubbd_err("submit write backing io: %lu:%u crc: %lu, iov_len: %lu, iocnt: %d\n",
					backing_io->offset, backing_io->len,
					crc64(backing_io->iov[0].iov_base, backing_io->iov[0].iov_len),
					backing_io->iov[0].iov_len, backing_io->iov_cnt);

		ret = cache_b->backing_backend->backend_ops->writev(cache_b->backing_backend, backing_io);
		if (ret) {
			ubbd_err("failed to submit backing io\n");
		}
	}

	ret = 0;
finish:
	ubbd_backend_io_finish(io, ret);
	return 0;
}
