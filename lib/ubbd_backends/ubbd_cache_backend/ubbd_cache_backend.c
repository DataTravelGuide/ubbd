#define _GNU_SOURCE

#include "cache_backend_internal.h"

int cache_sb_write(struct ubbd_cache_backend *cache_b)
{
	int ret;
	struct cache_super_ondisk *sb = (struct cache_super_ondisk *)cache_b->sb_buf;

	pthread_mutex_lock(&cache_b->sb_write_lock);
	sb->magic = CACHE_SB_MAGIC;
	sb->n_segs = cache_b->cache_sb.n_segs;
	sb->key_tail_seg = cache_b->cache_sb.key_tail_pos.seg;
	sb->tail_off_in_seg = cache_b->cache_sb.key_tail_pos.off_in_seg;
	sb->dirty_tail_seg = cache_b->cache_sb.dirty_tail_pos.seg;
	sb->dirty_tail_off_in_seg = cache_b->cache_sb.dirty_tail_pos.off_in_seg;
	sb->last_key_epoch = cache_b->cache_sb.last_key_epoch;

	ret = ubbd_backend_write(cache_b->cache_backend, CACHE_SB_OFF, CACHE_SB_SIZE, cache_b->sb_buf);

	pthread_mutex_unlock(&cache_b->sb_write_lock);

	return ret;
}

static int cache_backend_sb_init(struct ubbd_cache_backend *cache_b)
{
	struct cache_super_ondisk *sb;
	int ret;

	ret = ubbd_backend_read(cache_b->cache_backend, CACHE_SB_OFF, CACHE_SB_SIZE, cache_b->sb_buf);
	if (ret) {
		ubbd_err("failed to read cache sb\n");
		goto out;
	}

	sb = (struct cache_super_ondisk *)cache_b->sb_buf;
	if (sb->magic != CACHE_SB_MAGIC) {
		sb->magic = CACHE_SB_MAGIC;
		sb->key_tail_seg = 1;
		sb->tail_off_in_seg = 0;
		sb->dirty_tail_seg = 1;
		sb->dirty_tail_off_in_seg = 0;
		sb->last_key_epoch = 0;
		sb->n_segs = ubbd_backend_size(cache_b->cache_backends[0]) / CACHE_SEG_SIZE * 1;

		ret = ubbd_backend_write(cache_b->cache_backend, CACHE_SB_OFF, CACHE_SB_SIZE, cache_b->sb_buf);
		if (ret) {
			ubbd_err("failed to write cache sb.\n");
			goto out;
		}
	}

	/* initialize cache sb */
	cache_b->cache_sb.key_tail_pos.seg = sb->key_tail_seg;
	cache_b->cache_sb.key_tail_pos.off_in_seg = sb->tail_off_in_seg;
	cache_b->cache_sb.dirty_tail_pos.seg = sb->dirty_tail_seg;
	cache_b->cache_sb.dirty_tail_pos.off_in_seg = sb->dirty_tail_off_in_seg;
	cache_b->cache_sb.n_segs = sb->n_segs;
	cache_b->cache_sb.last_key_epoch = sb->last_key_epoch;
	cache_b->cache_sb.segs_per_device = cache_b->cache_sb.n_segs / 1;
	cache_b->cache_sb.num_queues = cache_b->ubbd_b.num_queues;

out:
	return ret;
}

static int backends_open(struct ubbd_cache_backend *cache_b)
{
	int ret;
	int i;

	cache_b->backing_backend->num_queues = 1;
	ret = ubbd_backend_open(cache_b->backing_backend);
	if (ret) {
		return ret;
	}
	cache_b->size = ubbd_backend_size(cache_b->backing_backend);

	/* TODO support multi cache backends */
	for (i = 0; i < 1; i++) {
		cache_b->cache_backends[i]->num_queues = cache_b->ubbd_b.num_queues;

		ret = ubbd_backend_open(cache_b->cache_backends[i]);
		if (ret) {
			goto close_backing;
		}
	}
	cache_b->cache_backend = cache_b->cache_backends[0];

	return 0;

close_backing:
	ubbd_backend_close(cache_b->backing_backend);

	return ret;
}

static void backends_close(struct ubbd_cache_backend *cache_b)
{
	int i;

	for (i = 0; i < 1; i++) {
		ubbd_backend_close(cache_b->cache_backends[i]);
	}
	ubbd_backend_close(cache_b->backing_backend);
}

static int cache_backend_open(struct ubbd_backend *ubbd_b)
{
	int ret = 0;
	struct ubbd_cache_backend *cache_b = CACHE_BACKEND(ubbd_b);

	pthread_mutex_init(&cache_b->cache_disk_append_mutex, NULL);
	pthread_mutex_init(&cache_b->sb_write_lock, NULL);

	ret = backends_open(cache_b);
	if (ret < 0) {
		goto out;
	}

	ret = cache_backend_sb_init(cache_b);
	if (ret < 0) {
		goto close_backends;
	}

	ret = cache_backend_io_init(cache_b);
	if (ret < 0) {
		goto close_backends;
	}

	ret = cache_backend_key_init(cache_b);
	if (ret < 0) {
		goto io_exit;
	}

	ret = cache_backend_wb_start(cache_b);
	if (ret < 0) {
		goto key_exit;
	}

	ret = cache_backend_gc_start(cache_b);
	if (ret < 0) {
		goto wb_stop;
	}

	cache_data_heads_init(cache_b);

	return 0;

wb_stop:
	cache_backend_wb_stop(cache_b);
key_exit:
	cache_backend_key_exit(cache_b);
io_exit:
	cache_backend_io_exit(cache_b);
close_backends:
	backends_close(cache_b);
out:
	return ret;
}

static void wait_for_cache_clean(struct ubbd_cache_backend *cache_b)
{
	uint64_t addr;

	while (true) {
		addr = seg_pos_to_addr(&cache_b->cache_sb.dirty_tail_pos);
		if (addr != seg_pos_to_addr(&cache_b->cache_sb.key_head_pos)) {
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

	cache_key_ondisk_write_all(cache_b);

	if (cache_b->detach_on_close) {
		wait_for_cache_clean(cache_b);
	}

	cache_backend_gc_stop(cache_b);
	cache_backend_wb_stop(cache_b);
	cache_backend_key_exit(cache_b);
	cache_backend_io_exit(cache_b);
	backends_close(cache_b);
}

static void cache_backend_release(struct ubbd_backend *ubbd_b)
{
	struct ubbd_cache_backend *cache_b = CACHE_BACKEND(ubbd_b);
	int i;

	if (!cache_b)
		return;

	if (cache_b->backing_backend)
		ubbd_backend_release(cache_b->backing_backend);

	for (i = 0; i < 1; i++) {
		ubbd_backend_release(cache_b->cache_backends[i]);
	}

	free(cache_b->sb_buf);
	free(cache_b);
}

static int cache_backend_writev(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct ubbd_cache_backend *cache_b = CACHE_BACKEND(ubbd_b);
	
	return cache_backend_io_writev(cache_b, io);
}

static int cache_backend_readv(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct ubbd_cache_backend *cache_b = CACHE_BACKEND(ubbd_b);

	return cache_backend_io_readv(cache_b, io);
}

static int cache_backend_flush(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct ubbd_cache_backend *cache_b = CACHE_BACKEND(ubbd_b);

	cache_key_ondisk_write_all(cache_b);
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

struct ubbd_backend_ops cache_backend_ops;
struct ubbd_backend *cache_backend_create(struct ubbd_dev_info *dev_info)
{
	struct ubbd_cache_backend *cache_b;
	struct ubbd_backend *ubbd_b;
	struct __ubbd_dev_info *cache_dev_info = &dev_info->cache_dev.cache_info;
	struct __ubbd_dev_info *backing_dev_info = &dev_info->cache_dev.backing_info;
	struct ubbd_dev_info cache_info, backing_info;
	int i;

	cache_b = calloc(1, sizeof(struct ubbd_cache_backend));
	if (!cache_b) {
		ubbd_err("failed to alloc cache_b.\n");
		return NULL;
	}

	if (posix_memalign((void **)&cache_b->sb_buf, PAGE_SIZE, PAGE_SIZE) != 0) {
		ubbd_err("alloc sb_buf failed\n");
		goto free_cache_b;
	}

	cache_b->lcache_debug = false;
	cache_info.type = cache_dev_info->type;
	cache_info.num_queues = dev_info->num_queues;
	memcpy(&cache_info.generic_dev.info, cache_dev_info, sizeof(struct __ubbd_dev_info));

	cache_b->cache_backends[0] = backend_create(&cache_info);
	if (!cache_b->cache_backends[0]) {
		goto free_sb_buf;
	}

	backing_info.type = backing_dev_info->type;
	backing_info.num_queues = 1;
	memcpy(&backing_info.generic_dev.info, backing_dev_info, sizeof(struct __ubbd_dev_info));

	cache_b->backing_backend = backend_create(&backing_info);
	if (!cache_b->backing_backend) {
		goto release_cache_backend;
	}

	cache_b->cache_mode = dev_info->cache_dev.cache_mode;

	ubbd_b = &cache_b->ubbd_b;
	ubbd_b->dev_type = UBBD_DEV_TYPE_CACHE;
	ubbd_b->backend_ops = &cache_backend_ops;

	return &cache_b->ubbd_b;

release_cache_backend:
	for (i = 0; i < 1; i++) {
		ubbd_backend_release(cache_b->cache_backends[i]);
	}
free_sb_buf:
	free(cache_b->sb_buf);
free_cache_b:
	free(cache_b);

	return NULL;
}

struct ubbd_backend_ops cache_backend_ops = {
	.create = cache_backend_create,
	.open = cache_backend_open,
	.close = cache_backend_close,
	.release = cache_backend_release,
	.writev = cache_backend_writev,
	.readv = cache_backend_readv,
	.flush = cache_backend_flush,
	.set_opts = cache_backend_set_opts,
};
