#include "cache_backend_internal.h"

void cache_seg_invalidate(struct ubbd_cache_backend *cache_b, uint64_t index)
{
	cache_b->cache_sb.segments[index].gen++;

	if (cache_b->lcache_debug)
		ubbd_err("gc seg: %lu\n", index);

	pthread_mutex_lock(&cache_b->cache_sb.bitmap_lock);
	ubbd_bit_clear(cache_b->cache_sb.seg_bitmap, index);
	pthread_mutex_unlock(&cache_b->cache_sb.bitmap_lock);
}

void cache_seg_get(struct ubbd_cache_backend *cache_b, uint64_t index)
{
	if (cache_b->lcache_debug)
		ubbd_err("seg: %lu inflight: %d\n",
				index, ubbd_atomic_read(&cache_b->cache_sb.segments[index].inflight));

	ubbd_atomic_inc(&cache_b->cache_sb.segments[index].inflight);
}

void cache_seg_put(struct ubbd_cache_backend *cache_b, uint64_t index)
{
	if (cache_b->lcache_debug)
		ubbd_err("seg %lu inflight: %d\n",
				index, ubbd_atomic_read(&cache_b->cache_sb.segments[index].inflight));

	ubbd_atomic_dec(&cache_b->cache_sb.segments[index].inflight);
}

void seg_used_add(struct ubbd_cache_backend *cache_b, struct cache_key *key)
{
	uint64_t index = key->p_off >> CACHE_SEG_SHIFT;

	pthread_mutex_lock(&cache_b->cache_sb.segments[index].lock);
	cache_b->cache_sb.segments[index].used += key->len;

	pthread_mutex_lock(&cache_b->cache_sb.bitmap_lock);
	if (!ubbd_bit_test(cache_b->cache_sb.seg_bitmap, index)) {
		ubbd_bit_set(cache_b->cache_sb.seg_bitmap, index);
	}
	pthread_mutex_unlock(&cache_b->cache_sb.bitmap_lock);
	pthread_mutex_unlock(&cache_b->cache_sb.segments[index].lock);
}

void seg_used_remove(struct ubbd_cache_backend *cache_b, struct cache_key *key)
{
	uint64_t index = key->p_off >> CACHE_SEG_SHIFT;
	bool invalidate = false;

	pthread_mutex_lock(&cache_b->cache_sb.segments[index].lock);
	cache_b->cache_sb.segments[index].used -= key->len;
	invalidate = (cache_b->cache_sb.segments[index].used == 0);
	pthread_mutex_unlock(&cache_b->cache_sb.segments[index].lock);

	if (cache_b->lcache_debug)
		ubbd_err("seg%lu used: %u\n", index, cache_b->cache_sb.segments[index].used);

	if (invalidate) {
		// FIXME set flag of seg to clean
again:
		if (ubbd_atomic_read(&cache_b->cache_sb.segments[index].inflight)) {
			usleep(100);
			goto again;
		}
		cache_seg_invalidate(cache_b, index);
	}

}
