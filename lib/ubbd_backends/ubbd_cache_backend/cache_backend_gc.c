#include "cache_backend_internal.h"

static bool need_gc(struct ubbd_cache_backend *cache_b)
{
	if (cache_b->cache_sb.key_tail_pos.seg == cache_b->cache_sb.dirty_tail_pos.seg)
		return false;

	if (ubbd_bitmap_weight(cache_b->cache_sb.seg_bitmap) < (cache_b->cache_sb.n_segs * 0.7))
		return false;

	return true;
}

static void *cache_gc_thread_fn(void* args)
{
	int ret = 0;
	struct ubbd_cache_backend *cache_b = args;
	uint64_t addr;
	static char kset_buf[CACHE_KSET_SIZE] __attribute__ ((__aligned__ (4096))) = { 0 };
	char seg_buf[CACHE_SEG_SIZE] __attribute__ ((__aligned__ (4096)));
	struct cache_kset_ondisk *kset_disk = (struct cache_kset_ondisk *)kset_buf;
	struct cache_key_ondisk *key_disk;
	struct cache_key *key;
	int i;

	while (true) {
		if (cache_b->gc_stop)
			break;

		if (cache_b->lcache_debug)
			ubbd_err("key_tail_pos: %lu, off: %u, dirty_tail_pos: %lu, off: %u\n",
					cache_b->cache_sb.key_tail_pos.seg,
					cache_b->cache_sb.key_tail_pos.off_in_seg,
					cache_b->cache_sb.dirty_tail_pos.seg,
					cache_b->cache_sb.dirty_tail_pos.off_in_seg);

		if (!need_gc(cache_b)) {
			usleep(100000);
			continue;
		}

		addr = seg_pos_to_addr(&cache_b->cache_sb.key_tail_pos);
		if (cache_b->lcache_debug)
			ubbd_err("read kset : %lu\n", addr);

		ret = ubbd_backend_read(cache_b->cache_backend, addr, CACHE_KSET_SIZE, kset_buf);
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
			ubbd_err("gc got last kset %lu\n", cache_b->cache_sb.key_tail_pos.seg);

			if (1) {
				ret = ubbd_backend_write(cache_b->cache_backend,
						cache_b->cache_sb.key_tail_pos.seg << CACHE_SEG_SHIFT,
						CACHE_SEG_SIZE, seg_buf);
				if (ret) {
					ubbd_err("failed to write zero to old key segment.\n");
				}
			}

			pthread_mutex_lock(&cache_b->cache_sb.bitmap_lock);
			ubbd_bit_clear(cache_b->cache_sb.seg_bitmap, cache_b->cache_sb.key_tail_pos.seg);
			pthread_mutex_unlock(&cache_b->cache_sb.bitmap_lock);
			//dump_bitmap(cache_b->cache_sb.seg_bitmap);

			cache_b->cache_sb.key_tail_pos.seg = kset_disk->next_seg;
			cache_b->cache_sb.key_tail_pos.off_in_seg = 0;

			cache_sb_write(cache_b);
			continue;
		}

		for (i = 0; i < kset_disk->keys; i++) {
			key_disk = &kset_disk->data[i];
			key = cache_key_decode(cache_b, key_disk);
			if (!key) {
				ret = -ENOMEM;
				break;
			}

			seg_used_remove(cache_b, key);
			cache_key_put(key);
		}

		cache_b->cache_sb.key_tail_pos.off_in_seg += kset_disk->kset_len;
		cache_sb_write(cache_b);
	}

	ubbd_info("gc thread exit: %d\n", ret);

	return NULL;
}

int cache_backend_gc_start(struct ubbd_cache_backend *cache_b)
{
	int ret;

	if (1) {
		ret = pthread_create(&cache_b->cache_gc_thread, NULL, cache_gc_thread_fn, cache_b);
		if (ret < 0) {
			ubbd_err("failed to start thread for gc.\n");
			return ret;
		}
	}

	return 0;
}

int cache_backend_gc_stop(struct ubbd_cache_backend *cache_b)
{
	int ret;

	cache_b->gc_stop = true;

	ret = pthread_join(cache_b->cache_gc_thread, NULL);
	if (ret) {
		ubbd_err("failed to wait cache_gc_thread joing: %d\n", ret);
		return ret;
	}

	return 0;
}
