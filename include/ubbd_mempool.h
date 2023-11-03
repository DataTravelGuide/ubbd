#ifndef UBBD_MEMPOOL_H
#define UBBD_MEMPOOL_H

#include "ubbd_bitmap.h"
#include "semaphore.h"

#define CACHELINE_SIZE	1

#define LIST_POISON  ((void *)0x201)

struct mempool_entry {
	struct mempool_bucket *bucket;
	struct mempool_entry *next;
	uint8_t block[];
};

struct mempool_bucket {
	struct ubbd_mempool *pool;
	struct mempool_bucket *next;
	ubbd_atomic	used;
	uint8_t entries[];
};

struct ubbd_mempool {
	int blocksize;
	int blockcount;
	int entrysize;
	int bucketsize;

	struct mempool_entry *available;
	struct mempool_entry *reclaim;
	struct mempool_entry *reclaim_last;

	bool debug;

	pthread_t fillin_thread;
	bool thread_stop;
	struct mempool_entry *pending;
	struct mempool_entry *pending_last;
	pthread_mutex_t pending_lock;
	pthread_cond_t pending_cond;
	bool unlimited;
	sem_t pending_sem;

	struct mempool_bucket inline_bucket;
	/* inline bucket must be the last member */
};

static inline int ubbd_mempool_get(struct ubbd_mempool *pool, void **block)
{
	struct mempool_entry *entry_available, *entry_next, *entry_first, *entry_last;

again:
	entry_available = pool->available;
	if (entry_available == NULL) {
		goto fetch_from_reclaim;
	}

	entry_next = entry_available->next;
	if (entry_available != ubbd_cas(&pool->available, entry_available, entry_next)) {
		cpu_relax();
		goto again;
	}

	*block = entry_available->block;
	memset(*block, 0, pool->blocksize);

	if (pool->debug)
		ubbd_atomic_inc(&entry_available->bucket->used);

	return 0;

insert_to_available:
	entry_available = pool->available;
	entry_last->next = entry_available;
	if (entry_available != ubbd_cas(&pool->available, entry_available, entry_first)) {
		cpu_relax();
		goto insert_to_available;
	}
	goto again;

fetch_from_reclaim:
	entry_first = pool->reclaim;
	entry_last = pool->reclaim_last;
	if (entry_first == LIST_POISON) {
		cpu_relax();
		goto fetch_from_reclaim;
	}

	if (entry_first == NULL) {
		if (pool->unlimited)
			goto fetch_from_pending;
		goto again;
	}

	if (entry_first != ubbd_cas(&pool->reclaim, entry_first, NULL)) {
		cpu_relax();
		goto fetch_from_reclaim;
	}
	goto insert_to_available;

fetch_from_pending:
	entry_first = pool->pending;
	entry_last = pool->pending_last;
	if (entry_first == NULL || entry_last == NULL) {
		sem_post(&pool->pending_sem);
		cpu_relax();
		goto again;
	}

	if (entry_first != ubbd_cas(&pool->pending, entry_first, NULL)) {
		cpu_relax();
		goto fetch_from_pending;
	}
	goto insert_to_available;
}

static inline void ubbd_mempool_put(void *block)
{
	struct mempool_entry *entry = ubbd_container_of(block, struct mempool_entry, block);
	struct mempool_entry *entry_reclaim;
	struct ubbd_mempool *pool = entry->bucket->pool;

again:
	entry_reclaim = pool->reclaim;
	if (entry_reclaim == LIST_POISON) {
		/* There is a putting happening */
		cpu_relax();
		goto again;
	}

	if (entry_reclaim == NULL) {
		/* set reclaim to LIST_POISON to prevent race with other put */
		if (entry_reclaim != ubbd_cas(&pool->reclaim, entry_reclaim, LIST_POISON)) {
			cpu_relax();
			goto again;
		}
		pool->reclaim_last = entry;
		entry->next = NULL;
		entry_reclaim = LIST_POISON;
	} else {
		entry->next = entry_reclaim;
	}

	if (entry_reclaim != ubbd_cas(&pool->reclaim, entry_reclaim, entry)) {
		cpu_relax();
		goto again;
	}

	if (pool->debug)
		ubbd_atomic_dec(&entry->bucket->used);
}

static void *fillin_fn(void *arg)
{
	struct ubbd_mempool *pool = (struct ubbd_mempool *)arg;
	struct mempool_entry *first_entry, *last_entry, *entry;
	struct mempool_bucket *bucket, *first_bucket;
	int ret = 0;
	int i;

	while (true) {
		if (pool->thread_stop) {
			ret = 0;
			goto out;
		}

		if (pool->pending != NULL) {
			sem_wait(&pool->pending_sem);
		}

		if (pool->pending != NULL)
			continue;


		pool->pending_last = NULL;

		bucket = calloc(1, pool->bucketsize);
		if (!bucket) {
			ubbd_err("failed to alloc bucket\n");
			continue;
		}

		/* I am the only person to change this list */
		first_bucket = pool->inline_bucket.next;
		bucket->next = first_bucket;
		bucket->pool = pool;
		ubbd_atomic_set(&bucket->used, 0);
		pool->inline_bucket.next = bucket;

		first_entry = (struct mempool_entry *)&bucket->entries[0];
		last_entry = NULL;

		for (i = 0; i < pool->blockcount; i++) {
			entry = (struct mempool_entry *)&bucket->entries[pool->entrysize * i];
			entry->next = NULL;
			entry->bucket = bucket;

			if (last_entry) {
				last_entry->next = entry;
			}
			last_entry = entry;
		}

again:
		if (NULL != ubbd_cas(&pool->pending, NULL, first_entry)) {
			goto again;
		}

		pool->pending_last = last_entry;
	};
out:
	ubbd_info("fillin thread exit with %d\n", ret);

	return NULL;
}

static inline struct ubbd_mempool *mempool_alloc(int blocksize, int blockcount, bool unlimited)
{
	struct ubbd_mempool *pool;
	struct mempool_entry *entry;
	int entry_size, bucket_size;
	struct mempool_bucket *bucket;
	int ret = 0;
	int i;

	entry_size = ubbd_roundup(sizeof(struct mempool_entry) + blocksize, CACHELINE_SIZE);
	bucket_size = sizeof(struct mempool_bucket) + entry_size * blockcount;

	pool = calloc(1, sizeof(struct ubbd_mempool) + bucket_size);
	if (!pool) {
		return NULL;
	}

	pthread_mutex_init(&pool->pending_lock, NULL);
	pthread_cond_init(&pool->pending_cond, NULL);
	ret = sem_init(&pool->pending_sem, 1, 1);
	if (ret) {
		ubbd_err("failed to init semaphore\n");
		return NULL;
	}

	pool->blockcount = blockcount;
	pool->blocksize = blocksize;
	pool->entrysize = entry_size;
	pool->bucketsize = bucket_size;
	pool->unlimited = unlimited;

	pool->reclaim = pool->available = NULL;

	bucket = &pool->inline_bucket;
	ubbd_atomic_set(&bucket->used, 0);
	bucket->next = NULL;
	bucket->pool = pool;

	for (i = 0; i < blockcount; i++) {
		entry = (struct mempool_entry *)&bucket->entries[pool->entrysize * i];
		if (!entry) {
			goto err;
		}

		entry->next = NULL;
		entry->bucket = bucket;
		ubbd_mempool_put(entry->block);
	}

	/* if unlimited, we need to start a new process to prepare a new bucket */
	if (unlimited) {
		ubbd_err("start process\n");
		ret = pthread_create(&pool->fillin_thread, NULL, fillin_fn, pool);
		if (ret) {
			ubbd_err("failed to start fillin thread.\n");
			goto err;
		}
	}

	return pool;

err:
	free(pool);

	return NULL;
}

static inline struct ubbd_mempool *ubbd_mempool_alloc(int blocksize, int blockcount)
{
	return mempool_alloc(blocksize, blockcount, 0);
}

static inline struct ubbd_mempool *ubbd_unlimited_mempool_alloc(int blocksize, int blockcount)
{
	return mempool_alloc(blocksize, blockcount, 1);
}

static inline void ubbd_mempool_free(struct ubbd_mempool *pool)
{
	struct mempool_bucket *bucket, *next;

	bucket = pool->inline_bucket.next;
	while (bucket) {
		if (pool->debug)
			ubbd_err("used: %d\n", ubbd_atomic_read(&bucket->used));
		next = bucket->next;
		free(bucket);
		bucket = next;
	}
	free(pool);
}
#endif /* UBBD_MEMPOOL_H */
