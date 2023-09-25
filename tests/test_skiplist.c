#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include "pthread.h"
#include <string.h>
#include "errno.h"

#define USKIPLIST_MAXLEVEL              8
#define USKIPLIST_P	0.25
#define THREAD_NUM	10

struct skiplist_node {
	void *next;
	pthread_mutex_t node_lock;
};

struct cache_key {
	int level:10;
	int deleted:1;
	int fullylinked:1;
	struct skiplist_node node_list[USKIPLIST_MAXLEVEL];

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

static int usl_random_level(void) {
    int level = 1;

    while ((random()&0xFFFF) < (USKIPLIST_P * 0xFFFF))
        level += 1;

    return (level < USKIPLIST_MAXLEVEL) ? level : USKIPLIST_MAXLEVEL;
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

static void cache_key_merge(struct cache_key *key_1,
		struct cache_key *key_2)
{
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
	key_dst->level = key_src->level;
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
	key->deleted = 1;
}

static int skiplist_find(struct cache_key *skiplist, struct cache_key *key,
		struct cache_key **prev_list, struct cache_key **next_list)
{
	struct cache_key *prev_key, *next_key, *key_tmp;
	int l;

	while (true) {
retry:
		prev_key = key_tmp = NULL;
		prev_key = skiplist;

		for (l = USKIPLIST_MAXLEVEL - 1; l >= 0; l--) {
			key_tmp = prev_key->node_list[l].next;

			while (true) {
				if (key_tmp == NULL)
					break;

				if (key_tmp->deleted) {
					next_key = key_tmp->node_list[l].next;
					pthread_mutex_lock(&prev_key->node_list[l].node_lock);
					prev_key->node_list[l].next = next_key;
					pthread_mutex_unlock(&prev_key->node_list[l].node_lock);
					key_tmp = next_key;
					continue;
				}

				if (cache_key_lstart(key_tmp) < cache_key_lstart(key)) {
					prev_key = key_tmp;
					key_tmp = key_tmp->node_list[l].next;
					continue;
				}
				break;
			}
next:
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
	struct cache_key *prev_key, *next_key, *key_tmp, *key_fixup;
	int locked_level = -1;
	bool valid;
	int i, l;
	int ret;

again:
	locked_level = -1;
	memset(prev_list, 0, sizeof(struct cache_key *) * USKIPLIST_MAXLEVEL);
	memset(next_list, 0, sizeof(struct cache_key *) * USKIPLIST_MAXLEVEL);

	ret = skiplist_find(skiplist, key, prev_list, next_list);
	if (ret) {
		printf("failed to find key\n");
		goto out;
	}

relock:
	for (i = 0; i < key->level; i++) {
		prev_key = prev_list[i];
		next_key = next_list[i];

		if (pthread_mutex_trylock(&prev_key->node_list[i].node_lock)) {
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

		if (key_tmp->deleted) {
			goto next;
		}

		if (key_tmp != prev_key) {
			pthread_mutex_lock(&key_tmp->node_list[0].node_lock);
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
			key_fixup = calloc(1, sizeof(struct cache_key));
			if (!key_fixup) {
				ret = -ENOMEM;
				if (key_tmp != prev_key) {
					pthread_mutex_unlock(&key_tmp->node_list[0].node_lock);
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
			}

			key_fixup->fullylinked = 1;

			if (key_tmp != prev_key) {
				pthread_mutex_unlock(&key_tmp->node_list[0].node_lock);
			}
			break;
		}


		/*
		 * |--------|		key_tmp
		 *   |==========|	key
		 */
		cache_key_cutback(key_tmp, cache_key_lend(key_tmp) - cache_key_lstart(key));

next:
		if (key_tmp != prev_key) {
			pthread_mutex_unlock(&key_tmp->node_list[0].node_lock);
		}

		key_tmp = key_tmp->node_list[0].next;
	}

	for (i = 0; i < key->level; i++) {
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

static void dump_list(struct cache_key *skiplist)
{
	struct cache_key *key_tmp;
	int i = 0;
	int l = 0;

	for (l = USKIPLIST_MAXLEVEL - 1; l >= 0; l--) {
		printf("level: %d\n", l);
		i = 0;
		key_tmp = skiplist->node_list[l].next;

		while (key_tmp) {
			if (!key_tmp->deleted) {
				//printf("index: %d, l_off: %lu, len: %u,  deleted: %d\n", i, cache_key_lstart(key_tmp), key_tmp->len, key_tmp->deleted);
				i++;
			}
			key_tmp = key_tmp->node_list[l].next;
		};
		printf("index: %d\n", i);
	}
}

static void *thread_fn(void *arg)
{
	struct cache_key *skiplist = arg;

	struct cache_key *keys = calloc(1024000, sizeof(struct cache_key));
	int i;

	for (i = 0; i < 1024000; i++) {
		//getrandom(&keys[i].val, sizeof(uint64_t), 0);
		keys[i].l_off = (random() % (1024 * 1024)) * 4096;
		keys[i].len = random() % 10 * 4096 + 4096;
		keys[i].level = usl_random_level();
		//printf("insert %lu, level: %d, len: %d\n", keys[i].l_off, keys[i].level, keys[i].len);

		skiplist_add(skiplist, &keys[i]);
		//dump_list(&skiplist);
	}

	return NULL;
}

int main()
{
	struct cache_key skiplist = { 0 };
	pthread_t thread[10];
	int i;
	void *retval;

	for(i = 0; i < THREAD_NUM; i++) {
		pthread_create(&thread[i], NULL, thread_fn, &skiplist);
	}

	for(i = 0; i < THREAD_NUM; i++) {
		pthread_join(thread[i], &retval);
	}

	dump_list(&skiplist);

	return 0;
}
