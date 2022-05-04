#ifndef UTILS_H
#define UTILS_H
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <stdbool.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define container_of(ptr, type, member) ({                      \
        const typeof(((type *)0)->member) *__mptr = (ptr);      \
        (type *)((char *)__mptr - offsetof(type, member));      \
})

struct context {
	struct context *parent;
	int (*finish)(struct context *ctx, int ret);
	char data[];
};

static inline struct context *context_alloc(size_t data_size)
{
	struct context *ctx;

	ctx = calloc(1, sizeof(struct context) + data_size);
	if (!ctx)
		return NULL;

	return ctx;
}

static inline void context_free(struct context *ctx)
{
	if (!ctx)
		return;

	free(ctx);
}

static inline int context_finish(struct context *ctx, int ret)
{
	if (ctx->finish)
		ret = ctx->finish(ctx, ret);

	if (ctx->parent)
		context_finish(ctx->parent, ret);

	context_free(ctx);

	return ret;
}

/* Atomic  */

typedef int ubbd_atomic;

typedef long ubbd_atomic64;

#ifndef atomic_read
#define atomic_read(ptr)       (*(__typeof__(*ptr) *volatile) (ptr))
#endif

#ifndef atomic_set
#define atomic_set(ptr, i)     ((*(__typeof__(*ptr) *volatile) (ptr)) = (i))
#endif

#define atomic_inc(ptr)        ((void) __sync_fetch_and_add(ptr, 1))
#define atomic_dec(ptr)        ((void) __sync_fetch_and_add(ptr, -1))
#define atomic_add(ptr, n)     ((void) __sync_fetch_and_add(ptr, n))
#define atomic_sub(ptr, n)     ((void) __sync_fetch_and_sub(ptr, n))

#define atomic_cmpxchg         __sync_val_compare_and_swap

static inline int ubbd_atomic_read(const ubbd_atomic *a)
{
	return atomic_read(a);
}

static inline void ubbd_atomic_set(ubbd_atomic *a, int i)
{
	atomic_set(a, i);
}

static inline void ubbd_atomic_add(int i, ubbd_atomic *a)
{
	atomic_add(a, i);
}

static inline void ubbd_atomic_sub(int i, ubbd_atomic *a)
{
	atomic_sub(a, i);
}

static inline bool ubbd_atomic_sub_and_test(int i, ubbd_atomic *a)
{
	return __sync_sub_and_fetch(a, i) == 0;
}

static inline void ubbd_atomic_inc(ubbd_atomic *a)
{
	atomic_inc(a);
}

static inline void ubbd_atomic_dec(ubbd_atomic *a)
{
	atomic_dec(a);
}

static inline bool ubbd_atomic_dec_and_test(ubbd_atomic *a)
{
	return __sync_sub_and_fetch(a, 1) == 0;
}

static inline bool ubbd_atomic_inc_and_test(ubbd_atomic *a)
{
	return __sync_add_and_fetch(a, 1) == 0;
}

static inline int ubbd_atomic_add_return(int i, ubbd_atomic *a)
{
	return __sync_add_and_fetch(a, i);
}

static inline int ubbd_atomic_sub_return(int i, ubbd_atomic *a)
{
	return __sync_sub_and_fetch(a, i);
}

static inline int ubbd_atomic_inc_return(ubbd_atomic *a)
{
	return ubbd_atomic_add_return(1, a);
}

static inline int ubbd_atomic_dec_return(ubbd_atomic *a)
{
	return ubbd_atomic_sub_return(1, a);
}

static inline int ubbd_atomic_cmpxchg(ubbd_atomic *a, int old, int new_value)
{
	return atomic_cmpxchg(a, old, new_value);
}

static inline int ubbd_atomic_add_unless(ubbd_atomic *a, int i, int u)
{
	int c, old;
	c = ubbd_atomic_read(a);
	for (;;) {
		if (c == (u)) {
			break;
		}
		old = ubbd_atomic_cmpxchg((a), c, c + (i));
		if (old == c) {
			break;
		}
		c = old;
	}
	return c != (u);
}

static inline long ubbd_atomic64_read(const ubbd_atomic64 *a)
{
	return atomic_read(a);
}

static inline void ubbd_atomic64_set(ubbd_atomic64 *a, long i)
{
	atomic_set(a, i);
}

static inline void ubbd_atomic64_add(long i, ubbd_atomic64 *a)
{
	atomic_add(a, i);
}

static inline void ubbd_atomic64_sub(long i, ubbd_atomic64 *a)
{
	atomic_sub(a, i);
}

static inline void ubbd_atomic64_inc(ubbd_atomic64 *a)
{
	atomic_inc(a);
}

static inline void ubbd_atomic64_dec(ubbd_atomic64 *a)
{
	atomic_dec(a);
}

static inline int ubbd_atomic64_add_return(int i, ubbd_atomic *a)
{
	return __sync_add_and_fetch(a, i);
}

static inline int ubbd_atomic64_sub_return(int i, ubbd_atomic *a)
{
	return __sync_sub_and_fetch(a, i);
}

static inline int ubbd_atomic64_inc_return(ubbd_atomic *a)
{
	return ubbd_atomic64_add_return(1, a);
}

static inline int ubbd_atomic64_dec_return(ubbd_atomic *a)
{
	return ubbd_atomic_sub_return(1, a);
}

static inline long ubbd_atomic64_cmpxchg(ubbd_atomic64 *a, long old, long new)
{
	return atomic_cmpxchg(a, old, new);
}

#endif
