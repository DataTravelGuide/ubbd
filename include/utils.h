#ifndef UTILS_H
#define UTILS_H
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <stdbool.h>

#define UBBD_LIB_DIR	"/var/lib/ubbd/"

#ifndef MAX
#define MAX(a,b)            (((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a,b)            (((a) < (b)) ? (a) : (b))
#endif

# define do_div(n,base) ({                                      \
        uint32_t __base = (base);                               \
        uint32_t __rem;                                         \
        __rem = ((uint64_t)(n)) % __base;                       \
        (n) = ((uint64_t)(n)) / __base;                         \
        __rem;                                                  \
 })

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define container_of(ptr, type, member) ({                      \
        const typeof(((type *)0)->member) *__mptr = (ptr);      \
        (type *)((char *)__mptr - offsetof(type, member));      \
})

int ubbd_util_get_file_size(const char *filepath, uint64_t *file_size);
int ubbd_load_module(char *mod_name);

int execute(char* program, char** arg_list);

#include <time.h>

static inline uint64_t get_ns()
{
	struct timespec t = {0,0};

	clock_gettime(CLOCK_MONOTONIC, &t);
	return ((uint64_t)t.tv_sec * 1.0e9 + t.tv_nsec);
}

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

static inline int wait_condition(int wait_count, uint64_t wait_interval_us, bool (*condition)(void *), void *data)
{
	int i;
	int ret;

	for (i = 0; i < wait_count; i++) {
		ret = condition(data);
		if (ret) {
			return 0;
		}
		usleep(wait_interval_us);
	}

	return -ETIMEDOUT;
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

#endif /* UTILS_H */
