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

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define container_of(ptr, type, member) ({                      \
        const typeof(((type *)0)->member) *__mptr = (ptr);      \
        (type *)((char *)__mptr - offsetof(type, member));      \
})

struct context {
	void *data;
	int (*finish)(struct context *ctx, int ret);
};

static inline struct context *context_alloc()
{
	return calloc(1, sizeof(struct context));
}

static inline void context_free(struct context *ctx)
{
	if (!ctx)
		return;

	if (ctx->data)
		free(ctx->data);
	free(ctx);
}

#endif
