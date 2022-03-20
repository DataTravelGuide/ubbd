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
	struct context *parent;
	int (*finish)(struct context *ctx, int ret);
};

static inline struct context *context_alloc()
{
	struct context *ctx;

	ctx = calloc(1, sizeof(struct context));
	if (!ctx)
		return NULL;

	return ctx;
}

static inline void context_free(struct context *ctx)
{
	if (!ctx)
		return;

	if (ctx->data)
		free(ctx->data);
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

#endif
