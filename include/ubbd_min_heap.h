#ifndef UBBD_MIN_HEAP_H
#define UBBD_MIN_HEAP_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <stdbool.h>

struct min_heap {
	void *data;
	int nr;
	int size;
};

struct min_heap_callbacks {
	int elem_size;
	bool (*less)(const void *lhs, const void *rhs);
	void (*swp)(void *lhs, void *rhs);
};

static inline void min_heapify(struct min_heap *heap, int pos,
		const struct min_heap_callbacks *func)
{
	void *left, *right, *parent, *smallest;
	void *data = heap->data;

	for (;;) {
		if (pos * 2 + 1 >= heap->nr)
			break;

		left = data + ((pos * 2 + 1) * func->elem_size);
		parent = data + (pos * func->elem_size);
		smallest = parent;
		if (func->less(left, smallest))
			smallest = left;

		if (pos * 2 + 2 < heap->nr) {
			right = data + ((pos * 2 + 2) * func->elem_size);
			if (func->less(right, smallest))
				smallest = right;
		}
		if (smallest == parent)
			break;
		func->swp(smallest, parent);
		if (smallest == left)
			pos = (pos * 2) + 1;
		else
			pos = (pos * 2) + 2;
	}
}

static inline void min_heapify_all(struct min_heap *heap,
		const struct min_heap_callbacks *func)
{
	int i;

	for (i = heap->nr / 2; i >= 0; i--)
		min_heapify(heap, i, func);
}

static inline int min_heap_pop(struct min_heap *heap,
		const struct min_heap_callbacks *func)
{
	void *data = heap->data;

	if (heap->nr <= 0) {
		ubbd_err("pop an empty heap\n");
		return -1;
	}

	/* Place last element at the root (position 0) and then sift down. */
	heap->nr--;
	memcpy(data, data + (heap->nr * func->elem_size), func->elem_size);
	min_heapify(heap, 0, func);

	return 0;
}

/*
 * Remove the minimum element and then push the given element. The
 * implementation performs 1 sift (O(log2(nr))) and is therefore more
 * efficient than a pop followed by a push that does 2.
 */
static inline void min_heap_pop_push(struct min_heap *heap,
		const void *element,
		const struct min_heap_callbacks *func)
{
	memcpy(heap->data, element, func->elem_size);
	min_heapify(heap, 0, func);
}

/* Push an element on to the heap, O(log2(nr)). */
static inline int min_heap_push(struct min_heap *heap, const void *element,
		const struct min_heap_callbacks *func)
{
	void *data = heap->data;
	void *child, *parent;
	int pos;

	if (heap->nr >= heap->size) {
		ubbd_err("push on a full heap\n");
		return -1;
	}

	/* Place at the end of data. */
	pos = heap->nr;
	memcpy(data + (pos * func->elem_size), element, func->elem_size);
	heap->nr++;

	/* Sift child at pos up. */
	for (; pos > 0; pos = (pos - 1) / 2) {
		child = data + (pos * func->elem_size);
		parent = data + ((pos - 1) / 2) * func->elem_size;
		if (func->less(parent, child))
			break;
		func->swp(parent, child);
	}

	return 0;
}

#endif /* UBBD_MIN_HEAP_H */
