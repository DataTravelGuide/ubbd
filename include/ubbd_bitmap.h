#ifndef UBBD_BITMAP_H
#define UBBD_BITMAP_H

#include "utils.h"

struct ubbd_bitmap {
	uint64_t size;
	uint8_t data[];
};

#define UBBD_BITMAP_SHIFT	3 /* most used to do (index >> UBBD_BITMAP_SHIFT) == (index / 8) */
#define UBBD_BITMAP_MASK	0x7 /* most used to do (index & UBBD_BITMAP_MASK) == (index % 8) */

#define __hweight8(w)		        \
        ((unsigned int)                 \
         ((!!((w) & (1ULL << 0))) +     \
          (!!((w) & (1ULL << 1))) +     \
          (!!((w) & (1ULL << 2))) +     \
          (!!((w) & (1ULL << 3))) +     \
          (!!((w) & (1ULL << 4))) +     \
          (!!((w) & (1ULL << 5))) +     \
          (!!((w) & (1ULL << 6))) +     \
          (!!((w) & (1ULL << 7)))))

static inline uint64_t ubbd_bitmap_weight(struct ubbd_bitmap *bitmap)
{
	uint64_t weight = 0;
	uint64_t index;

	for (index = 0; index < (bitmap->size >> UBBD_BITMAP_SHIFT); index++) {
		weight += __hweight8(bitmap->data[index]);
	}

	return weight;
}

static inline bool ubbd_bit_test(struct ubbd_bitmap *bitmap, uint64_t bit)
{
	return bitmap->data[bit >> UBBD_BITMAP_SHIFT] & (1 << (bit & UBBD_BITMAP_MASK));
}

static inline void ubbd_bit_set(struct ubbd_bitmap *bitmap, uint64_t bit)
{
	bitmap->data[bit >> UBBD_BITMAP_SHIFT] |= (1 << (bit & UBBD_BITMAP_MASK));
}

static inline void ubbd_bit_clear(struct ubbd_bitmap *bitmap, uint64_t bit)
{
	bitmap->data[bit >> UBBD_BITMAP_SHIFT] &= ~(1 << (bit & UBBD_BITMAP_MASK));
}

int ubbd_bit_find_next(struct ubbd_bitmap *bitmap, uint64_t off, uint64_t *found_bit);
int ubbd_bit_find_next_zero(struct ubbd_bitmap *bitmap, uint64_t off, uint64_t *found_bit);

struct ubbd_bitmap *ubbd_bitmap_alloc(uint32_t size);
void ubbd_bitmap_free(struct ubbd_bitmap *bitmap);
#endif /* UBBD_BITMAP_H */
