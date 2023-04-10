#include "ubbd_log.h"
#include "ubbd_bitmap.h"

static int find_next(struct ubbd_bitmap *bitmap, uint64_t off,
		uint64_t *found, bool zero)
{
	uint64_t index = off;

	while (true) {
		if (++index >= bitmap->size)
			index = index % bitmap->size;

		if (index == off) {
			/* not found */
			break;
		}

		if ((zero && !ubbd_bit_test(bitmap, index)) ||
			(!zero && ubbd_bit_test(bitmap, index))) {
			*found = index;
			return 0;
		}
	}

	return -1;
}

int ubbd_bit_find_next(struct ubbd_bitmap *bitmap, uint64_t off, uint64_t *found_bit)
{
	return find_next(bitmap, off, found_bit, false);
}

int ubbd_bit_find_next_zero(struct ubbd_bitmap *bitmap, uint64_t off, uint64_t *found_bit)
{
	return find_next(bitmap, off, found_bit, true);
}

struct ubbd_bitmap *ubbd_bitmap_alloc(uint32_t size)
{
	struct ubbd_bitmap *bitmap;

	bitmap = calloc(1, sizeof(struct ubbd_bitmap) +
			((ubbd_roundup(size, 8) >> UBBD_BITMAP_SHIFT) * sizeof(uint8_t)));
	if (!bitmap) {
		ubbd_err("failed to alloc bitmap.\n");
		return NULL;
	}
	bitmap->size = size;

	return bitmap;
}

void ubbd_bitmap_free(struct ubbd_bitmap *bitmap)
{
	free(bitmap);
}
