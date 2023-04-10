#define _GNU_SOURCE
#include "ubbd_backend.h"

#define MEM_BACKEND(ubbd_b) ((struct ubbd_mem_backend *)container_of(ubbd_b, struct ubbd_mem_backend, ubbd_b))

pthread_mutex_t mem_backend_mutex = PTHREAD_MUTEX_INITIALIZER;

struct mem_block {
	char addr[UBBD_MEM_BLK_SIZE];
};

static struct mem_block *mem_blocks[UBBD_MEM_BLK_COUNT] = { 0 };

struct mem_block *mem_block_alloc(uint64_t blkid) {
	struct mem_block *block = NULL;

	block = calloc(1, sizeof(*block));
	if (!block)
		return NULL;

	return block;
}

int get_mem_block(uint64_t offset, struct mem_block **block_ret, bool alloc) {
	struct mem_block *block = NULL;
	uint64_t blkid = offset >> UBBD_MEM_BLK_SHIFT;
	int ret = 0;

	pthread_mutex_lock(&mem_backend_mutex);
	block = mem_blocks[blkid];
	if (block) {
		*block_ret = block;
	} else {
		block = mem_block_alloc(blkid);
		if (!block) {
			ret = -ENOMEM;
			goto out;
		}
		*block_ret = mem_blocks[blkid] = block;
	}
out:
	pthread_mutex_unlock(&mem_backend_mutex);
	return ret;
}

struct ubbd_backend_ops mem_backend_ops;

static struct ubbd_backend* mem_backend_create(struct __ubbd_dev_info *info)
{
	struct ubbd_mem_backend *mem_backend;
	struct ubbd_backend *ubbd_b;

	mem_backend = calloc(1, sizeof(*mem_backend));
	if (!mem_backend)
		return NULL;

	ubbd_b = &mem_backend->ubbd_b;
	ubbd_b->dev_type = UBBD_DEV_TYPE_MEM;
	ubbd_b->backend_ops = &mem_backend_ops;
	ubbd_b->dev_size = info->size;

	return ubbd_b;
}

static int mem_backend_open(struct ubbd_backend *ubbd_b)
{
	return 0;
}

static void mem_backend_close(struct ubbd_backend *ubbd_b)
{
	return;
}

static void mem_backend_release(struct ubbd_backend *ubbd_b)
{
	struct ubbd_mem_backend *mem_backend = MEM_BACKEND(ubbd_b);
	int i = 0;

	pthread_mutex_lock(&mem_backend_mutex);
	for (i = 0; i < UBBD_MEM_BLK_COUNT; i++) {
		free(mem_blocks[i]);
		mem_blocks[i] = NULL;
	}
	pthread_mutex_unlock(&mem_backend_mutex);

	if (mem_backend)
		free(mem_backend);
}

static int mem_backend_writev(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct mem_block *block = NULL;
	int off_in_blk;
	ssize_t count = 0;
	int ret = 0;
	int i;
	ssize_t len, off_in_iov = 0;
	void *base;

	for (i = 0; i < io->iov_cnt; i++) {
		off_in_iov = 0;
again:
		off_in_blk = (io->offset + count) & UBBD_MEM_BLK_MASK;
		ret = get_mem_block(io->offset + count, &block, true);
		if (ret) {
			ubbd_err("failed to get mem block.\n");
			goto out;
		}

		base = io->iov[i].iov_base + off_in_iov;
		len = MIN(io->iov[i].iov_len - off_in_iov, UBBD_MEM_BLK_SIZE - off_in_blk);
		/* avoid overflow */
		len = MIN(len, io->len - count);
		memcpy(block->addr + off_in_blk, base, len);

		count += len;
		if (count >= io->len) {
			break;
		}

		off_in_iov += len;
		if (off_in_iov < io->iov[i].iov_len) {
			/* iov not finished, goto next block */
			goto again;
		}
	}

	ret = count == io->len? 0 : -5;
	ubbd_backend_io_finish(io, ret);

out:
	return ret;
}

static int mem_backend_readv(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	struct mem_block *block = NULL;
	int off_in_blk;
	ssize_t count = 0;
	int ret = 0;
	int i;
	ssize_t len, off_in_iov = 0;
	void *base;

	for (i = 0; i < io->iov_cnt; i++) {
		off_in_iov = 0;
again:
		off_in_blk = (io->offset + count) & UBBD_MEM_BLK_MASK;
		ret = get_mem_block(io->offset + count, &block, false);
		if (ret) {
			ubbd_err("failed to get mem block for read.\n");
			goto out;
		}

		base = io->iov[i].iov_base + off_in_iov;
		if (block) {
			len = MIN(io->iov[i].iov_len - off_in_iov, UBBD_MEM_BLK_SIZE - off_in_blk);
			/* avoid overflow */
			len = MIN(len, io->len - count);
			memcpy(base, block->addr + off_in_blk, len);
		} else {
			len = MIN(io->iov[i].iov_len, io->len - count);
			memset(base, 0, len);
		}

		count += len;
		if (count >= io->len) {
			break;
		}
		off_in_iov += len;
		if (off_in_iov < io->iov[i].iov_len) {
			/* iov not finished, goto next block */
			goto again;
		}
	}

	ret = count == io->len? 0 : -5;
	ubbd_backend_io_finish(io, ret);

out:
	return ret;
}

static int mem_backend_flush(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	ubbd_backend_io_finish(io, 0);

	return 0;
}

struct ubbd_backend_ops mem_backend_ops = {
	.create = mem_backend_create,
	.open = mem_backend_open,
	.close = mem_backend_close,
	.release = mem_backend_release,
	.writev = mem_backend_writev,
	.readv = mem_backend_readv,
	.flush = mem_backend_flush,
};
