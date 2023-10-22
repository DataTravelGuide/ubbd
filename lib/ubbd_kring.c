#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>

#include "ubbd_dev.h"
#include "utils.h"
#include "ubbd_kring.h"
#include "ubbd_queue.h"


void *ubbd_kring_get_info(struct ubbd_kring_info *kring_info)
{
	struct ubbd_sb *sb = kring_info->map;

	if (sb->magic != UBBD_MAGIC) {
		ubbd_err("invalid magic: %llx (expected: %llx)\n", sb->magic, UBBD_MAGIC);
		return NULL;
	}

	ubbd_dbg("info_off: %u\n", sb->info_off);

	return (void *)((char *)kring_info->map + sb->info_off);
}

int ubbd_close_kring(struct ubbd_kring_info *kring_info)
{
	int ret;
	int retval = 0;

	if (!kring_info || !kring_info->map)
		return 0;

	ret = munmap(kring_info->map, kring_info->kring_map_size);
	if (ret != 0) {
		ubbd_err("could not unmap device: %d\n", errno);
		retval = ret;
	}

	ret = close(kring_info->fd);
	if (ret != 0) {
		ubbd_err("could not close device fd for: %d\n", errno);
		if (!retval) {
			retval = ret;
		}
	}

	kring_info->map = NULL;

	return retval;
}


int ubbd_open_kring(struct ubbd_kring_info *kring_info)
{
	char *mmap_name;
	int mmap_prot;

	if (asprintf(&mmap_name, "/dev/ubbd_kring%d", kring_info->kring_id) == -1) {
		ubbd_err("cont init mmap name\n");
		goto err_fail;
	}

	kring_info->fd = open(mmap_name, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (kring_info->fd == -1) {
		ubbd_err("could not open %s\n", mmap_name);
		goto err_mmap_name;
	}
	ubbd_info("fd: %d\n", kring_info->fd);

	mmap_prot = PROT_READ|PROT_WRITE;

	kring_info->map = mmap(NULL, kring_info->kring_map_size, mmap_prot, MAP_SHARED, kring_info->fd, 0);
	if (kring_info->map == MAP_FAILED) {
		ubbd_err("could not mmap %s, %d\n", mmap_name, errno);
		goto err_fd_close;
	}

	ubbd_info("version: %d\n", kring_info->map->version);
	free(mmap_name);

	return 0;

err_fd_close:
	close(kring_info->fd);
err_mmap_name:
	free(mmap_name);
err_fail:
	return -1;
}


int ubbd_processing_start(struct ubbd_kring_info *kring_info)
{
	int r;
	uint32_t buf;

	/* Clear the event on the fd */
	do {
		r = read(kring_info->fd, &buf, 4);
	} while (r == -1 && errno == EINTR);

	if (r == -1 && errno != EAGAIN) {
		ubbd_err("failed to read device /dev/ubbd_kring%d: %d\n",
			 kring_info->kring_id, errno);
		return -errno;
	}

	return 0;
}

int ubbd_processing_complete(struct ubbd_kring_info *kring_info)
{
	int r;
	uint32_t buf = 0;

	/* Tell the kernel there are completed commands */
	do {
		r = write(kring_info->fd, &buf, 4);
	} while (r == -1 && errno == EINTR);

	if (r == -1 && errno != EAGAIN) {
		ubbd_err("failed to write kring device /dev/ubbd_kring%d: %d\n",
			 kring_info->kring_id, errno);
		return -errno;
	}

	return 0;
}

struct ubbd_se *ubbd_cmd_head(struct ubbd_kring_info *kring_info)
{
        struct ubbd_sb *sb = kring_info->map;

	ubbd_dbg("cmd: head: %u tail: %u\n", sb->cmd_head, sb->cmd_tail);

        return (struct ubbd_se *) ((char *) sb + sb->cmdr_off + sb->cmd_head);
}

struct ubbd_se *ubbd_cmd_to_handle(struct ubbd_queue *ubbd_q)
{
	struct ubbd_sb *sb = ubbd_q->kring_info.map;

	ubbd_dbg("cmd: handled: %u\n", ubbd_q->se_to_handle);

	return (struct ubbd_se *) ((char *) sb + sb->cmdr_off + ubbd_q->se_to_handle);
}
