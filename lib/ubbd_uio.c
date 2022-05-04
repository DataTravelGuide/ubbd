#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>

#include "ubbd_dev.h"
#include "utils.h"
#include "ubbd_uio.h"

struct ubbd_dev_info *ubbd_uio_get_dev_info(void *map)
{
	struct ubbd_sb *sb = map;

	ubbd_dbg("info_off: %u\n", sb->info_off);

	return (struct ubbd_dev_info *)((char *)map + sb->info_off);
}


int device_close_shm(struct ubbd_uio_info *uio_info)
{
	int ret;

	ret = munmap(uio_info->map, uio_info->uio_map_size);
	if (ret != 0) {
		ubbd_err("could not unmap device: %d\n", errno);
	}

	ret = close(uio_info->fd);
	if (ret != 0) {
		ubbd_err("could not close device fd for: %d\n", errno);
	}

	return ret;
}


int device_open_shm(struct ubbd_uio_info *uio_info)
{
	char *mmap_name;

	if (asprintf(&mmap_name, "/dev/uio%d", uio_info->uio_id) == -1) {
		ubbd_err("cont init mmap name\n");
		goto err_fail;
	}

	uio_info->fd = open(mmap_name, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (uio_info->fd == -1) {
		ubbd_err("could not open %s\n", mmap_name);
		goto err_mmap_name;
	}
	ubbd_info("fd: %d\n", uio_info->fd);

	uio_info->map = mmap(NULL, uio_info->uio_map_size, PROT_READ|PROT_WRITE, MAP_SHARED, uio_info->fd, 0);
	if (uio_info->map == MAP_FAILED) {
		ubbd_err("could not mmap %s\n", mmap_name);
		goto err_fd_close;
	}

	ubbd_info("version: %d\n", uio_info->map->version);
	free(mmap_name);

	return 0;

err_fd_close:
	close(uio_info->fd);
err_mmap_name:
	free(mmap_name);
err_fail:
	return -1;
}


void ubbdlib_processing_start(struct ubbd_queue *ubbd_q)
{
	int r;
	uint32_t buf;

	/* Clear the event on the fd */
	do {
		r = read(ubbd_q->uio_info.fd, &buf, 4);
	} while (r == -1 && errno == EINTR);
	if (r == -1 && errno != EAGAIN) {
		ubbd_err("failed to read device /dev/%s, %d\n",
			 "uio0", errno);
		exit(-errno);
	}
}

void ubbdlib_processing_complete(struct ubbd_queue *ubbd_q)
{
	int r;
	uint32_t buf = 0;

	/* Tell the kernel there are completed commands */
	do {
		r = write(ubbd_q->uio_info.fd, &buf, 4);
	} while (r == -1 && errno == EINTR);
	if (r == -1 && errno != EAGAIN) {
		ubbd_err("failed to write uio device, %d\n",
			 errno);
		exit(-errno);
	}
}


struct ubbd_se *device_cmd_head(struct ubbd_queue *ubbd_q)
{
        struct ubbd_sb *sb = ubbd_q->uio_info.map;

	ubbd_dbg("cmd: head: %u tail: %u\n", sb->cmd_head, sb->cmd_tail);

        return (struct ubbd_se *) ((char *) sb + sb->cmdr_off + sb->cmd_head);
}

struct ubbd_se *device_cmd_tail(struct ubbd_queue *ubbd_q)
{
	struct ubbd_sb *sb = ubbd_q->uio_info.map;

	ubbd_dbg("cmd: tail: %u\n", sb->cmd_tail);

	return (struct ubbd_se *) ((char *) sb + sb->cmdr_off + sb->cmd_tail);
}

struct ubbd_se *device_cmd_to_handle(struct ubbd_queue *ubbd_q)
{
	struct ubbd_sb *sb = ubbd_q->uio_info.map;

	ubbd_dbg("cmd: handled: %u\n", ubbd_q->se_to_handle);

	return (struct ubbd_se *) ((char *) sb + sb->cmdr_off + ubbd_q->se_to_handle);
}

struct ubbd_se *get_oldest_se(struct ubbd_queue *ubbd_q)
{
	struct ubbd_sb *sb = ubbd_q->uio_info.map;

	if (sb->cmd_tail == sb->cmd_head)
		return NULL;

	return (struct ubbd_se *) ((char *) sb + sb->cmdr_off + sb->cmd_tail);
}
