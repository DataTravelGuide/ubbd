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


int device_close_shm(struct ubbd_device *ubbd_dev)
{
	int ret;

	ret = munmap(ubbd_dev->map, ubbd_dev->uio_map_size);
	if (ret != 0) {
		ubbd_err("could not unmap device %s: %d\n", ubbd_dev->dev_name, errno);
	}

	ret = close(ubbd_dev->fd);
	if (ret != 0) {
		ubbd_err("could not close device fd for %s: %d\n", ubbd_dev->dev_name, errno);
	}

	return ret;
}


int device_open_shm(struct ubbd_device *ubbd_dev)
{
	char *mmap_name;

	if (asprintf(&mmap_name, "/dev/uio%d", ubbd_dev->uio_id) == -1) {
		ubbd_err("cont init mmap name\n");
		goto err_fail;
	}

	ubbd_dev->fd = open(mmap_name, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (ubbd_dev->fd == -1) {
		ubbd_err("could not open %s\n", mmap_name);
		goto err_mmap_name;
	}
	ubbd_info("fd: %d\n", ubbd_dev->fd);

	/* bring the map into memory */
	ubbd_dev->map = mmap(NULL, ubbd_dev->uio_map_size, PROT_READ|PROT_WRITE, MAP_SHARED, ubbd_dev->fd, 0);
	if (ubbd_dev->map == MAP_FAILED) {
		ubbd_err("could not mmap %s\n", mmap_name);
		goto err_fd_close;
	}

	ubbd_info("version: %d\n", ubbd_dev->map->version);

	return true;

err_fd_close:
	close(ubbd_dev->fd);
err_mmap_name:
	free(mmap_name);
err_fail:
	return false;
}


void ubbdlib_processing_start(struct ubbd_device *dev)
{
	int r;
	uint32_t buf;

	/* Clear the event on the fd */
	do {
		r = read(dev->fd, &buf, 4);
	} while (r == -1 && errno == EINTR);
	if (r == -1 && errno != EAGAIN) {
		ubbd_err("failed to read device /dev/%s, %d\n",
			 "uio0", errno);
		exit(-errno);
	}
}

void ubbdlib_processing_complete(struct ubbd_device *dev)
{
	int r;
	uint32_t buf = 0;

	/* Tell the kernel there are completed commands */
	do {
		r = write(dev->fd, &buf, 4);
	} while (r == -1 && errno == EINTR);
	if (r == -1 && errno != EAGAIN) {
		ubbd_err("failed to write device /dev/%s, %d\n",
			 dev->dev_name, errno);
		exit(-errno);
	}
}


struct ubbd_se *device_cmd_head(struct ubbd_device *dev)
{
        struct ubbd_sb *sb = dev->map;

	ubbd_dbg("cmd: head: %u tail: %u\n", sb->cmd_head, sb->cmd_tail);

        return (struct ubbd_se *) ((char *) sb + sb->cmdr_off + sb->cmd_head);
}

struct ubbd_se *device_cmd_tail(struct ubbd_device *dev)
{
	struct ubbd_sb *sb = dev->map;

	ubbd_dbg("cmd: tail: %u\n", sb->cmd_tail);

	return (struct ubbd_se *) ((char *) sb + sb->cmdr_off + sb->cmd_tail);
}

struct ubbd_se *device_cmd_to_handle(struct ubbd_device *dev)
{
	struct ubbd_sb *sb = dev->map;

	ubbd_dbg("cmd: handled: %u\n", dev->se_to_handle);

	return (struct ubbd_se *) ((char *) sb + sb->cmdr_off + dev->se_to_handle);
}

struct ubbd_se *get_oldest_se(struct ubbd_device *ubbd_dev)
{
	struct ubbd_sb *sb = ubbd_dev->map;

	if (sb->cmd_tail == sb->cmd_head)
		return NULL;

	return (struct ubbd_se *) ((char *) sb + sb->cmdr_off + sb->cmd_tail);
}

void ubbd_uio_advance_cmd_ring(struct ubbd_device *ubbd_dev)
{
	struct ubbd_se *se;
	struct ubbd_sb *sb = ubbd_dev->map;

again:
	se = get_oldest_se(ubbd_dev);
	if (!se)
		return;

	if (se->header.flags) {
		UBBD_UPDATE_DEV_TAIL(ubbd_dev, sb, se);
		goto again;
	}
	return;
}
