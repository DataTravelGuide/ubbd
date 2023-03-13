#define _GNU_SOURCE
#include "ubbd_uio.h"
#include "ubbd_dev.h"

#define SSH_DEV(ubbd_dev) ((struct ubbd_ssh_device *)container_of(ubbd_dev, struct ubbd_ssh_device, ubbd_dev))

struct ubbd_dev_ops ssh_dev_ops;

static struct ubbd_device *ssh_dev_create(struct __ubbd_dev_info *info)
{
	struct ubbd_ssh_device *ssh_dev;
	struct ubbd_device *ubbd_dev;

	ssh_dev = calloc(1, sizeof(*ssh_dev));
	if (!ssh_dev)
		return NULL;

	ubbd_dev = &ssh_dev->ubbd_dev;
	ubbd_dev->dev_type = UBBD_DEV_TYPE_SSH;
	ubbd_dev->dev_ops = &ssh_dev_ops;

	return ubbd_dev;
}

static int ssh_dev_init(struct ubbd_device *ubbd_dev, bool reopen)
{
	ubbd_dev->dev_features.write_cache = false;
	ubbd_dev->dev_features.fua = false;
	ubbd_dev->dev_features.discard = false;
	ubbd_dev->dev_features.write_zeros = false;

	return 0;
}

static void ssh_dev_release(struct ubbd_device *ubbd_dev)
{
	struct ubbd_ssh_device *ssh_dev = SSH_DEV(ubbd_dev);

	free(ssh_dev);
}

struct ubbd_dev_ops ssh_dev_ops = {
	.create = ssh_dev_create,
	.init = ssh_dev_init,
	.release = ssh_dev_release,
};
