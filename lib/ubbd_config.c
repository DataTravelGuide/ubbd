#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "ubbd_backend.h"
#include "ubbd_config.h"

static char *get_backend_conf_path(int dev_id)
{
	char *path;

	if (asprintf(&path, "%s/ubbd%d_backend_config", UBBD_LIB_DIR, dev_id) == -1) {
		ubbd_err("failed to init backend config path.\n");
		return NULL;
	}

	return path;
}

static char *get_dev_conf_path(int dev_id)
{
	char *path;

	if (asprintf(&path, "%s/ubbd%d_dev_config", UBBD_LIB_DIR, dev_id) == -1) {
		ubbd_err("failed to init dev config path.\n");
		return NULL;
	}

	return path;
}

static size_t get_conf_size(struct ubbd_conf_header *conf_header)
{
	if (conf_header->conf_type == UBBD_CONF_TYPE_BACKEND) {
		ubbd_err("backend size: %lu\n", sizeof(struct ubbd_backend_conf));
		return sizeof(struct ubbd_backend_conf);
	} else if (conf_header->conf_type == UBBD_CONF_TYPE_DEVICE) {
		ubbd_err("dev size: %lu\n", sizeof(struct ubbd_dev_conf));
		return sizeof(struct ubbd_dev_conf);
	} else {
		ubbd_err("unrecognized config type: %d\n", conf_header->conf_type);
		return 0;
	}
}

static void check_conf_dir(void)
{
	struct stat st = {0};

	if (stat(UBBD_LIB_DIR, &st) == -1)
		mkdir(UBBD_LIB_DIR, 0644);
}


static struct ubbd_conf_header *conf_get_header(char *conf_path)
{
	int fd;
	struct ubbd_conf_header *header;
	size_t len;

	header = calloc(1, sizeof(struct ubbd_conf_header));
	if (!header) {
		ubbd_err("failed to alloc for conf_header.\n");
		return NULL;
	}

	check_conf_dir();

	fd = open(conf_path, O_RDONLY);
	if (fd == -1) {
		ubbd_err("failed to open %s\n", conf_path);
		free(header);
		return NULL;
	}

	len = read(fd, header, sizeof(struct ubbd_conf_header));
	close(fd);
	if (len != sizeof(struct ubbd_conf_header)) {
		ubbd_err("read conf_header len is %lu not expected: %lu\n", len, sizeof(struct ubbd_conf_header));
		free(header);
		return NULL;
	}

	if (header->magic != UBBD_CONFIG_MAGIC) {
		ubbd_err("wrong magic in config header\n");
		free(header);
		return NULL;
	}

	return header;
}

static int __conf_read(char *conf_path, void *data, size_t len)
{
	int fd;
	size_t read_len;

	fd = open(conf_path, O_RDONLY);
	if (fd == -1) {
		ubbd_err("failed to open %s\n", conf_path);
		return -1;
	}

	read_len = read(fd, data, len);
	close(fd);
	if (read_len < 0) {
		ubbd_err("read config failed: %ld, %s\n", read_len, strerror(errno));
		return -1;
	}

	return 0;
}

static void *ubbd_conf_read(char *conf_path, int conf_type)
{
	struct ubbd_conf_header *conf_header;
	size_t conf_size;
	void *data = NULL;

	conf_header = conf_get_header(conf_path);
	if (!conf_header) {
		ubbd_err("failed to get config header.\n");
		goto out;
	}

	if (conf_header->conf_type != conf_type) {
		ubbd_err("wrong conf_type, expected: %d, but got: %d.\n", conf_type, conf_header->conf_type);
		goto free_header;
	}

	conf_size = get_conf_size(conf_header);

	data = calloc(1, conf_size);
	if (!data) {
		ubbd_err("failed to alloc for config data.\n");
		goto free_header;
	}

	if (__conf_read(conf_path, data, conf_size)) {
		ubbd_err("failed to read config data\n");
		free(data);
		data = NULL;
	}

free_header:
	free(conf_header);
out:
	return data;
}

static void *read_backend_conf(int dev_id, int conf_type)
{
	char *conf_path;
	void *data = NULL;

	conf_path = get_backend_conf_path(dev_id);
	if (!conf_path)
		goto out;

	data = ubbd_conf_read(conf_path, conf_type);
	if (!data) {
		ubbd_err("failed to read backend config.\n");
		goto free_path;
	}

free_path:
	free(conf_path);
out:
	return data;
}

struct ubbd_backend_conf *ubbd_conf_read_backend_conf(int dev_id)
{
	return read_backend_conf(dev_id, UBBD_CONF_TYPE_BACKEND);
}

static void *read_dev_conf(int dev_id, int conf_type)
{
	char *conf_path;
	void *data = NULL;

	conf_path = get_dev_conf_path(dev_id);
	if (!conf_path)
		goto out;

	data = ubbd_conf_read(conf_path, conf_type);
	if (!data) {
		ubbd_err("failed to read backend config.\n");
		goto free_path;
	}

free_path:
	free(conf_path);
out:
	return data;
}

struct ubbd_dev_conf *ubbd_conf_read_dev_conf(int dev_id)
{
	return read_dev_conf(dev_id, UBBD_CONF_TYPE_DEVICE);
}

/* write config */

static int __conf_write(char *conf_path, void *data, size_t len)
{
	int fd;
	size_t write_len;

	check_conf_dir();

	fd = open(conf_path, O_WRONLY | O_CREAT);
	if (fd == -1) {
		ubbd_err("failed to open %s for write\n", conf_path);
		return -1;
	}

	write_len = write(fd, data, len);
	close(fd);
	if (write_len < 0 ) {
		ubbd_err("write config failed: %ld, %s\n", write_len, strerror(errno));
		return -1;
	}

	return 0;
}

int ubbd_conf_write(char *conf_path, void *data, size_t len)
{
	struct ubbd_conf_header *header;

	header = (struct ubbd_conf_header *)data;

	if (header->magic != UBBD_CONFIG_MAGIC) {
		ubbd_err("data is not a ubbd_config item\n");
		return -1;
	}

	return __conf_write(conf_path, data, len);
}

static int write_backend_conf(int dev_id, void *data, size_t len)
{
	char *conf_path;
	int ret = -ENOMEM;

	conf_path = get_backend_conf_path(dev_id);
	if (!conf_path)
		goto out;

	ret = ubbd_conf_write(conf_path, data, len);
	if (ret) {
		ubbd_err("failed to write backend config.\n");
		goto free_path;
	}

free_path:
	free(conf_path);
out:
	return ret;
}


int ubbd_conf_write_backend_conf(struct ubbd_backend_conf *b_conf)
{
	return write_backend_conf(b_conf->dev_id, b_conf, sizeof(*b_conf));
}

static int write_dev_conf(int dev_id, void *data, size_t len)
{
	char *conf_path;
	int ret = -ENOMEM;

	conf_path = get_dev_conf_path(dev_id);
	if (!conf_path)
		goto out;

	ret = ubbd_conf_write(conf_path, data, len);
	if (ret) {
		ubbd_err("failed to write dev config.\n");
		goto free_path;
	}

free_path:
	free(conf_path);
out:
	return ret;
}


int ubbd_conf_write_dev_conf(struct ubbd_dev_conf *dev_conf)
{
	return write_dev_conf(dev_conf->dev_id, dev_conf, sizeof(*dev_conf));
}
