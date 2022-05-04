#define _GNU_SOURCE
#include <getopt.h>
#include <sys/types.h>

#include "ubbd_mgmt.h"
#include "utils.h"
#include "ubbd_netlink.h"


enum ubbd_mgmt_cmd str_to_cmd(char *str)
{
	enum ubbd_mgmt_cmd cmd;

	if (!strcmp("map", str))
		cmd = UBBD_MGMT_CMD_MAP;
	else if (!strcmp("unmap", str))
		cmd = UBBD_MGMT_CMD_UNMAP;
	else if (!strcmp("config", str))
		cmd = UBBD_MGMT_CMD_CONFIG;
	else
		cmd = -1;

	return cmd;
}

static enum ubbd_dev_type str_to_type(char *str)
{
	enum ubbd_dev_type type;

	if (!strcmp("file", str))
		type = UBBD_DEV_TYPE_FILE;
	else if (!strcmp("rbd", str))
		type = UBBD_DEV_TYPE_RBD;
	else if (!strcmp("null", str))
		type = UBBD_DEV_TYPE_NULL;
	else
		type = -1;

	return type;
}

static struct option const long_options[] =
{
	{"command", required_argument, NULL, 'c'},
	{"type", required_argument, NULL, 't'},
	{"filepath", required_argument, NULL, 'f'},
	{"devsize", required_argument, NULL, 's'},
	{"force", no_argument, NULL, 'o'},
	{"pool", required_argument, NULL, 'p'},
	{"image", required_argument, NULL, 'i'},
	{"ubbdid", required_argument, NULL, 'u'},
	{"data-pages-reserve", required_argument, NULL, 'r'},
	{"num-queues", required_argument, NULL, 'q'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static char *short_options = "c:t:f:p:i:u:h:s:o:r:q";

static void usage(int status)
{ 
	if (status != 0)
		fprintf(stderr, "Try `ubbdadm --help' for more information.\n");
	else {
		printf("\
			ubbdadm --command map --type file --filepath PATH --devsize SIZE\n\
			ubbdadm --command map --type rbd --pool POOL --image IMANGE \n\
			ubbdadm --command unmap --ubbdid ID\n");
	}
	exit(status);
}

static int do_file_map(char *filepath, uint64_t devsize, uint32_t num_queues)
{
	struct ubbd_mgmt_request req = {0};
	struct ubbd_mgmt_rsp rsp = {0};
	int fd;
	int ret;

	req.cmd = UBBD_MGMT_CMD_MAP;
	req.u.add.info.num_queues = num_queues;
	req.u.add.info.type = UBBD_DEV_TYPE_FILE;
	strcpy(req.u.add.info.file.path, filepath);
	req.u.add.info.file.size = devsize;
	ret = ubbdd_request(&fd, &req);
	if (ret) {
		ubbd_err("failed to send map request to ubbdd: %d.\n", ret);
		return ret;
	}
	
	ret = ubbdd_response(fd, &rsp, -1);
	if (ret) {
		ubbd_err("error in waiting response for map request: %d.\n", ret);
		return ret;
	}

	fprintf(stdout, "%s\n", rsp.u.add.path);

	return 0;
}

static int do_rbd_map(char *pool, char *image, uint32_t num_queues)
{
	struct ubbd_mgmt_request req = {0};
	struct ubbd_mgmt_rsp rsp = {0};
	int fd;
	int ret;

	req.cmd = UBBD_MGMT_CMD_MAP;
	req.u.add.info.num_queues = num_queues;
	req.u.add.info.type = UBBD_DEV_TYPE_RBD;
	strcpy(req.u.add.info.rbd.pool, pool);
	strcpy(req.u.add.info.rbd.image, image);
	ret = ubbdd_request(&fd, &req);
	if (ret) {
		ubbd_err("failed to send map request to ubbdd: %d.\n", ret);
		return ret;
	}
	
	ret = ubbdd_response(fd, &rsp, -1);
	if (ret) {
		ubbd_err("error in waiting response for map request: %d.\n", ret);
		return ret;
	}
	return 0;
}

static int do_null_map(uint64_t dev_size, uint32_t num_queues)
{
	struct ubbd_mgmt_request req = {0};
	struct ubbd_mgmt_rsp rsp = {0};
	int fd;
	int ret;

	req.cmd = UBBD_MGMT_CMD_MAP;
	req.u.add.info.num_queues = num_queues;
	req.u.add.info.type = UBBD_DEV_TYPE_NULL;
	req.u.add.info.null.size = dev_size;
	ret = ubbdd_request(&fd, &req);
	if (ret) {
		ubbd_err("failed to send map request to ubbdd: %d.\n", ret);
		return ret;
	}
	
	ret = ubbdd_response(fd, &rsp, -1);
	if (ret) {
		ubbd_err("error in waiting response for map request: %d.\n", ret);
		return ret;
	}
	return 0;
}

static int do_unmap(int ubbdid, bool force)
{
	struct ubbd_mgmt_request req = {0};
	struct ubbd_mgmt_rsp rsp = {0};
	int fd;
	int ret;

	req.cmd = UBBD_MGMT_CMD_UNMAP;
	req.u.remove.dev_id = ubbdid;
	req.u.remove.force = force;

	ret = ubbdd_request(&fd, &req);
	if (ret) {
		ubbd_err("failed to send map request to ubbdd: %d.\n", ret);
		return ret;
	}
	
	ret = ubbdd_response(fd, &rsp, -1);
	if (ret) {
		ubbd_err("error in waiting response for map request: %d.\n", ret);
		return ret;
	}
	return 0;
}

static int do_config(int ubbdid, int data_pages_reserve)
{
	struct ubbd_mgmt_request req = {0};
	int fd;

	req.cmd = UBBD_MGMT_CMD_CONFIG;
	req.u.config.dev_id = ubbdid;
	req.u.config.data_pages_reserve = data_pages_reserve;
	ubbdd_request(&fd, &req);

	return 0;
}

int main(int argc, char **argv)
{
	int ch, longindex;
	enum ubbd_mgmt_cmd command;
	enum ubbd_dev_type type;
	char *filepath, *pool, *image;
	uint64_t dev_size;
	int ubbdid;
	int data_pages_reserve;
	bool force = false;
	int ret = 0;
	uint32_t num_queues = 0;

	optopt = 0;
	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'c':
			command = str_to_cmd(optarg);
			break;
		case 't':
			type = str_to_type(optarg);
			break;
		case 'f':
			filepath = optarg;
			break;
		case 's':
			dev_size = atoll(optarg);
			break;
		case 'o':
			force = true;
			break;
		case 'p':
			pool = optarg;
			break;
		case 'i':
			image = optarg;
			break;
		case 'u':
			ubbdid = atoi(optarg);
			break;
		case 'r':
			data_pages_reserve = atoi(optarg);
			break;
		case 'q':
			num_queues = atoi(optarg);
			break;
		case 'h':
			usage(0);
		}
	}

	if (optopt) {
		ubbd_err("unrecognized character '%c'\n", optopt);
		return -1;
	}

	if (command == UBBD_MGMT_CMD_MAP) {
		switch (type) {
		case UBBD_DEV_TYPE_FILE:
			ret = do_file_map(filepath, dev_size, num_queues);
			break;
		case UBBD_DEV_TYPE_RBD:
			ret = do_rbd_map(pool, image, num_queues);
			break;
		case UBBD_DEV_TYPE_NULL:
			ret = do_null_map(dev_size, num_queues);
			break;
		default:
			printf("error type: %d\n", type);
			exit(-1);
		}
	} else if (command == UBBD_MGMT_CMD_UNMAP) {
		ret = do_unmap(ubbdid, force);
	} else if (command == UBBD_MGMT_CMD_CONFIG) {
		if (data_pages_reserve < 0 ||
				data_pages_reserve > 100) {
			ubbd_err("data_pages_reserve should be [0 - 100]\n");
			exit(-1);
		}

		ret = do_config(ubbdid, data_pages_reserve);
	} else {
		printf("error command: %d\n", command);
		exit(-1);
	}

	return ret;
}
