#define _GNU_SOURCE
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/mngt.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <pthread.h>
#include <sched.h>

#include "utils.h"
#include "ubbd_netlink.h"
#include "ubbd_dev.h"
#include "ubbd_uio.h"
#include "ubbd.h"

#define UBBD_NL_VERSION 1

static LIST_HEAD(ubbd_nl_req_list);
static pthread_mutex_t ubbd_nl_req_list_lock;
static pthread_cond_t	ubbd_nl_thread_cond;
static int ubbd_nl_queue_req(struct ubbd_device *ubbd_dev, struct ubbd_nl_req *req);

static struct nla_policy ubbd_status_policy[UBBD_STATUS_ATTR_MAX + 1] = {
	[UBBD_STATUS_DEV_ID] = { .type = NLA_S32 },
	[UBBD_STATUS_QUEUE_INFO] = { .type = NLA_NESTED },
	[UBBD_STATUS_STATUS] = { .type = NLA_U8 },
};

static struct nla_policy ubbd_queue_info_policy[UBBD_QUEUE_INFO_ATTR_MAX + 1] = {
	[UBBD_QUEUE_INFO_UIO_ID] = { .type = NLA_S32 },
	[UBBD_QUEUE_INFO_UIO_MAP_SIZE] = { .type = NLA_U64 },
};

static struct ubbd_nl_req *nl_req_alloc()
{
	return calloc(1, sizeof(struct ubbd_nl_req));
}

static void nl_req_free(struct ubbd_nl_req *req)
{
	if (!req)
		return;

	free(req);
}

static struct nl_sock *get_ubbd_socket(int *driver_id)
{
	struct nl_sock *socket;

	socket = nl_socket_alloc();
	if (!socket) {
		ubbd_err("Couldn't allocate netlink socket\n");
		return NULL;
	}

	if (genl_connect(socket)) {
		ubbd_err("Couldn't connect to the generic netlink socket\n");
		goto free_sock;
	}

	*driver_id = genl_ctrl_resolve(socket, "UBBD");
	if (*driver_id < 0) {
		ubbd_err("Couldn't resolve the ubbd netlink family, make sure the ubbd module is loaded.\n");
		goto close_sock;
	}

	return socket;

close_sock:
	nl_close(socket);
free_sock:
	nl_socket_free(socket);
	return NULL;
}

static void ubbd_socket_close(struct nl_sock *socket)
{
	nl_close(socket);
	nl_socket_free(socket);
}

static int nl_callback(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *msg_attr[UBBD_ATTR_MAX + 1];
	int ret;

	ret = nla_parse(msg_attr, UBBD_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0), NULL);
	if (ret) {
		ubbd_err("Invalid response from the kernel\n");
		goto out;
	}

	ret = nla_get_s32(msg_attr[UBBD_ATTR_RETVAL]);
	if (ret)
		ubbd_err("error: %d\n", ret);
out:
	return ret;
}

static int send_netlink_remove_dev(struct ubbd_nl_req *req)
{
	struct ubbd_device *ubbd_dev = req->ubbd_dev;
	struct nl_msg *msg;
	void *hdr;
	int ret = -ENOMEM;
	struct nl_sock *socket;
	int driver_id;

	socket = get_ubbd_socket(&driver_id);
	if (!socket)
		return -1;

	nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, nl_callback, NULL);

	msg = nlmsg_alloc();
	if (!msg)
		goto close_sock;

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id,
			  0, 0, UBBD_CMD_REMOVE_DEV, UBBD_NL_VERSION);
	if (!hdr)
		goto free_msg;

	ret = nla_put_s32(msg, UBBD_ATTR_DEV_ID, ubbd_dev->dev_id);
	if (ret < 0)
		goto free_msg;

	ret = nl_send_sync(socket, msg);
	ubbd_socket_close(socket);
	return ret;

free_msg:
	nlmsg_free(msg);
close_sock:
	ubbd_socket_close(socket);
	return ret;
}

static int send_netlink_config(struct ubbd_nl_req *req)
{
	struct ubbd_device *ubbd_dev = req->ubbd_dev;
	struct nl_msg *msg;
	void *hdr;
	int ret = -ENOMEM;
	struct nl_sock *socket;
	int driver_id;
	struct nlattr *sock_attr;

	socket = get_ubbd_socket(&driver_id);
	if (!socket)
		return -1;

	nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, nl_callback, NULL);

	msg = nlmsg_alloc();
	if (!msg)
		goto close_sock;

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id,
			  0, 0, UBBD_CMD_CONFIG, UBBD_NL_VERSION);
	if (!hdr)
		goto free_msg;

	ret = nla_put_s32(msg, UBBD_ATTR_DEV_ID, ubbd_dev->dev_id);
	if (ret < 0)
		goto free_msg;

	sock_attr = nla_nest_start(msg, UBBD_ATTR_DEV_OPTS);
	if (!sock_attr) {
		ubbd_dev_err(ubbd_dev, "Couldn't nest config\n");
		goto free_msg;
	}

	ret = nla_put_u32(msg, UBBD_DEV_OPTS_DP_RESERVE, req->req_opts.config_opts.data_pages_reserve_percnt);
	if (ret < 0)
		goto free_msg;

	nla_nest_end(msg, sock_attr);

	ret = nl_send_sync(socket, msg);
	ubbd_socket_close(socket);
	if (ret) {
		ubbd_err("send_netlink_config ret of send: %d\n", ret);
	}

	return ret;

free_msg:
	nlmsg_free(msg);
close_sock:
	ubbd_socket_close(socket);
	return ret;
}

int send_netlink_remove_disk(struct ubbd_nl_req *req)
{
	struct ubbd_device *ubbd_dev = req->ubbd_dev;
	struct nl_msg *msg;
	void *hdr;
	int ret = -ENOMEM;
	struct nl_sock *socket;
	int driver_id;
	uint64_t flags = 0;

	socket = get_ubbd_socket(&driver_id);
	if (!socket)
		return -1;

	nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, nl_callback, NULL);

	msg = nlmsg_alloc();
	if (!msg)
		goto close_sock;

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id,
			  0, 0, UBBD_CMD_REMOVE_DISK, UBBD_NL_VERSION);
	if (!hdr)
		goto free_msg;

	ret = nla_put_s32(msg, UBBD_ATTR_DEV_ID, ubbd_dev->dev_id);
	if (ret < 0)
		goto free_msg;

	if (req->req_opts.remove_opts.force)
		flags |= UBBD_ATTR_FLAGS_REMOVE_FORCE;

	ret = nla_put_u64(msg, UBBD_ATTR_FLAGS, flags);
	if (ret < 0)
		goto free_msg;

	ret = nl_send_sync(socket, msg);
	ubbd_socket_close(socket);
	return ret;

free_msg:
	nlmsg_free(msg);
close_sock:
	ubbd_socket_close(socket);

	return ret;

}

static int send_netlink_add_disk(struct ubbd_nl_req *req)
{
	struct ubbd_device *ubbd_dev = req->ubbd_dev;
	struct nl_msg *msg;
	void *hdr;
	int ret = -ENOMEM;
	struct nl_sock *socket;
	int driver_id;

	socket = get_ubbd_socket(&driver_id);
	if (!socket)
		return -1;

	nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, nl_callback, NULL);

	msg = nlmsg_alloc();
	if (!msg)
		goto close_sock;

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id,
			  0, 0, UBBD_CMD_ADD_DISK, UBBD_NL_VERSION);
	if (!hdr)
		goto free_msg;

	ret = nla_put_s32(msg, UBBD_ATTR_DEV_ID, ubbd_dev->dev_id);
	if (ret < 0)
		goto free_msg;

	ret = nl_send_sync(socket, msg);
	ubbd_socket_close(socket);
	if (ret) {
		ubbd_info("ret of send auto netlink add: %d\n", ret);
	} else {
		ubbd_info("adde done\n");
	}
	return ret;

free_msg:
	nlmsg_free(msg);
close_sock:
	ubbd_socket_close(socket);
	return ret;
}

static int parse_status(struct nlattr *attr, struct ubbd_nl_dev_status *status);
static int add_dev_done_callback(struct nl_msg *msg, void *arg)
{
	struct ubbd_device *ubbd_dev = arg;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *msg_attr[UBBD_ATTR_MAX + 1];
	struct ubbd_nl_dev_status dev_status = { 0 };
	int ret;

	ret = nla_parse(msg_attr, UBBD_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0), NULL);
	if (ret) {
		ubbd_err("Invalid response from the kernel\n");
		return ret;
	}

	if (msg_attr[UBBD_ATTR_DEV_INFO]) {
		ret = parse_status(msg_attr[UBBD_ATTR_DEV_INFO], &dev_status);
		if (ret)
			goto out;
	} else {
		ubbd_err("no dev_info replyied in add_dev_don\n");
		ret = -EINVAL;
		goto out;
	}

	ret = ubbd_dev_init_from_dev_status(ubbd_dev, &dev_status);
	if (ret) {
		goto out;
	}

	ret = NL_OK;

out:
	return ret;
}

int send_netlink_add_dev(struct ubbd_nl_req *req)
{
	struct ubbd_device *ubbd_dev = req->ubbd_dev;
	struct nl_msg *msg;
	void *hdr;
	int ret = -ENOMEM;
	struct nl_sock *socket;
	int driver_id;
	uint64_t dev_features = 0;
	struct nlattr *dev_opts_attr;

	socket = get_ubbd_socket(&driver_id);
	if (!socket)
		return -1;

	nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, add_dev_done_callback, ubbd_dev);

	msg = nlmsg_alloc();
	if (!msg)
		goto close_sock;

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id,
			  0, 0, UBBD_CMD_ADD_DEV, UBBD_NL_VERSION);
	if (!hdr)
		goto free_msg;

        if (ubbd_dev->dev_features.write_cache)
                dev_features |= UBBD_ATTR_FLAGS_ADD_WRITECACHE;

	if (ubbd_dev->dev_features.fua)
		dev_features |= UBBD_ATTR_FLAGS_ADD_FUA;

	if (ubbd_dev->dev_features.discard)
		dev_features |= UBBD_ATTR_FLAGS_ADD_DISCARD;

	if (ubbd_dev->dev_features.write_zeros)
		dev_features |= UBBD_ATTR_FLAGS_ADD_WRITE_ZEROS;

	if (ubbd_dev->dev_features.read_only)
		dev_features |= UBBD_ATTR_FLAGS_ADD_READONLY;

        ret = nla_put_u64(msg, UBBD_ATTR_FLAGS, dev_features);
        if (ret < 0)
                goto free_msg;

	dev_opts_attr = nla_nest_start(msg, UBBD_ATTR_DEV_OPTS);
	if (!dev_opts_attr)
		goto free_msg;

	ret = nla_put_u64(msg, UBBD_DEV_OPTS_DEV_SIZE, ubbd_dev->dev_size);
	if (ret < 0)
		goto free_msg;

	ret = nla_put_u32(msg, UBBD_DEV_OPTS_DEV_QUEUES, ubbd_dev->num_queues);
	if (ret < 0)
		goto free_msg;

	ret = nla_put_u32(msg, UBBD_DEV_OPTS_IO_TIMEOUT, ubbd_dev->io_timeout);
	if (ret < 0)
		goto free_msg;

	if (ubbd_dev->sh_mem_size) {
		ret = nla_put_u32(msg, UBBD_DEV_OPTS_DATA_PAGES, ubbd_dev->sh_mem_size / PAGE_SIZE);
		if (ret < 0)
			goto free_msg;
	}

	nla_nest_end(msg, dev_opts_attr);

	ret = nl_send_sync(socket, msg);
	ubbd_socket_close(socket);
	if (ret < 0)
		ubbd_err("Could not send netlink cmd %d: %d\n", UBBD_CMD_ADD_DEV, ret);
	return ret;

free_msg:
	nlmsg_free(msg);
close_sock:
	ubbd_socket_close(socket);
	return ret;
}

static int parse_queue_info_cpu_list(cpu_set_t *cpuset, struct nlattr *attr)
{
	int rem;
	int c;
	struct nlattr *cpu_list_attr;

	nla_for_each_nested(cpu_list_attr, attr, rem) {
		c = nla_get_s32(&cpu_list_attr[UBBD_QUEUE_INFO_CPU_ID]);
		CPU_SET(c, cpuset);
	}

	return 0;
}


static int parse_status(struct nlattr *attr, struct ubbd_nl_dev_status *dev_status)
{
	struct nlattr *status[UBBD_STATUS_ATTR_MAX+1];
	struct nlattr *queue_info_attr;
	int num_queues = 0;
	int rem;
	int ret;

	ret = nla_parse_nested(status, UBBD_STATUS_ATTR_MAX, attr,
			       ubbd_status_policy);
	if (ret) {
		ubbd_err("failed to parse nested status\n");
		ret = -EINVAL;
		goto out;
	}

	dev_status->dev_id = nla_get_s32(status[UBBD_STATUS_DEV_ID]);
	dev_status->status = nla_get_u8(status[UBBD_STATUS_STATUS]);
	nla_for_each_nested(queue_info_attr, status[UBBD_STATUS_QUEUE_INFO], rem) {
		num_queues++;
	}

	dev_status->num_queues = num_queues;
	num_queues = 0;

	nla_for_each_nested(queue_info_attr, status[UBBD_STATUS_QUEUE_INFO], rem) {
		struct nlattr *queue_info[UBBD_QUEUE_INFO_ATTR_MAX + 1];

		ret = nla_parse_nested(queue_info, UBBD_QUEUE_INFO_ATTR_MAX,
				queue_info_attr, ubbd_queue_info_policy);
		if (ret) {
			ubbd_err("failed to parse nested queue_info\n");
			ret = -EINVAL;
			goto out;
		}
		dev_status->queue_infos[num_queues].uio_id = nla_get_s32(queue_info[UBBD_QUEUE_INFO_UIO_ID]);
		dev_status->queue_infos[num_queues].uio_map_size = nla_get_s32(queue_info[UBBD_QUEUE_INFO_UIO_MAP_SIZE]);
		dev_status->queue_infos[num_queues].backend_pid = nla_get_s32(queue_info[UBBD_QUEUE_INFO_B_PID]);
		dev_status->queue_infos[num_queues].status = nla_get_s32(queue_info[UBBD_QUEUE_INFO_STATUS]);

		ret = parse_queue_info_cpu_list(&dev_status->queue_infos[num_queues].cpuset, queue_info[UBBD_QUEUE_INFO_CPU_LIST]);
		if (ret) {
			ubbd_err("failed to parse nested cpu_list\n");
			ret = -EINVAL;
			goto out;
		}

		num_queues++;
	}

	return 0;
out:
	return ret;
}

static int status_callback(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *msg_attr[UBBD_ATTR_MAX + 1];
	int ret;
	struct ubbd_nl_dev_status *dev_status = arg;

	ret = nla_parse(msg_attr, UBBD_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0), NULL);
	if (ret) {
		ubbd_err("Invalid response from the kernel\n");
		return ret;
	}

	ret = nla_get_s32(msg_attr[UBBD_ATTR_RETVAL]);
	if (ret)
		return ret;

	if (msg_attr[UBBD_ATTR_DEV_INFO]) {
		ret = parse_status(msg_attr[UBBD_ATTR_DEV_INFO], dev_status);
		if (ret)
			goto out;
	}
out:
	return ret;
}

int ubbd_nl_dev_status(int dev_id, struct ubbd_nl_dev_status *dev_status)
{
	struct nl_msg *msg;
	void *hdr;
	int ret = -ENOMEM;
	struct nl_sock *socket;
	int driver_id;
	LIST_HEAD(tmp_list);

	socket = get_ubbd_socket(&driver_id);
	if (!socket)
		return -1;

	nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, status_callback, dev_status);

	msg = nlmsg_alloc();
	if (!msg)
		goto close_sock;

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id,
			  0, 0, UBBD_CMD_STATUS, UBBD_NL_VERSION);
	if (!hdr)
		goto free_msg;

	ret = nla_put_s32(msg, UBBD_ATTR_DEV_ID, dev_id);
	if (ret < 0)
		goto free_msg;

	ret = nl_send_sync(socket, msg);
	ubbd_socket_close(socket);
	if (ret < 0) {
		ubbd_err("Could not send netlink cmd %d, with dev_id: %d: %d\n",
				UBBD_CMD_STATUS, dev_id, ret);
	}

	return ret;

free_msg:
	nlmsg_free(msg);
close_sock:
	ubbd_socket_close(socket);
	return ret;
}

static int list_callback(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *msg_attr[UBBD_ATTR_MAX + 1];
	int ret;
	struct nlattr *list_attr;
	struct ubbd_nl_list_result *result = arg;
	int rem;

	ret = nla_parse(msg_attr, UBBD_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0), NULL);
	if (ret) {
		ubbd_err("Invalid response from the kernel\n");
		return ret;
	}

	ret = nla_get_s32(msg_attr[UBBD_ATTR_RETVAL]);
	if (ret)
		return ret;

	result->num_devs = 0;
	if (!msg_attr[UBBD_ATTR_DEV_LIST]) {
		ubbd_err("no dev list\n");
	}
	nla_for_each_nested(list_attr, msg_attr[UBBD_ATTR_DEV_LIST], rem) {
		result->dev_ids[result->num_devs] = nla_get_s32(&list_attr[UBBD_LIST_DEV_ID]);
		result->num_devs++;

	}
	return ret;
}

int ubbd_nl_dev_list(struct ubbd_nl_list_result *result)
{
	struct nl_msg *msg;
	void *hdr;
	int ret = -ENOMEM;
	struct nl_sock *socket;
	int driver_id;

	socket = get_ubbd_socket(&driver_id);
	if (!socket)
		return -1;

	nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, list_callback, result);

	msg = nlmsg_alloc();
	if (!msg)
		goto close_sock;

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id,
			  0, 0, UBBD_CMD_LIST, UBBD_NL_VERSION);
	if (!hdr)
		goto free_msg;

	ret = nl_send_sync(socket, msg);
	ubbd_socket_close(socket);
	if (ret < 0)
		ubbd_err("Could not send netlink cmd %d: %d\n", UBBD_CMD_LIST, ret);
	return ret;

free_msg:
	nlmsg_free(msg);
close_sock:
	ubbd_socket_close(socket);
	return ret;

}

static int ubbd_nl_queue_op(struct ubbd_device *ubbd_dev, int queue_id, uint64_t flags)
{
	struct nl_msg *msg;
	void *hdr;
	int ret = -ENOMEM;
	struct nl_sock *socket;
	int driver_id;

	socket = get_ubbd_socket(&driver_id);
	if (!socket)
		return -1;

	nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, nl_callback, NULL);

	msg = nlmsg_alloc();
	if (!msg)
		goto close_sock;

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id,
			  0, 0, UBBD_CMD_QUEUE_OP, UBBD_NL_VERSION);
	if (!hdr)
		goto free_msg;

	ret = nla_put_s32(msg, UBBD_ATTR_DEV_ID, ubbd_dev->dev_id);
	if (ret < 0)
		goto free_msg;

	ret = nla_put_s32(msg, UBBD_ATTR_QUEUE_ID, queue_id);
	if (ret < 0)
		goto free_msg;

	ret = nla_put_u64(msg, UBBD_ATTR_FLAGS, flags);
	if (ret < 0)
		goto free_msg;

	ret = nl_send_sync(socket, msg);
	ubbd_socket_close(socket);
	return ret;

free_msg:
	nlmsg_free(msg);
close_sock:
	ubbd_socket_close(socket);
	return ret;
}

int ubbd_nl_stop_queue(struct ubbd_device *ubbd_dev, int queue_id)
{
	return ubbd_nl_queue_op(ubbd_dev, queue_id, UBBD_ATTR_FLAGS_QUEUE_OP_STOP);
}

int ubbd_nl_start_queue(struct ubbd_device *ubbd_dev, int queue_id)
{
	return ubbd_nl_queue_op(ubbd_dev, queue_id, UBBD_ATTR_FLAGS_QUEUE_OP_START);
}

int ubbd_nl_queue_req(struct ubbd_device *ubbd_dev, struct ubbd_nl_req *req)
{
	pthread_mutex_lock(&ubbd_nl_req_list_lock);
	list_add_tail(&req->node, &ubbd_nl_req_list);
	pthread_cond_signal(&ubbd_nl_thread_cond);
	pthread_mutex_unlock(&ubbd_nl_req_list_lock);

	return 0;
}

int ubbd_nl_req_add_dev(struct ubbd_device *ubbd_dev, struct context *ctx)
{
	struct ubbd_nl_req *req = nl_req_alloc();

	INIT_LIST_HEAD(&req->node);
	req->type = UBBD_NL_REQ_ADD_DEV;
	req->ubbd_dev = ubbd_dev;
	req->ctx = ctx;

	return ubbd_nl_queue_req(ubbd_dev, req);
}

int ubbd_nl_req_add_disk(struct ubbd_device *ubbd_dev, struct context *ctx)
{
	struct ubbd_nl_req *req = nl_req_alloc();

	INIT_LIST_HEAD(&req->node);
	req->type = UBBD_NL_REQ_ADD_DISK;
	req->ubbd_dev = ubbd_dev;
	req->ctx = ctx;

	return ubbd_nl_queue_req(ubbd_dev, req);
}

int ubbd_nl_req_remove_disk(struct ubbd_device *ubbd_dev, bool force, struct context *ctx)
{
	struct ubbd_nl_req *req = nl_req_alloc();

	INIT_LIST_HEAD(&req->node);
	req->type = UBBD_NL_REQ_REMOVE_DISK;
	req->ubbd_dev = ubbd_dev;
	req->req_opts.remove_opts.force = force;
	req->ctx = ctx;

	return ubbd_nl_queue_req(ubbd_dev, req);
}

int ubbd_nl_req_remove_dev(struct ubbd_device *ubbd_dev, struct context *ctx)
{
	struct ubbd_nl_req *req = nl_req_alloc();

	INIT_LIST_HEAD(&req->node);
	req->type = UBBD_NL_REQ_REMOVE_DEV;
	req->ubbd_dev = ubbd_dev;
	req->ctx = ctx;

	return ubbd_nl_queue_req(ubbd_dev, req);
}

int ubbd_nl_req_config(struct ubbd_device *ubbd_dev, int data_pages_reserve_percnt, struct context *ctx)
{
	struct ubbd_nl_req *req = nl_req_alloc();

	INIT_LIST_HEAD(&req->node);
	req->type = UBBD_NL_REQ_CONFIG;
	req->ubbd_dev = ubbd_dev;
	req->req_opts.config_opts.data_pages_reserve_percnt = data_pages_reserve_percnt;
	req->ctx = ctx;

	return ubbd_nl_queue_req(ubbd_dev, req);
}

static int handle_nl_req(struct ubbd_nl_req *req)
{
	int ret = 0;

	switch (req->type) {
	case UBBD_NL_REQ_ADD_DEV:
		ret = send_netlink_add_dev(req);
		break;
	case UBBD_NL_REQ_ADD_DISK:
		ret = send_netlink_add_disk(req);
		break;
	case UBBD_NL_REQ_REMOVE_DISK:
		ret = send_netlink_remove_disk(req);
		break;
	case UBBD_NL_REQ_REMOVE_DEV:
		ret = send_netlink_remove_dev(req);
		break;
	case UBBD_NL_REQ_CONFIG:
		ret = send_netlink_config(req);
		break;
	default:
		ubbd_err("unknown netlink request type: %d\n", req->type);
	}

	ubbd_dbg("return ret: %d\n", ret);
	return ret;
}

static bool stop_nl_thread = false;
static void *nl_thread_fn(void* args)
{
	LIST_HEAD(tmp_list);
	struct ubbd_nl_req *req, *tmp_req;
	int ret;

	while (1) {
		pthread_mutex_lock(&ubbd_nl_req_list_lock);
		if (list_empty(&ubbd_nl_req_list)) {
			if (stop_nl_thread) {
				pthread_mutex_unlock(&ubbd_nl_req_list_lock);
				return NULL;
			}
			pthread_cond_wait(&ubbd_nl_thread_cond, &ubbd_nl_req_list_lock);
		}
		list_for_each_entry_safe(req, tmp_req, &ubbd_nl_req_list, node)
			list_move_tail(&req->node, &tmp_list);
		pthread_mutex_unlock(&ubbd_nl_req_list_lock);

		list_for_each_entry_safe(req, tmp_req, &tmp_list, node) {
			list_del(&req->node);
			ret = handle_nl_req(req);
			if (req->ctx) {
				ubbd_dbg("call finish of ctx: %d\n", ret);
				ret = context_finish(req->ctx, ret);
			}
			nl_req_free(req);
		}
	}

	return NULL;
}

pthread_t ubbd_nl_thread;

int ubbd_nl_start_thread(void)
{
	INIT_LIST_HEAD(&ubbd_nl_req_list);
	pthread_mutex_init(&ubbd_nl_req_list_lock, NULL);
	pthread_cond_init(&ubbd_nl_thread_cond, NULL);

	return pthread_create(&ubbd_nl_thread, NULL, nl_thread_fn, NULL);
}

void ubbd_nl_stop_thread(void)
{
	pthread_mutex_lock(&ubbd_nl_req_list_lock);
	stop_nl_thread = true;
	pthread_cond_signal(&ubbd_nl_thread_cond);
	pthread_mutex_unlock(&ubbd_nl_req_list_lock);
}

int ubbd_nl_wait_thread(void)
{
	void *join_retval;

	return pthread_join(ubbd_nl_thread, &join_retval);
}
