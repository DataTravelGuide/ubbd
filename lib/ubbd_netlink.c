#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/mngt.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/errno.h>
#include <pthread.h>

#include "utils.h"
#include "ubbd_netlink.h"
#include "ubbd_dev.h"
#include "ubbd_uio.h"
#include "ubbd.h"

#define UBBD_NL_VERSION 1

static LIST_HEAD(ubbd_nl_req_list);
static pthread_mutex_t ubbd_nl_req_list_lock;
static pthread_cond_t	ubbd_nl_thread_cond;

static struct nla_policy ubbd_status_policy[UBBD_STATUS_ATTR_MAX + 1] = {
	[UBBD_STATUS_DEV_ID] = { .type = NLA_S32 },
	[UBBD_STATUS_UIO_ID] = { .type = NLA_S32 },
	[UBBD_STATUS_UIO_MAP_SIZE] = { .type = NLA_U64 },
	[UBBD_STATUS_STATUS] = { .type = NLA_U8 },
};

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
		return NULL;
	}

	*driver_id = genl_ctrl_resolve(socket, "UBBD");
	if (*driver_id < 0) {
		ubbd_err("Couldn't resolve the ubbd netlink family, make sure the ubbd module is loaded.\n");
		return NULL;
	}

	return socket;
}

static void ubbd_socket_close(struct nl_sock *socket)
{
	nl_close(socket);
	nl_socket_free(socket);
}

static int send_netlink_remove(struct ubbd_device *ubbd_dev)
{
	struct nl_msg *msg;
	void *hdr;
	int ret = -ENOMEM;
	struct nl_sock *socket;
	int driver_id;

	socket = get_ubbd_socket(&driver_id);
	if (!socket)
		return -1;

	msg = nlmsg_alloc();
	if (!msg)
		goto close_sock;

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id,
			  0, 0, UBBD_CMD_REMOVE, UBBD_NL_VERSION);
	if (!hdr)
		goto free_msg;

	ret = nla_put_u64(msg, UBBD_ATTR_PRIV_DATA, (uint64_t)ubbd_dev);
	if (ret < 0)
		goto free_msg;

	ret = nla_put_s32(msg, UBBD_ATTR_DEV_ID, ubbd_dev->dev_id);
	if (ret < 0)
		goto free_msg;

	/* Ignore ack. There is nothing we can do. */
	ret = nl_send_auto(socket, msg);
	ubbd_socket_close(socket);
	if (ret) {
		ubbd_err("send_netlink_remove ret of send: %d\n", ret);
	} else {
	        list_del(&ubbd_dev->dev_node);
	        ubbd_dev_release(ubbd_dev);
	}
	return ret;

free_msg:
	nlmsg_free(msg);
close_sock:
	ubbd_socket_close(socket);
	return ret;
}

int send_netlink_remove_prepare(struct ubbd_device *ubbd_dev)
{
	struct nl_msg *msg;
	void *hdr;
	int ret = -ENOMEM;
	struct nl_sock *socket;
	int driver_id;

	socket = get_ubbd_socket(&driver_id);
	if (!socket)
		return -1;

	//nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, remove_prepare_done_callback, NULL);

	msg = nlmsg_alloc();
	if (!msg)
		goto close_sock;

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id,
			  0, 0, UBBD_CMD_REMOVE_PREPARE, UBBD_NL_VERSION);
	if (!hdr)
		goto free_msg;

	ret = nla_put_u64(msg, UBBD_ATTR_PRIV_DATA, (uint64_t)ubbd_dev);
	if (ret < 0)
		goto free_msg;

	ret = nla_put_s32(msg, UBBD_ATTR_DEV_ID, ubbd_dev->dev_id);
	if (ret < 0)
		goto free_msg;

	/* Ignore ack. There is nothing we can do. */
	ret = nl_send_auto(socket, msg);
	ubbd_socket_close(socket);
	if (ret < 0) {
		ubbd_err("Could not send netlink cmd %d\n", UBBD_CMD_REMOVE_PREPARE);
	} else {
		void *join_retval;

		ubbd_dev->status = UBBD_DEV_STATUS_REMOVE_PREPARED;
		// TODO get ubbddevice from global list
		ret = pthread_join(ubbd_dev->cmdproc_thread, &join_retval);
		device_close_shm(ubbd_dev);

		ubbd_nl_queue_req(UBBD_CMD_REMOVE, ubbd_dev);
	}
	return ret;

free_msg:
	nlmsg_free(msg);
close_sock:
	ubbd_socket_close(socket);
	return ret;

}

static int send_netlink_add(struct ubbd_device *ubbd_dev)
{
	struct nl_msg *msg;
	void *hdr;
	int ret = -ENOMEM;
	struct nl_sock *socket;
	int driver_id;

	socket = get_ubbd_socket(&driver_id);
	if (!socket)
		return -1;

	msg = nlmsg_alloc();
	if (!msg)
		goto close_sock;

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id,
			  0, 0, UBBD_CMD_ADD, UBBD_NL_VERSION);
	if (!hdr)
		goto free_msg;

	ret = nla_put_u64(msg, UBBD_ATTR_PRIV_DATA, (uint64_t)ubbd_dev);
	if (ret < 0)
		goto free_msg;

	ret = nla_put_s32(msg, UBBD_ATTR_DEV_ID, ubbd_dev->dev_id);
	if (ret < 0)
		goto free_msg;

	ret = nl_send_auto(socket, msg);
	ubbd_socket_close(socket);
	if (ret) {
		ubbd_info("ret of send auto netlink add: %d\n", ret);
	} else {
		ubbd_info("adde done\n");
		ubbd_info("ubbd_dev: %p, dev_id: %u, uio_id: %d", ubbd_dev, ubbd_dev->dev_id, ubbd_dev->uio_id);
	}
	return ret;

free_msg:
	nlmsg_free(msg);
close_sock:
	ubbd_socket_close(socket);
	return ret;
}

static int add_prepare_done_callback(struct nl_msg *msg, void *arg)
{
	struct ubbd_device *ubbd_dev;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *msg_attr[UBBD_ATTR_MAX + 1];
	int ret;

	ret = nla_parse(msg_attr, UBBD_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0), NULL);
	if (ret)
		ubbd_err("Invalid response from the kernel\n");

	ubbd_dev = (struct ubbd_device *)(nla_get_u64(msg_attr[UBBD_ATTR_PRIV_DATA]));
	ubbd_dev->status = UBBD_DEV_STATUS_ADD_PREPARED;
	ubbd_dev->dev_id = (int32_t)(nla_get_s32(msg_attr[UBBD_ATTR_DEV_ID]));
	ubbd_dev->uio_id = (int32_t)(nla_get_s32(msg_attr[UBBD_ATTR_UIO_ID]));
	ubbd_dev->uio_map_size = (uint64_t)(nla_get_u64(msg_attr[UBBD_ATTR_UIO_MAP_SIZE]));
	if (!device_open_shm(ubbd_dev))
		exit(-1);

	memcpy(ubbd_uio_get_dev_info(ubbd_dev->map), &ubbd_dev->dev_info, sizeof(struct ubbd_dev_info));
	// TODO get ubbddevice from global list
	pthread_create(&ubbd_dev->cmdproc_thread, NULL, cmd_process, ubbd_dev);

	ubbd_nl_queue_req(UBBD_CMD_ADD, ubbd_dev);

	return NL_OK;
}

int send_netlink_add_prepare(struct ubbd_device *ubbd_dev)
{
	struct nl_msg *msg;
	void *hdr;
	int ret = -ENOMEM;
	struct nl_sock *socket;
	int driver_id;
	uint64_t dev_features = 0;

	socket = get_ubbd_socket(&driver_id);
	if (!socket)
		return -1;

	nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, add_prepare_done_callback, NULL);

	msg = nlmsg_alloc();
	if (!msg)
		goto close_sock;

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id,
			  0, 0, UBBD_CMD_ADD_PREPARE, UBBD_NL_VERSION);
	if (!hdr)
		goto free_msg;

	ret = nla_put_u64(msg, UBBD_ATTR_PRIV_DATA, (uint64_t)ubbd_dev);
	if (ret < 0)
		goto free_msg;

	ret = nla_put_u64(msg, UBBD_ATTR_DEV_SIZE, ubbd_dev->dev_size);
	if (ret < 0)
		goto free_msg;

        if (ubbd_dev->dev_features.write_cache)
                dev_features |= UBBD_DEV_FEATURE_WRITECACHE;

	if (ubbd_dev->dev_features.fua)
		dev_features |= UBBD_DEV_FEATURE_FUA;
        ret = nla_put_u64(msg, UBBD_ATTR_DEV_FEATURES, dev_features);
        if (ret < 0)
                goto free_msg;

	/* Ignore ack. There is nothing we can do. */
	ret = nl_send_sync(socket, msg);
	ubbd_socket_close(socket);
	if (ret < 0)
		ubbd_err("Could not send netlink cmd %d\n", UBBD_CMD_ADD_PREPARE);
	return ret;

free_msg:
	nlmsg_free(msg);
close_sock:
	ubbd_socket_close(socket);
	return ret;
}

static int status_callback(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *msg_attr[UBBD_ATTR_MAX + 1];
	int ret;
	struct list_head *dev_list = (struct list_head *)arg;

	ret = nla_parse(msg_attr, UBBD_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0), NULL);
	if (ret)
		ubbd_err("Invalid response from the kernel\n");

	if (msg_attr[UBBD_ATTR_DEV_LIST]) {
		struct nlattr *attr;
		int rem;

		nla_for_each_nested(attr, msg_attr[UBBD_ATTR_DEV_LIST], rem) {
			struct nlattr *status[UBBD_STATUS_ATTR_MAX+1];
			struct ubbd_nl_dev_status *dev_status;

			if (nla_type(attr) != UBBD_STATUS_ITEM) {
				ubbd_err("ubbd: ubbd device shoudl be nested in UBBD_STATUS_ITEM\n");
				ret = -EINVAL;
				goto out;
			}

			ret = nla_parse_nested(status, UBBD_STATUS_ATTR_MAX, attr,
					       ubbd_status_policy);
			if (ret) {
				ubbd_err("failed to parse nested status\n");
				ret = -EINVAL;
				goto out;
			}

			dev_status = calloc(1, sizeof(struct ubbd_nl_dev_status));
			if (!dev_status) {
				ret = -ENOMEM;
				goto out;
			}
			INIT_LIST_HEAD(&dev_status->node);
			dev_status->dev_id = nla_get_s32(status[UBBD_STATUS_DEV_ID]);
			dev_status->uio_id = nla_get_s32(status[UBBD_STATUS_UIO_ID]);
			dev_status->uio_map_size = nla_get_s32(status[UBBD_STATUS_UIO_MAP_SIZE]);
			dev_status->status = nla_get_u8(status[UBBD_STATUS_STATUS]);

			list_add_tail(&dev_status->node, dev_list);
		}
	}

out:
	return NL_OK;
}

int ubbd_nl_dev_list(struct list_head *dev_list)
{
	struct nl_msg *msg;
	void *hdr;
	int ret = -ENOMEM;
	struct nl_sock *socket;
	int driver_id;

	socket = get_ubbd_socket(&driver_id);
	if (!socket)
		return -1;

	nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, status_callback, dev_list);

	msg = nlmsg_alloc();
	if (!msg)
		goto close_sock;

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id,
			  0, 0, UBBD_CMD_STATUS, UBBD_NL_VERSION);
	if (!hdr)
		goto free_msg;

	ret = nla_put_s64(msg, UBBD_ATTR_DEV_ID, -1);
	if (ret < 0)
		goto free_msg;

	/* Ignore ack. There is nothing we can do. */
	ret = nl_send_sync(socket, msg);
	ubbd_socket_close(socket);
	if (ret < 0)
		ubbd_err("Could not send netlink cmd %d\n", UBBD_CMD_ADD_PREPARE);
	return ret;

free_msg:
	nlmsg_free(msg);
close_sock:
	ubbd_socket_close(socket);
	return ret;

}

int ubbd_nl_queue_req(enum ubbd_nl_req_type req_type, struct ubbd_device *ubbd_dev)
{
	struct ubbd_nl_req *req = calloc(1, sizeof(struct ubbd_nl_req));

	INIT_LIST_HEAD(&req->node);
	req->type = req_type;
	req->ubbd_dev = ubbd_dev;

	pthread_mutex_lock(&ubbd_nl_req_list_lock);
	list_add_tail(&req->node, &ubbd_nl_req_list);
	pthread_cond_signal(&ubbd_nl_thread_cond);
	pthread_mutex_unlock(&ubbd_nl_req_list_lock);

	return 0;
}

static int handle_nl_req(struct ubbd_nl_req *req)
{
	int ret = 0;

	switch (req->type) {
	case UBBD_NL_REQ_ADD_PREPARE:
		ret = send_netlink_add_prepare(req->ubbd_dev);
		break;
	case UBBD_NL_REQ_ADD:
		ret = send_netlink_add(req->ubbd_dev);
		break;
	case UBBD_NL_REQ_REMOVE_PREPARE:
		ret = send_netlink_remove_prepare(req->ubbd_dev);
		break;
	case UBBD_NL_REQ_REMOVE:
		ret = send_netlink_remove(req->ubbd_dev);
		break;
	default:
		ubbd_err("unknown netlink request type: %d\n", req->type);
		exit(-1);
	}

	return ret;
}

static void *nl_thread_fn(void* args)
{
	LIST_HEAD(tmp_list);
	struct ubbd_nl_req *req, *tmp_req;

	while (1) {
		pthread_mutex_lock(&ubbd_nl_req_list_lock);
		if (list_empty(&ubbd_nl_req_list)) {
			pthread_cond_wait(&ubbd_nl_thread_cond, &ubbd_nl_req_list_lock);
		}
		list_for_each_entry_safe(req, tmp_req, &ubbd_nl_req_list, node)
			list_move_tail(&req->node, &tmp_list);
		pthread_mutex_unlock(&ubbd_nl_req_list_lock);

		list_for_each_entry_safe(req, tmp_req, &tmp_list, node) {
			list_del(&req->node);
			handle_nl_req(req);
		}
	}

	return NULL;
}

int start_netlink_thread(pthread_t *t)
{
	INIT_LIST_HEAD(&ubbd_nl_req_list);
	pthread_mutex_init(&ubbd_nl_req_list_lock, NULL);
	pthread_cond_init(&ubbd_nl_thread_cond, NULL);

	return pthread_create(t, NULL, nl_thread_fn, NULL);
}
