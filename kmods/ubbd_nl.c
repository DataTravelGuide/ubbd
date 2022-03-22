/* netlink */

#include "ubbd_internal.h"
static int ubbd_total_devs = 0;

static int ubbd_nl_reply_add_dev_done(struct ubbd_device *ubbd_dev,
					  u64 priv_data,
					  struct genl_info *info)
{
	struct sk_buff *reply_skb;
	void *msg_head;
	size_t msg_size;

	msg_size = nla_total_size(nla_attr_size(sizeof(u64)) +
				  nla_attr_size(sizeof(s32)) +
				  nla_attr_size(sizeof(s32)) +
				  nla_attr_size(sizeof(s32)) +
				  nla_attr_size(sizeof(u64)));

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault())
		goto err;
#endif
	reply_skb = genlmsg_new(msg_size, GFP_KERNEL);
	if (!reply_skb)
		goto err;

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault())
		goto err_free;
#endif
	msg_head = genlmsg_put_reply(reply_skb, info, &ubbd_genl_family, 0,
				     UBBD_CMD_ADD_DEV);
	if (!msg_head)
		goto err_free;

	if (nla_put_u64_64bit(reply_skb, UBBD_ATTR_PRIV_DATA,
				priv_data, UBBD_ATTR_PAD) ||
	    nla_put_s32(reply_skb, UBBD_ATTR_DEV_ID,
		    	ubbd_dev->dev_id) ||
	    nla_put_s32(reply_skb, UBBD_ATTR_UIO_ID,
			ubbd_dev->uio_info.uio_dev->minor) ||
	    nla_put_u64_64bit(reply_skb, UBBD_ATTR_UIO_MAP_SIZE,
			ubbd_dev->uio_info.mem[0].size, UBBD_ATTR_PAD))
		goto err_cancel;

	if (nla_put_s32(reply_skb, UBBD_ATTR_RETVAL, 0))
		goto err_cancel;

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault())
		goto err_cancel;
#endif
	genlmsg_end(reply_skb, msg_head);
	return genlmsg_reply(reply_skb, info);

err_cancel:
	genlmsg_cancel(reply_skb, msg_head);
err_free:
	nlmsg_free(reply_skb);
err:
	return -EMSGSIZE;
}

static int handle_cmd_add_dev(struct sk_buff *skb, struct genl_info *info)
{
	struct ubbd_device *ubbd_dev = NULL;
	u64 dev_features;
	u64 priv_data;
	u64 device_size;
	u32 data_pages;
	int ret;

	if (!info->attrs[UBBD_ATTR_PRIV_DATA] ||
			!info->attrs[UBBD_ATTR_DEV_SIZE] ||
			!info->attrs[UBBD_ATTR_FLAGS]) {
		ret = -EINVAL;
		goto out;
	}

	priv_data = nla_get_u64(info->attrs[UBBD_ATTR_PRIV_DATA]);
	device_size = nla_get_u64(info->attrs[UBBD_ATTR_DEV_SIZE]);
	dev_features = nla_get_u64(info->attrs[UBBD_ATTR_FLAGS]);

	if (info->attrs[UBBD_ATTR_DATA_PAGES])
		data_pages = nla_get_u32(info->attrs[UBBD_ATTR_DATA_PAGES]);
	else
		data_pages = UBBD_UIO_DATA_PAGES;

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault()) {
		ret = -ENOMEM;
		goto out;
	}
#endif
	ubbd_dev = ubbd_dev_create(data_pages);
	if (!ubbd_dev) {
		ret = -ENOMEM;
		goto out;
	}

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault()) {
		ret = -ENOMEM;
		goto err_dev_put;
	}
#endif
	ret = ubbd_dev_sb_init(ubbd_dev);
	if (ret) {
		pr_err("failed to init dev sb: %d.", ret);
		goto err_dev_put;
	}

	ret = ubbd_dev_uio_init(ubbd_dev);
	if (ret) {
		pr_debug("failed to init uio: %d.", ret);
		goto err_dev_put;
	}

	ret = ubbd_dev_device_setup(ubbd_dev, device_size, dev_features);
	if (ret) {
		ret = -EINVAL;
		goto err_dev_put;
	}

	mutex_lock(&ubbd_dev_list_mutex);
	ubbd_total_devs++;
	list_add_tail(&ubbd_dev->dev_node, &ubbd_dev_list);
	mutex_unlock(&ubbd_dev_list_mutex);

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault()) {
		ret = -ENOMEM;
		goto err_free_disk;
	}
#endif
	ret = ubbd_nl_reply_add_dev_done(ubbd_dev, priv_data, info);
	if (ret)
		goto err_free_disk;

	ubbd_dev->status = UBBD_DEV_STATUS_PREPARED;

	return 0;

err_free_disk:
	mutex_lock(&ubbd_dev_list_mutex);
	ubbd_total_devs--;
	list_del_init(&ubbd_dev->dev_node);
	mutex_unlock(&ubbd_dev_list_mutex);

	ubbd_free_disk(ubbd_dev);
err_dev_put:
	ubbd_dev_put(ubbd_dev);
out:
	return ret;
}

/*
 * ubbd_dev_list_mutex is held
 */
static struct ubbd_device *__find_ubbd_dev(int dev_id)
{
	struct ubbd_device *ubbd_dev = NULL;
	struct ubbd_device *ubbd_dev_tmp;

	list_for_each_entry(ubbd_dev_tmp, &ubbd_dev_list, dev_node) {
		if (ubbd_dev_tmp->dev_id == dev_id) {
			ubbd_dev = ubbd_dev_tmp;
			break;
		}
	}

	return ubbd_dev;
}

static struct ubbd_device *find_ubbd_dev(int dev_id)
{
	struct ubbd_device *ubbd_dev = NULL;

	mutex_lock(&ubbd_dev_list_mutex);
	ubbd_dev = __find_ubbd_dev(dev_id);
	mutex_unlock(&ubbd_dev_list_mutex);

	return ubbd_dev;
}

static int handle_cmd_add_disk(struct sk_buff *skb, struct genl_info *info)
{
	struct ubbd_device *ubbd_dev;
	int dev_id;
	int ret = 0;

	dev_id = nla_get_s32(info->attrs[UBBD_ATTR_DEV_ID]);
	ubbd_dev = find_ubbd_dev(dev_id);
	if (!ubbd_dev) {
		pr_err("cant find dev: %d", dev_id);
		ret = -ENOENT;
		goto out;
	}
	if (ubbd_dev->status != UBBD_DEV_STATUS_PREPARED) {
		ret = -EINVAL;
		pr_err("add_disk expected status is UBBD_DEV_STATUS_PREPARED, \
				but current status is: %d.", ubbd_dev->status);
		goto out;
	}
	ubbd_dev->status = UBBD_DEV_STATUS_RUNNING;

	add_disk(ubbd_dev->disk);
	blk_put_queue(ubbd_dev->disk->queue);

out:
	return ret;
}


static int handle_cmd_remove_disk(struct sk_buff *skb, struct genl_info *info)
{
	struct ubbd_device *ubbd_dev;
	int dev_id;
	u64 remove_flags;
	bool force = false;
	int ret = 0;
	bool disk_is_running = false;

	dev_id = nla_get_s32(info->attrs[UBBD_ATTR_DEV_ID]);
	remove_flags = nla_get_u64(info->attrs[UBBD_ATTR_FLAGS]);
	ubbd_dev = find_ubbd_dev(dev_id);
	if (!ubbd_dev) {
		ret = -ENOENT;
		goto out;
	}

	if (remove_flags & UBBD_ATTR_FLAGS_REMOVE_FORCE) {
		force = true;
		pr_debug("force remove ubbd%d", dev_id);
	}

	spin_lock(&ubbd_dev->lock);
	if (!force && ubbd_dev->open_count) {
		ret = -EBUSY;
		spin_unlock(&ubbd_dev->lock);
		goto out;
	}
	spin_unlock(&ubbd_dev->lock);

	mutex_lock(&ubbd_dev->req_lock);
	disk_is_running = (ubbd_dev->status == UBBD_DEV_STATUS_RUNNING);
	ubbd_dev->status = UBBD_DEV_STATUS_REMOVING;

	if (force) {
		ubbd_end_inflight_reqs(ubbd_dev, -EIO);
	}
	mutex_unlock(&ubbd_dev->req_lock);

	if (disk_is_running) {
		del_gendisk(ubbd_dev->disk);
	}

out:
	return ret;
}

static int handle_cmd_remove_dev(struct sk_buff *skb, struct genl_info *info)
{
	struct ubbd_device *ubbd_dev;
	int dev_id;
	int ret = 0;

	dev_id = nla_get_s32(info->attrs[UBBD_ATTR_DEV_ID]);
	mutex_lock(&ubbd_dev_list_mutex);
	ubbd_dev = __find_ubbd_dev(dev_id);
	if (!ubbd_dev) {
		mutex_unlock(&ubbd_dev_list_mutex);
		ret = -ENOENT;
		goto out;
	}

	if (ubbd_dev->status != UBBD_DEV_STATUS_REMOVING &&
			ubbd_dev->status != UBBD_DEV_STATUS_PREPARED) {
		pr_err("remove dev is not allowed in current status: %d.",
				ubbd_dev->status);
		mutex_unlock(&ubbd_dev_list_mutex);
		ret = -EINVAL;
		goto out;
	}

	list_del_init(&ubbd_dev->dev_node);
	mutex_unlock(&ubbd_dev_list_mutex);

	ubbd_free_disk(ubbd_dev);
	ubbd_dev_put(ubbd_dev);
out:
	return ret;
}

static int fill_ubbd_status_item(struct ubbd_device *ubbd_dev, struct sk_buff *reply_skb)
{
	struct nlattr *dev_nest;

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault())
		return -EMSGSIZE;
#endif
	dev_nest = nla_nest_start(reply_skb, UBBD_STATUS_ITEM);
	if (!dev_nest)
		return -EMSGSIZE;

	if (nla_put_s32(reply_skb, UBBD_STATUS_DEV_ID,
				ubbd_dev->dev_id) ||
		nla_put_s32(reply_skb, UBBD_STATUS_UIO_ID,
				ubbd_dev->uio_info.uio_dev->minor) ||
		nla_put_u64_64bit(reply_skb, UBBD_STATUS_UIO_MAP_SIZE,
				ubbd_dev->uio_info.mem[0].size, UBBD_ATTR_PAD) ||
		nla_put_u8(reply_skb, UBBD_STATUS_STATUS,
				ubbd_dev->status))
		return -EMSGSIZE;
	nla_nest_end(reply_skb, dev_nest);

	return 0;
}

static int fill_ubbd_status(struct ubbd_device *ubbd_dev,
			struct sk_buff *reply_skb, int dev_id)
{
	struct nlattr *dev_list;
	int ret = 0;

	dev_list = nla_nest_start(reply_skb, UBBD_ATTR_DEV_LIST);
	if (dev_id == -1) {
		list_for_each_entry(ubbd_dev, &ubbd_dev_list, dev_node) {
			ret = fill_ubbd_status_item(ubbd_dev, reply_skb);
			if (ret)
				goto out;
		}
	} else {
		ubbd_dev = find_ubbd_dev(dev_id);
		if (!ubbd_dev) {
			ret = -ENOENT;
			goto out;
		}
		ret = fill_ubbd_status_item(ubbd_dev, reply_skb);
		if (ret)
			goto out;
	}
	nla_nest_end(reply_skb, dev_list);
out:
	return ret;
}

static int handle_cmd_status(struct sk_buff *skb, struct genl_info *info)
{
	struct ubbd_device *ubbd_dev;
	int dev_id = -1;
	struct sk_buff *reply_skb = NULL;
	void *msg_head = NULL;
	size_t msg_size;
	int ret = 0;

	if (info->attrs[UBBD_ATTR_DEV_ID])
		dev_id = nla_get_s32(info->attrs[UBBD_ATTR_DEV_ID]);

	msg_size = nla_total_size(nla_attr_size(sizeof(s32)) +
			          nla_attr_size(sizeof(s32)) +
			          nla_attr_size(sizeof(u64)) +
				  nla_attr_size(sizeof(u8)));

	mutex_lock(&ubbd_dev_list_mutex);
	/* msg_size for all devs */
	msg_size *= (dev_id == -1? ubbd_total_devs : 1);
	/* add size for retval */
	msg_size += nla_attr_size(sizeof(s32));

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault()) {
		mutex_unlock(&ubbd_dev_list_mutex);
		ret = -ENOMEM;
		goto err;
	}
#endif
	reply_skb = genlmsg_new(msg_size, GFP_KERNEL);
	if (!reply_skb) {
		mutex_unlock(&ubbd_dev_list_mutex);
		ret = -ENOMEM;
		goto err;
	}

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault()) {
		mutex_unlock(&ubbd_dev_list_mutex);
		ret = -ENOMEM;
		goto err_free;
	}
#endif
	msg_head = genlmsg_put_reply(reply_skb, info, &ubbd_genl_family, 0,
				     UBBD_CMD_STATUS);
	if (!msg_head) {
		mutex_unlock(&ubbd_dev_list_mutex);
		ret = -ENOMEM;
		goto err_free;
	}

	ret = fill_ubbd_status(ubbd_dev, reply_skb, dev_id);
	if (ret) {
		mutex_unlock(&ubbd_dev_list_mutex);
		goto err_cancel;
	}

	mutex_unlock(&ubbd_dev_list_mutex);
	if (nla_put_s32(reply_skb, UBBD_ATTR_RETVAL, 0)) {
		ret = -EMSGSIZE;
		goto err_cancel;
	}

#ifdef UBBD_FAULT_INJECT
	if (ubbd_mgmt_need_fault()) {
		ret = -EMSGSIZE;
		goto err_cancel;
	}
#endif
	genlmsg_end(reply_skb, msg_head);
	return genlmsg_reply(reply_skb, info);

err_cancel:
	genlmsg_cancel(reply_skb, msg_head);
err_free:
	nlmsg_free(reply_skb);
err:
	return ret;
}

static struct nla_policy ubbd_dev_config_attr_policy[UBBD_DEV_CONFIG_MAX+1] = {
	[UBBD_DEV_CONFIG_DP_RESERVE]	= { .type = NLA_U32 },
};

static int handle_cmd_config(struct sk_buff *skb, struct genl_info *info)
{
	struct ubbd_device *ubbd_dev;
	struct nlattr *config[UBBD_DEV_CONFIG_MAX + 1];
	int dev_id;
	u32 config_dp_reserve;
	int ret = 0;

	if (!info->attrs[UBBD_ATTR_DEV_ID] ||
			!info->attrs[UBBD_ATTR_DEV_CONFIG]) {
		ret = -EINVAL;
		goto out;
	}

	dev_id = nla_get_s32(info->attrs[UBBD_ATTR_DEV_ID]);
	ubbd_dev = find_ubbd_dev(dev_id);
	if (!ubbd_dev) {
		pr_err("cant find dev: %d", dev_id);
		ret = -ENOENT;
		goto out;
	}

	if (ubbd_dev->status != UBBD_DEV_STATUS_RUNNING) {
		pr_err("config cmd expected ubbd dev status is running, \
				but current status is: %d.", ubbd_dev->status);
		ret = -EINVAL;
		goto out;
	}

	ret = nla_parse_nested_deprecated(config, UBBD_DEV_CONFIG_MAX,
			info->attrs[UBBD_ATTR_DEV_CONFIG],
			ubbd_dev_config_attr_policy,
			info->extack);
	if (ret) {
		pr_err("failed to parse config");
		goto out;
	}

	if (config[UBBD_DEV_CONFIG_DP_RESERVE]) {
		config_dp_reserve = nla_get_u32(config[UBBD_DEV_CONFIG_DP_RESERVE]);
		if (config_dp_reserve > 100) {
			ret = -EINVAL;
			pr_err("dp_reserve is not valide: %u", config_dp_reserve);
			goto out;
		}
		ubbd_dev->data_pages_reserve = config_dp_reserve * ubbd_dev->data_pages / 100;
	}

out:
	return ret;
}

#ifdef HAVE_GENL_SMALL_OPS
static const struct genl_small_ops ubbd_genl_ops[] = {
	{
		.cmd	= UBBD_CMD_ADD_DEV,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_add_dev,
	},
	{
		.cmd	= UBBD_CMD_ADD_DISK,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_add_disk,
	},
	{
		.cmd	= UBBD_CMD_REMOVE_DISK,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_remove_disk,
	},
	{
		.cmd	= UBBD_CMD_REMOVE_DEV,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_remove_dev,
	},
	{
		.cmd	= UBBD_CMD_STATUS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_status,
	},
	{
		.cmd	= UBBD_CMD_CONFIG,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_config,
	},
};
#else
static const struct genl_ops ubbd_genl_ops[] = {
	{
		.cmd	= UBBD_CMD_ADD_DEV,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_add_dev,
	},
	{
		.cmd	= UBBD_CMD_ADD_DISK,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_add_disk,
	},
	{
		.cmd	= UBBD_CMD_REMOVE_DISK,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_remove_disk,
	},
	{
		.cmd	= UBBD_CMD_REMOVE_DEV,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_remove_dev,
	},
	{
		.cmd	= UBBD_CMD_STATUS,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_status,
	},
	{
		.cmd	= UBBD_CMD_CONFIG,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_config,
	},
};
#endif

/* multicast group */
enum ubbd_multicast_groups {
	UBBD_MCGRP_CONFIG,
};

static const struct genl_multicast_group ubbd_mcgrps[] = {
	[UBBD_MCGRP_CONFIG] = { .name = "ubbd_mc_group", },
};

#ifdef	HAVE_GENL_POLICY
static struct nla_policy ubbd_attr_policy[UBBD_ATTR_MAX+1] = {
	[UBBD_ATTR_PRIV_DATA]	= { .type = NLA_U64 },
	[UBBD_ATTR_DEV_ID]	= { .type = NLA_S32 },
	[UBBD_ATTR_UIO_ID]	= { .type = NLA_S32 },
	[UBBD_ATTR_UIO_MAP_SIZE]	= { .type = NLA_U64 },
	[UBBD_ATTR_DEV_SIZE]	= { .type = NLA_U64 },
	[UBBD_ATTR_FLAGS]	= { .type = NLA_U64 },
	[UBBD_ATTR_DEV_CONFIG]	= { .type = NLA_NESTED },
};
#endif

struct genl_family ubbd_genl_family __ro_after_init = {
	.module = THIS_MODULE,
	.hdrsize = 0,
	.name = "UBBD",
	.version = 1,
	.maxattr = UBBD_ATTR_MAX,
#ifdef	HAVE_GENL_POLICY
	.policy = ubbd_attr_policy,
#endif
	.mcgrps = ubbd_mcgrps,
	.n_mcgrps = ARRAY_SIZE(ubbd_mcgrps),
	.netnsok = true,
#ifdef HAVE_GENL_SMALL_OPS
	.small_ops = ubbd_genl_ops,
	.n_small_ops = ARRAY_SIZE(ubbd_genl_ops),
#else
	.ops = ubbd_genl_ops,
	.n_ops = ARRAY_SIZE(ubbd_genl_ops),
#endif
};
