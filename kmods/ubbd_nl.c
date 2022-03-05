/* netlink */

#include "ubbd_internal.h"
static int ubbd_total_devs = 0;

static int ubbd_nl_reply_add_prepare_done(struct ubbd_device *ubbd_dev,
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

	reply_skb = genlmsg_new(msg_size, GFP_KERNEL);
	if (!reply_skb)
		goto err;

	msg_head = genlmsg_put_reply(reply_skb, info, &ubbd_genl_family, 0,
				     UBBD_CMD_ADD_PREPARE);
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

	genlmsg_end(reply_skb, msg_head);
	return genlmsg_reply(reply_skb, info);

err_cancel:
	genlmsg_cancel(reply_skb, msg_head);
err_free:
	nlmsg_free(reply_skb);
err:
	return -EMSGSIZE;
}

static int ubbd_nl_reply(struct genl_info *info, u8 cmd, int retval)
{
	struct sk_buff *reply_skb;
	void *msg_head;
	size_t msg_size;

	msg_size = nla_total_size(nla_attr_size(sizeof(s32)));

	reply_skb = genlmsg_new(msg_size, GFP_KERNEL);
	if (!reply_skb)
		goto err;

	msg_head = genlmsg_put_reply(reply_skb, info, &ubbd_genl_family, 0,
				     cmd);
	if (!msg_head)
		goto err_free;

	if (nla_put_s32(reply_skb, UBBD_ATTR_RETVAL,
		    	retval))
		goto err_cancel;

	genlmsg_end(reply_skb, msg_head);
	return genlmsg_reply(reply_skb, info);

err_cancel:
	genlmsg_cancel(reply_skb, msg_head);
err_free:
	nlmsg_free(reply_skb);
err:
	return -EMSGSIZE;
}

static int handle_cmd_add_prepare(struct sk_buff *skb, struct genl_info *info)
{
	struct ubbd_device *ubbd_dev = NULL;
	u64 dev_features;
	u64 priv_data;
	u64 device_size;
	u32 data_pages;
	int rc;

	if (!info->attrs[UBBD_ATTR_PRIV_DATA] ||
			!info->attrs[UBBD_ATTR_DEV_SIZE] ||
			!info->attrs[UBBD_ATTR_FLAGS]) {
		rc = -EINVAL;
		goto reply;
	}

	priv_data = nla_get_u64(info->attrs[UBBD_ATTR_PRIV_DATA]);
	device_size = nla_get_u64(info->attrs[UBBD_ATTR_DEV_SIZE]);
	dev_features = nla_get_u64(info->attrs[UBBD_ATTR_FLAGS]);

	if (info->attrs[UBBD_ATTR_DATA_PAGES])
		data_pages = nla_get_u32(info->attrs[UBBD_ATTR_DATA_PAGES]);
	else
		data_pages = UBBD_UIO_DATA_PAGES;

	ubbd_dev = ubbd_dev_create(data_pages);
	if (!ubbd_dev) {
		rc = -ENOMEM;
		goto reply;
	}

	rc = ubbd_dev_sb_init(ubbd_dev);
	if (rc) {
		pr_err("failed to init dev sb: %d.", rc);
		goto err_dev_put;
	}

	rc = ubbd_dev_uio_init(ubbd_dev);
	if (rc) {
		pr_debug("failed to init uio: %d.", rc);
		goto err_dev_put;
	}

	rc = ubbd_dev_device_setup(ubbd_dev, device_size, dev_features);
	if (rc) {
		rc = -EINVAL;
		goto err_dev_put;
	}

	mutex_lock(&ubbd_dev_list_mutex);
	ubbd_total_devs++;
	list_add_tail(&ubbd_dev->dev_node, &ubbd_dev_list);
	mutex_unlock(&ubbd_dev_list_mutex);

	ubbd_dev->status = UBBD_DEV_STATUS_ADD_PREPARED;

	rc = ubbd_nl_reply_add_prepare_done(ubbd_dev, priv_data, info);
	if (rc)
		goto err_free_disk;

	return rc;

err_free_disk:
	ubbd_free_disk(ubbd_dev);
err_dev_put:
	ubbd_dev_put(ubbd_dev);
reply:
	ubbd_nl_reply(info, UBBD_CMD_ADD_PREPARE, rc);
	return rc;
}

static struct ubbd_device *find_ubbd_dev(int dev_id)
{
	struct ubbd_device *ubbd_dev = NULL;
	struct ubbd_device *ubbd_dev_tmp;

	mutex_lock(&ubbd_dev_list_mutex);
	list_for_each_entry(ubbd_dev_tmp, &ubbd_dev_list, dev_node) {
		if (ubbd_dev_tmp->dev_id == dev_id) {
			ubbd_dev = ubbd_dev_tmp;
			break;
		}
	}
	mutex_unlock(&ubbd_dev_list_mutex);

	return ubbd_dev;
}

static int handle_cmd_add(struct sk_buff *skb, struct genl_info *info)
{
	struct ubbd_device *ubbd_dev;
	int dev_id;
	int rc = 0;

	dev_id = nla_get_s32(info->attrs[UBBD_ATTR_DEV_ID]);
	ubbd_dev = find_ubbd_dev(dev_id);
	if (!ubbd_dev) {
		pr_err("cant find dev: %d", dev_id);
		rc = -ENOENT;
		goto out;
	}

	add_disk(ubbd_dev->disk);
	blk_put_queue(ubbd_dev->disk->queue);
	ubbd_dev->status = UBBD_DEV_STATUS_RUNNING;

out:
	ubbd_nl_reply(info, UBBD_CMD_ADD, rc);
	return rc;
}


static int handle_cmd_remove_prepare(struct sk_buff *skb, struct genl_info *info)
{
	struct ubbd_device *ubbd_dev;
	int dev_id;
	u64 remove_flags;
	bool force = false;
	int rc = 0;

	dev_id = nla_get_s32(info->attrs[UBBD_ATTR_DEV_ID]);
	remove_flags = nla_get_u64(info->attrs[UBBD_ATTR_FLAGS]);
	ubbd_dev = find_ubbd_dev(dev_id);
	if (!ubbd_dev) {
		rc = -ENOENT;
		goto out;
	}

	if (remove_flags & UBBD_ATTR_FLAGS_REMOVE_FORCE) {
		force = true;
		pr_debug("force remove ubbd%d", dev_id);
	}

	mutex_lock(&ubbd_dev->req_lock);
	if (!force && ubbd_dev->open_count) {
		rc = -EBUSY;
		mutex_unlock(&ubbd_dev->req_lock);
		goto out;
	}

	ubbd_dev->status = UBBD_DEV_STATUS_REMOVING;

	if (force) {
		ubbd_end_inflight_reqs(ubbd_dev, -EIO);
	}

	mutex_unlock(&ubbd_dev->req_lock);

	del_gendisk(ubbd_dev->disk);

out:
	ubbd_nl_reply(info, UBBD_CMD_REMOVE_PREPARE, rc);
	return rc;
}

static int handle_cmd_remove(struct sk_buff *skb, struct genl_info *info)
{
	struct ubbd_device *ubbd_dev;
	int dev_id;
	int rc = 0;

	dev_id = nla_get_s32(info->attrs[UBBD_ATTR_DEV_ID]);
	ubbd_dev = find_ubbd_dev(dev_id);
	if (!ubbd_dev) {
		rc = -ENOENT;
		goto out;
	}

	list_del_init(&ubbd_dev->dev_node);

	ubbd_free_disk(ubbd_dev);
	ubbd_dev_put(ubbd_dev);
out:
	ubbd_nl_reply(info, UBBD_CMD_REMOVE, rc);
	return rc;
}

static int fill_ubbd_status_item(struct ubbd_device *ubbd_dev, struct sk_buff *reply_skb)
{
	struct nlattr *dev_nest;

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

	reply_skb = genlmsg_new(msg_size, GFP_KERNEL);
	if (!reply_skb) {
		ret = -ENOMEM;
		goto err;
	}

	msg_head = genlmsg_put_reply(reply_skb, info, &ubbd_genl_family, 0,
				     UBBD_CMD_STATUS);
	if (!msg_head) {
		nlmsg_free(reply_skb);
		ret = -ENOMEM;
		goto err_free;
	}

	ret = fill_ubbd_status(ubbd_dev, reply_skb, dev_id);
	if (ret)
		goto err_cancel;

	mutex_unlock(&ubbd_dev_list_mutex);
	if (nla_put_s32(reply_skb, UBBD_ATTR_RETVAL, 0))
		goto err_cancel;

	genlmsg_end(reply_skb, msg_head);
	return genlmsg_reply(reply_skb, info);

err_cancel:
	genlmsg_cancel(reply_skb, msg_head);
err_free:
	nlmsg_free(reply_skb);
err:
	mutex_unlock(&ubbd_dev_list_mutex);
	ubbd_nl_reply(info, UBBD_CMD_STATUS, ret);
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

	ret = nla_parse_nested_deprecated(config, UBBD_DEV_CONFIG_MAX,
			info->attrs[UBBD_ATTR_DEV_CONFIG],
			ubbd_dev_config_attr_policy,
			info->extack);
	if (ret) {
		pr_err("failed to parse config");
		goto out;
	}

	mutex_lock(&ubbd_dev->req_lock);
	if (config[UBBD_DEV_CONFIG_DP_RESERVE]) {
		config_dp_reserve = nla_get_u32(config[UBBD_DEV_CONFIG_DP_RESERVE]);
		if (config_dp_reserve > 100) {
			ret = -EINVAL;
			pr_err("dp_reserve is not valide: %u", config_dp_reserve);
			mutex_unlock(&ubbd_dev->req_lock);
			goto out;
		}
		ubbd_dev->data_pages_reserve = config_dp_reserve * ubbd_dev->data_pages / 100;
	}
	mutex_unlock(&ubbd_dev->req_lock);

out:
	ubbd_nl_reply(info, UBBD_CMD_CONFIG, ret);
	return ret;
}

#ifdef HAVE_GENL_SMALL_OPS
static const struct genl_small_ops ubbd_genl_ops[] = {
	{
		.cmd	= UBBD_CMD_ADD_PREPARE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_add_prepare,
	},
	{
		.cmd	= UBBD_CMD_ADD,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_add,
	},
	{
		.cmd	= UBBD_CMD_REMOVE_PREPARE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_remove_prepare,
	},
	{
		.cmd	= UBBD_CMD_REMOVE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_remove,
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
		.cmd	= UBBD_CMD_ADD_PREPARE,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_add_prepare,
	},
	{
		.cmd	= UBBD_CMD_ADD,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_add,
	},
	{
		.cmd	= UBBD_CMD_REMOVE_PREPARE,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_remove_prepare,
	},
	{
		.cmd	= UBBD_CMD_REMOVE,
		.flags	= GENL_ADMIN_PERM,
		.doit	= handle_cmd_remove,
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
	.version = 2,
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
