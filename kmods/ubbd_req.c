#include "ubbd_internal.h"

struct ubbd_se *get_submit_entry(struct ubbd_device *ubbd_dev)
{
	struct ubbd_se *se;

	pr_debug("get se head : %u", ubbd_dev->sb_addr->cmd_head);
	se = (struct ubbd_se *)(ubbd_dev->cmdr + ubbd_dev->sb_addr->cmd_head);

	return se;
}

struct ubbd_se *get_oldest_se(struct ubbd_device *ubbd_dev)
{
	if (ubbd_dev->sb_addr->cmd_tail == ubbd_dev->sb_addr->cmd_head)
		return NULL;

	pr_debug("get tail se: %u", ubbd_dev->sb_addr->cmd_tail);
	return (struct ubbd_se *)(ubbd_dev->cmdr + ubbd_dev->sb_addr->cmd_tail);
}

struct ubbd_ce *get_complete_entry(struct ubbd_device *ubbd_dev)
{
	if (ubbd_dev->sb_addr->compr_tail == ubbd_dev->sb_addr->compr_head)
		return NULL;

	pr_debug("get complete entry: %u, head: %u", ubbd_dev->sb_addr->compr_tail, ubbd_dev->sb_addr->compr_head);
	return (struct ubbd_ce *)(ubbd_dev->compr + ubbd_dev->sb_addr->compr_tail);
}

static uint32_t ubbd_req_get_pi(struct ubbd_request *req, uint32_t bvec_index)
{
	if (bvec_index < UBBD_REQ_INLINE_PI_MAX)
		return req->inline_pi[bvec_index];
	else
		return (req->pi[bvec_index - UBBD_REQ_INLINE_PI_MAX]);
}

static void ubbd_req_set_pi(struct ubbd_request *req, uint32_t index, int value)
{
	pr_debug("set pi: req: %p, bvec_index: %u, page_index: %d", req, index, value);
	if (index < UBBD_REQ_INLINE_PI_MAX)
		req->inline_pi[index] = value;
	else
		req->pi[index - UBBD_REQ_INLINE_PI_MAX] = value;
}

static void increase_page_allocated(struct ubbd_device *ubbd_dev)
{
	ubbd_dev->data_pages_allocated++;
}

static void decrease_page_allocated(struct ubbd_device *ubbd_dev, int page_index)
{
	struct page *page = NULL;

	if (ubbd_dev->data_pages_allocated > ubbd_dev->data_pages_reserve) {
		loff_t off;

		page = xa_load(&ubbd_dev->data_pages_array, page_index);
		if (!page)
			return;

		off = ubbd_dev->data_off + page_index * 4096;
		unmap_mapping_range(ubbd_dev->inode->i_mapping, off, 2, 1);

		xa_erase(&ubbd_dev->data_pages_array, page_index);
		__free_page(page);
		ubbd_dev->data_pages_allocated--;
	}
}

static int ubbd_get_empty_block(struct ubbd_device *ubbd_dev, struct bio *bio, struct ubbd_request *req)
{
	struct page *page = NULL;
	int cnt = 0;
	int page_index = 0;
	struct bio_vec bv;
	struct bvec_iter iter;
	int ret = 0;

next_bio:
	bio_for_each_segment(bv, bio, iter) {
again:
		page_index = find_first_zero_bit(ubbd_dev->data_bitmap, ubbd_dev->data_pages);
		if (page_index == ubbd_dev->data_pages) {
			ret = -ENOMEM;
			cnt--;
			goto out;
		}

		if (!xa_load(&ubbd_dev->data_pages_array, page_index)) {
			if (page) {
				ret = xa_err(xa_store(&ubbd_dev->data_pages_array, page_index, page, GFP_NOIO));
				if (ret) {
					pr_err("xa_store failed.");
					cnt--;
					goto out;
				}
				page = NULL;
			} else {
				page = alloc_page(GFP_NOIO);
				if (!page) {
					ret = -ENOMEM;
					cnt--;
					goto out;
				}
				pr_debug("alloc page: %p", page);
				increase_page_allocated(ubbd_dev);
				goto again;
			}
		}

		set_bit(page_index, ubbd_dev->data_bitmap);

		ubbd_req_set_pi(req, cnt, page_index);
		cnt++;
	}

	if (bio->bi_next) {
		bio = bio->bi_next;
		goto next_bio;
	}

out:
	if (page) {
		__free_page(page);
		ubbd_dev->data_pages_allocated--;
	}

	if (ret) {
		pr_err("ret is %d", ret);
		while (cnt >= 0) {
			page_index = ubbd_req_get_pi(req, cnt);
			decrease_page_allocated(ubbd_dev, page_index);
			clear_bit(page_index, ubbd_dev->data_bitmap);
			cnt--;
		}
	}
	return ret;
}

static void ubbd_set_se_iov(struct ubbd_request *ubbd_req)
{
	uint32_t bvec_index = 0;
	struct bio_vec bv;
	struct bvec_iter iter;
	struct bio *bio = ubbd_req->req->bio;
	uint32_t page_index;
	struct ubbd_se *se = ubbd_req->se;

	pr_debug("%s, %d;", __func__, __LINE__);
next:
	bio_for_each_segment(bv, bio, iter) {
		pr_debug("%s, %d;", __func__, __LINE__);
		page_index = ubbd_req_get_pi(ubbd_req, bvec_index);

		pr_debug("ydsyds_2: bvec_index: %u, page_index: %u", bvec_index, page_index);
		se->iov[bvec_index].iov_base = (void *)((page_index * PAGE_SIZE) + ubbd_req->ubbd_dev->data_off + bv.bv_offset);
		se->iov[bvec_index].iov_len = bv.bv_len;
		bvec_index++;
	}

	pr_debug("%s, %d;", __func__, __LINE__);
	if (bio->bi_next) {
		bio = bio->bi_next;
		goto next;
	}
	pr_debug("%s, %d;", __func__, __LINE__);
	return;
}

static struct page *ubbd_req_get_page(struct ubbd_request *req, uint32_t bvec_index)
{
	struct ubbd_device *ubbd_dev = req->ubbd_dev;

	return xa_load(&ubbd_dev->data_pages_array, ubbd_req_get_pi(req, bvec_index));
}

static uint32_t ubbd_bio_segments(struct bio *bio)
{
	uint32_t segs = 0;

	while (bio) {
		segs += bio_segments(bio);
		bio = bio->bi_next;
	}

	return segs;
}

static void copy_data_from_ubbdreq(struct ubbd_request *ubbd_req)
{
	uint32_t bvec_index = 0;
	struct bio_vec bv;
	struct bvec_iter iter;
	void *src, *dst;
	struct bio *bio = ubbd_req->req->bio;
	struct page *page = NULL;

copy:
	bio_for_each_segment(bv, bio, iter) {
		page = ubbd_req_get_page(ubbd_req, bvec_index);
		BUG_ON(!page);

		dst = kmap_atomic(bv.bv_page);
		src = kmap_atomic(page);

		pr_debug("copy page %p", page);
		memcpy(dst + bv.bv_offset, src + bv.bv_offset, bv.bv_len);
		kunmap_atomic(src);
		kunmap_atomic(dst);

		bvec_index++;
	}

	if (bio->bi_next) {
		bio = bio->bi_next;
		goto copy;
	}
	return;
}

static void copy_data_to_ubbdreq(struct ubbd_request *ubbd_req)
{
	uint32_t bvec_index = 0;
	struct bio_vec bv;
	struct bvec_iter iter;
	void *src, *dst;
	struct bio *bio = ubbd_req->req->bio;
	struct page *page = NULL;

	pr_debug("%s, %d;", __func__, __LINE__);
copy:
	bio_for_each_segment(bv, bio, iter) {
		pr_debug("%s, %d;", __func__, __LINE__);
		page = ubbd_req_get_page(ubbd_req, bvec_index);
		BUG_ON(!page);

		pr_debug("%s, %d;", __func__, __LINE__);
		src = kmap_atomic(bv.bv_page);
		dst = kmap_atomic(page);

		pr_debug("%s, %d;", __func__, __LINE__);
		memcpy(dst + bv.bv_offset, src + bv.bv_offset, bv.bv_len);
		pr_debug("%s, %d;", __func__, __LINE__);
		kunmap_atomic(dst);
		kunmap_atomic(src);

		bvec_index++;
	}

	pr_debug("%s, %d;", __func__, __LINE__);
	if (bio->bi_next) {
		bio = bio->bi_next;
		goto copy;
	}
	pr_debug("%s, %d;", __func__, __LINE__);
	return;
}

static bool submit_ring_space_enough(struct ubbd_device *ubbd_dev, u32 cmd_size)
{
	u32 space_available;
	u32 space_needed;
	u32 space_max, space_used;

	/* There is a CMDR_RESERVED we dont use to prevent the ring to be used up */
	space_max = ubbd_dev->sb_addr->cmdr_size - CMDR_RESERVED;

	if (ubbd_dev->sb_addr->cmd_head > ubbd_dev->sb_addr->cmd_tail)
		space_used = ubbd_dev->sb_addr->cmd_head - ubbd_dev->sb_addr->cmd_tail;
	else if (ubbd_dev->sb_addr->cmd_head < ubbd_dev->sb_addr->cmd_tail)
		space_used = ubbd_dev->sb_addr->cmd_head + (ubbd_dev->sb_addr->cmdr_size - ubbd_dev->sb_addr->cmd_tail);
	else
		space_used = 0;

	space_available = space_max - space_used;

	if (ubbd_dev->sb_addr->cmdr_size - ubbd_dev->sb_addr->cmd_head > cmd_size)
		space_needed = cmd_size;
	else
		space_needed = cmd_size + ubbd_dev->sb_addr->cmdr_size - ubbd_dev->sb_addr->cmd_head;

	if (space_available < space_needed)
		return false;

	return true;
}

static void insert_padding(struct ubbd_device *ubbd_dev, u32 cmd_size)
{
	struct ubbd_se_hdr *header;
	u32 pad_len;

	if (ubbd_dev->sb_addr->cmdr_size - ubbd_dev->sb_addr->cmd_head >= cmd_size)
		return;

	pad_len = ubbd_dev->sb_addr->cmdr_size - ubbd_dev->sb_addr->cmd_head;

	header = (struct ubbd_se_hdr *)get_submit_entry(ubbd_dev);
	memset(header, 0, pad_len);
	ubbd_se_hdr_set_op(&header->len_op, UBBD_OP_PAD);
	ubbd_se_hdr_set_len(&header->len_op, pad_len);
	header->flags |= 1;
	pr_debug("len_op: %x", header->len_op);
	pr_debug("insert pad: %u", pad_len);

	UPDATE_CMDR_HEAD(ubbd_dev->sb_addr->cmd_head, pad_len, ubbd_dev->sb_addr->cmdr_size);
}

void ubbd_req_init(struct ubbd_device *ubbd_dev, enum ubbd_op op, struct request *rq)
{
	struct ubbd_request *ubbd_req = blk_mq_rq_to_pdu(rq);

	ubbd_req->req = rq;
	ubbd_req->ubbd_dev = ubbd_dev;
	ubbd_req->op = op;
}

void ubbd_queue_nodata_workfn(struct work_struct *work)
{
	struct ubbd_request *ubbd_req =
		container_of(work, struct ubbd_request, work);
	struct ubbd_device *ubbd_dev = ubbd_req->ubbd_dev;
	struct ubbd_se	*se;
	struct ubbd_se_hdr *header;
	u64 offset = (u64)blk_rq_pos(ubbd_req->req) << SECTOR_SHIFT;
	u64 length = blk_rq_bytes(ubbd_req->req);
	size_t command_size;
	int ret = 0;

	command_size = ubbd_cmd_get_base_cmd_size(0);

	mutex_lock(&ubbd_dev->req_lock);

	if (ubbd_dev->status == UBBD_DEV_STATUS_REMOVING) {
		ret = -EIO;
		mutex_unlock(&ubbd_dev->req_lock);
		goto end_request;
	}

	ubbd_req->req_tid = ++ubbd_dev->req_tid;
	pr_debug("req_tid: %llu", ubbd_req->req_tid);
	if (!submit_ring_space_enough(ubbd_dev, command_size)) {
		pr_debug("space is not enough");
		ret = -ENOMEM;
		mutex_unlock(&ubbd_dev->req_lock);
		goto end_request;
	}

	insert_padding(ubbd_dev, command_size);
	pr_debug("after insert padding");

	se = get_submit_entry(ubbd_dev);
	memset(se, 0, command_size);
	header = &se->header;

	ubbd_se_hdr_set_op(&header->len_op, ubbd_req->op);
	ubbd_se_hdr_set_len(&header->len_op, command_size);

	pr_debug("len_op: %x", header->len_op);
	se->priv_data = ubbd_req->req_tid;
	se->offset = offset;
	se->len = length;
	pr_debug("se id: %llu", se->priv_data);

	pr_debug("%s, %d;", __func__, __LINE__);
	ubbd_req->se = se;
	pr_debug("%s, %d;", __func__, __LINE__);
	pr_debug("%s, %d: ubbd_req: %p;", __func__, __LINE__, ubbd_req);

	pr_debug("%s, %d; ubbd_req->req: %p", __func__, __LINE__, ubbd_req->req);
	pr_debug("%s, %d;", __func__, __LINE__);

	list_add_tail(&ubbd_req->inflight_reqs_node, &ubbd_dev->inflight_reqs);

	UPDATE_CMDR_HEAD(ubbd_dev->sb_addr->cmd_head, command_size, ubbd_dev->sb_addr->cmdr_size);
	pr_debug("head: %u, tail: %u", ubbd_dev->sb_addr->cmd_head, ubbd_dev->sb_addr->cmd_tail);
	ubbd_flush_dcache_range(ubbd_dev->sb_addr, sizeof(*ubbd_dev->sb_addr));
	mutex_unlock(&ubbd_dev->req_lock);

	pr_debug("notify");
	uio_event_notify(&ubbd_dev->uio_info);

	return;

end_request:
	atomic_dec(&ubbd_inflight);
	pr_debug("requeue inflight: %d", atomic_read(&ubbd_inflight));
	if (ret == -ENOMEM)
		blk_mq_requeue_request(ubbd_req->req, true);
	else
		blk_mq_end_request(ubbd_req->req, errno_to_blk_status(ret));

	return;
}

void ubbd_queue_workfn(struct work_struct *work)
{
	struct ubbd_request *ubbd_req =
		container_of(work, struct ubbd_request, work);
	struct ubbd_device *ubbd_dev = ubbd_req->ubbd_dev;
	struct ubbd_se	*se;
	struct ubbd_se_hdr *header;
	u64 offset = (u64)blk_rq_pos(ubbd_req->req) << SECTOR_SHIFT;
	u64 length = blk_rq_bytes(ubbd_req->req);
	struct bio *bio = ubbd_req->req->bio;
	size_t command_size;
	int ret = 0;

	ubbd_req->pi_cnt = ubbd_bio_segments(bio);
	command_size = ubbd_cmd_get_base_cmd_size(ubbd_req->pi_cnt);

	mutex_lock(&ubbd_dev->req_lock);
	if (ubbd_dev->status == UBBD_DEV_STATUS_REMOVING) {
		ret = -EIO;
		mutex_unlock(&ubbd_dev->req_lock);
		goto end_request;
	}

	if (!submit_ring_space_enough(ubbd_dev, command_size)) {
		pr_debug("space is not enough");
		ret = -ENOMEM;
		mutex_unlock(&ubbd_dev->req_lock);
		goto end_request;
	}

	ubbd_req->req_tid = ++ubbd_dev->req_tid;
	pr_debug("req_tid: %llu", ubbd_req->req_tid);

	if (ubbd_req->pi_cnt > UBBD_REQ_INLINE_PI_MAX) {
		ubbd_req->pi = kcalloc(ubbd_req->pi_cnt - UBBD_REQ_INLINE_PI_MAX, sizeof(uint32_t), GFP_NOIO);
		if (!ubbd_req->pi) {
			pr_debug("kcalloc failed");
			ret = -ENOMEM;
			goto end_request;
		}

	}

	ret = ubbd_get_empty_block(ubbd_dev, bio, ubbd_req);
	if (ret) {
		pr_err("get empty failed");
		goto err_free_pi;
	}

	insert_padding(ubbd_dev, command_size);
	pr_debug("after insert padding");

	se = get_submit_entry(ubbd_dev);
	memset(se, 0, command_size);
	header = &se->header;

	ubbd_se_hdr_set_op(&header->len_op, ubbd_req->op);
	ubbd_se_hdr_set_len(&header->len_op, command_size);

	pr_debug("len_op: %x", header->len_op);
	//se->priv_data = ubbd_req;
	se->priv_data = ubbd_req->req_tid;
	pr_debug("se id: %llu", se->priv_data);
	se->offset = offset;
	se->len = length;
	se->iov_cnt = ubbd_req->pi_cnt;

	pr_debug("%s, %d;", __func__, __LINE__);
	ubbd_req->se = se;
	pr_debug("%s, %d;", __func__, __LINE__);
	pr_debug("%s, %d: ubbd_req: %p;", __func__, __LINE__, ubbd_req);

	pr_debug("%s, %d; ubbd_req->req: %p", __func__, __LINE__, ubbd_req->req);
	pr_debug("%s, %d;", __func__, __LINE__);

	ubbd_set_se_iov(ubbd_req);

	if (req_op(ubbd_req->req) == REQ_OP_WRITE) {
		pr_debug("%s, %d;", __func__, __LINE__);
		copy_data_to_ubbdreq(ubbd_req);
		pr_debug("%s, %d;", __func__, __LINE__);
	}
	
	list_add_tail(&ubbd_req->inflight_reqs_node, &ubbd_dev->inflight_reqs);

	UPDATE_CMDR_HEAD(ubbd_dev->sb_addr->cmd_head, command_size, ubbd_dev->sb_addr->cmdr_size);
	pr_debug("head: %u, tail: %u", ubbd_dev->sb_addr->cmd_head, ubbd_dev->sb_addr->cmd_tail);
	ubbd_flush_dcache_range(ubbd_dev->sb_addr, sizeof(*ubbd_dev->sb_addr));
	mutex_unlock(&ubbd_dev->req_lock);

	pr_debug("notify");
	uio_event_notify(&ubbd_dev->uio_info);

	return;

err_free_pi:
	if (ubbd_req->pi)
		kfree(ubbd_req->pi);

end_request:
	atomic_dec(&ubbd_inflight);
	pr_debug("requeue inflight: %d", atomic_read(&ubbd_inflight));
	if (ret == -ENOMEM)
		blk_mq_requeue_request(ubbd_req->req, true);
	else
		blk_mq_end_request(ubbd_req->req, errno_to_blk_status(ret));

	return;
}

blk_status_t ubbd_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct ubbd_device *ubbd_dev = hctx->queue->queuedata;
	struct request *req = bd->rq;
	struct ubbd_request *ubbd_req = blk_mq_rq_to_pdu(bd->rq);

	memset(ubbd_req, 0, sizeof(struct ubbd_request));
	INIT_LIST_HEAD(&ubbd_req->inflight_reqs_node);

	pr_debug("start request: %p", req);
	blk_mq_start_request(bd->rq);
	atomic_inc(&ubbd_inflight);
	pr_debug("inc inflight: %d", atomic_read(&ubbd_inflight));

	switch (req_op(bd->rq)) {
	case REQ_OP_FLUSH:
		pr_debug("flush");
		ubbd_req_init(ubbd_dev, UBBD_OP_FLUSH, req);
		INIT_WORK(&ubbd_req->work, ubbd_queue_nodata_workfn);
		break;
	case REQ_OP_DISCARD:
		pr_debug("discard");
		ubbd_req_init(ubbd_dev, UBBD_OP_DISCARD, req);
		INIT_WORK(&ubbd_req->work, ubbd_queue_nodata_workfn);
		break;
	case REQ_OP_WRITE_ZEROES:
		pr_debug("writezero");
		ubbd_req_init(ubbd_dev, UBBD_OP_WRITE_ZEROS, req);
		INIT_WORK(&ubbd_req->work, ubbd_queue_nodata_workfn);
		break;
	case REQ_OP_WRITE:
		pr_debug("write");
		ubbd_req_init(ubbd_dev, UBBD_OP_WRITE, req);
		INIT_WORK(&ubbd_req->work, ubbd_queue_workfn);
		break;
	case REQ_OP_READ:
		pr_debug("read");
		ubbd_req_init(ubbd_dev, UBBD_OP_READ, req);
		INIT_WORK(&ubbd_req->work, ubbd_queue_workfn);
		break;
	default:
		atomic_dec(&ubbd_inflight);
		pr_debug("unknown req_op %d", req_op(bd->rq));
		return BLK_STS_IOERR;
	}

	queue_work(ubbd_wq, &ubbd_req->work);
	pr_debug("inflight: %d", atomic_read(&ubbd_inflight));

	return BLK_STS_OK;
}


/* requests */
static void ubbd_req_release(struct ubbd_request *ubbd_req)
{
	uint32_t bvec_index = 0;
	uint32_t page_index;
	struct ubbd_device *ubbd_dev = ubbd_req->ubbd_dev;

	for (bvec_index = 0; bvec_index < ubbd_req->pi_cnt; bvec_index++) {
		page_index = ubbd_req_get_pi(ubbd_req, bvec_index);
		pr_debug("release page: %u, req: %p, bvec_index: %u ", page_index, ubbd_req, bvec_index);

		decrease_page_allocated(ubbd_dev, page_index);
		clear_bit(page_index, ubbd_dev->data_bitmap);
	}

	if (ubbd_req->pi) {
		kfree(ubbd_req->pi);
		ubbd_req->pi = NULL;
	}
	pr_debug("finish releaes ubbd");
}


static struct ubbd_request *find_inflight_req(struct ubbd_device *ubbd_dev, u64 req_tid)
{
	struct ubbd_request *req;
	bool found = false;

	list_for_each_entry(req, &ubbd_dev->inflight_reqs, inflight_reqs_node) {
		pr_debug("find_inflight_req: req: %llu, req_tid: %llu", req->req_tid, req_tid);
		if (req->req_tid == req_tid) {
			found = true;
			break;
		}
	}

	if (found)
		return req;
	return NULL;
}

static void advance_cmd_ring(struct ubbd_device *ubbd_dev)
{
       struct ubbd_se *se;

again:
       se = get_oldest_se(ubbd_dev);
        if (!se)
               goto out;

	if (se->header.flags) {
		UPDATE_CMDR_TAIL(ubbd_dev->sb_addr->cmd_tail, ubbd_se_hdr_get_len(se->header.len_op), ubbd_dev->sb_addr->cmdr_size);
		goto again;
       }
out:
       ubbd_flush_dcache_range(ubbd_dev->sb_addr, sizeof(*ubbd_dev->sb_addr));
       return;
}

void complete_work_fn(struct work_struct *work)
{
	struct ubbd_device *ubbd_dev = container_of(work, struct ubbd_device, complete_work);
	struct ubbd_ce *ce;
	struct ubbd_se *se;
	struct ubbd_request *req;

	pr_debug("ubbd_irqcontrol");

again:
	mutex_lock(&ubbd_dev->req_lock);
	if (ubbd_dev->status == UBBD_DEV_STATUS_REMOVING) {
		mutex_unlock(&ubbd_dev->req_lock);
		return;
	}

	ce = get_complete_entry(ubbd_dev);
	if (!ce) {
		mutex_unlock(&ubbd_dev->req_lock);
		return;
	}

	ubbd_flush_dcache_range(ce, sizeof(*ce));
	pr_debug("ce: %p", ce);
	pr_debug("ce id: %llu", ce->priv_data);
	req = find_inflight_req(ubbd_dev, ce->priv_data);
	WARN_ON(!req);
	if (!req) {
		goto advance_compr;
	}

	se = req->se;

	if (req_op(req->req) == REQ_OP_READ)
		copy_data_from_ubbdreq(req);

	se->header.flags |= 1;
	pr_debug("end_request: %p: se: %p, se->priv_data: %llu, ce->result: %d ce->priv_data: %llu", req->req, se, se->priv_data, ce->result, ce->priv_data);

	atomic_dec(&ubbd_inflight);
	pr_debug("inflight: %d", atomic_read(&ubbd_inflight));
	list_del(&req->inflight_reqs_node);
	ubbd_req_release(req);
	pr_debug("end_request: %p", req->req);
	blk_mq_end_request(req->req, errno_to_blk_status(ce->result));
	pr_debug("after end request");

	advance_cmd_ring(ubbd_dev);
	pr_debug("after advance ring");

advance_compr:
	UPDATE_COMPR_TAIL(ubbd_dev->sb_addr->compr_tail, sizeof(struct ubbd_ce), ubbd_dev->sb_addr->compr_size);
	pr_debug("update compr tail");
	mutex_unlock(&ubbd_dev->req_lock);

	ubbd_flush_dcache_range(ubbd_dev->sb_addr, sizeof(*ubbd_dev->sb_addr));
	goto again;
}

void ubbd_end_inflight_reqs(struct ubbd_device *ubbd_dev, int ret)
{
	struct ubbd_request *req;

	while (!list_empty(&ubbd_dev->inflight_reqs)) {
		req = list_first_entry(&ubbd_dev->inflight_reqs,
				struct ubbd_request, inflight_reqs_node);
		list_del_init(&req->inflight_reqs_node);
		atomic_dec(&ubbd_inflight);
		ubbd_req_release(req);
		blk_mq_end_request(req->req, errno_to_blk_status(ret));
	}
}
