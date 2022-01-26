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
	if (index < UBBD_REQ_INLINE_PI_MAX)
		req->inline_pi[index] = value;
	else
		req->pi[index - UBBD_REQ_INLINE_PI_MAX] = value;
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
		spin_lock(&ubbd_dev->req_lock);
		page_index = find_first_zero_bit(ubbd_dev->data_bitmap, 256*1024);
		if (page_index == 256*1024) {
			spin_unlock(&ubbd_dev->req_lock);
			ret = -ENOMEM;
			cnt--;
			goto out;
		}

		if (!xa_load(&ubbd_dev->data_pages, page_index)) {
			if (page) {
				ret = xa_err(xa_store(&ubbd_dev->data_pages, page_index, page, GFP_NOIO));
				if (ret) {
					pr_debug("xa_store failed.");
					spin_unlock(&ubbd_dev->req_lock);
					cnt--;
					goto out;
				}
				page = NULL;
			} else {
				spin_unlock(&ubbd_dev->req_lock);
				page = alloc_page(GFP_NOIO);
				if (!page) {
					ret = -ENOMEM;
					cnt--;
					goto out;
				}
				goto again;
			}
		}

		pr_debug("ydsyds_1: bvec_index: %u, page_index: %u", cnt, page_index);
		set_bit(page_index, ubbd_dev->data_bitmap);
		spin_unlock(&ubbd_dev->req_lock);

		ubbd_req_set_pi(req, cnt, page_index);
		cnt++;
	}

	if (bio->bi_next) {
		bio = bio->bi_next;
		goto next_bio;
	}

out:
	if (page)
		__free_page(page);

	if (ret) {
		spin_lock(&ubbd_dev->req_lock);
		while (cnt >= 0) {
			page_index = ubbd_req_get_pi(req, cnt);
			clear_bit(page_index, ubbd_dev->data_bitmap);
			cnt--;
		}
		spin_unlock(&ubbd_dev->req_lock);
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

	return xa_load(&ubbd_dev->data_pages, ubbd_req_get_pi(req, bvec_index));
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
	uint32_t page_index;

copy:
	bio_for_each_segment(bv, bio, iter) {
		page_index = ubbd_req_get_pi(ubbd_req, bvec_index);
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
	uint32_t page_index;

	pr_debug("%s, %d;", __func__, __LINE__);
copy:
	bio_for_each_segment(bv, bio, iter) {
		pr_debug("%s, %d;", __func__, __LINE__);
		page_index = ubbd_req_get_pi(ubbd_req, bvec_index);
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

int queue_ubbd_op_nodata(struct ubbd_device *ubbd_dev, enum ubbd_op op, struct request *rq)
{
	struct ubbd_request *ubbd_req = blk_mq_rq_to_pdu(rq);
	struct ubbd_se	*se;
	struct ubbd_se_hdr *header;
	size_t command_size;
	int ret = 0;

	pr_debug("queue_ubbd_op: %p", rq);
	ubbd_req->req = rq;
	ubbd_req->ubbd_dev = ubbd_dev;
	command_size = ubbd_cmd_get_base_cmd_size(0);

	spin_lock(&ubbd_dev->req_lock);
	ubbd_req->req_tid = ++ubbd_dev->req_tid;
	pr_debug("req_tid: %llu", ubbd_req->req_tid);
	if (!submit_ring_space_enough(ubbd_dev, command_size)) {
		pr_debug("space is not enough");
		ret = -ENOMEM;
		spin_unlock(&ubbd_dev->req_lock);
		return ret;
	}

	insert_padding(ubbd_dev, command_size);
	pr_debug("after insert padding");

	se = get_submit_entry(ubbd_dev);
	memset(se, 0, command_size);
	header = &se->header;

	ubbd_se_hdr_set_op(&header->len_op, op);
	ubbd_se_hdr_set_len(&header->len_op, command_size);

	pr_debug("len_op: %x", header->len_op);
	//se->priv_data = ubbd_req;
	se->priv_data = ubbd_req->req_tid;
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
	spin_unlock(&ubbd_dev->req_lock);

	pr_debug("notify");
	uio_event_notify(&ubbd_dev->uio_info);

	return 0;
}

int queue_ubbd_op(struct ubbd_device *ubbd_dev, enum ubbd_op op, struct request *rq)
{
	struct ubbd_request *ubbd_req = blk_mq_rq_to_pdu(rq);
	struct ubbd_se	*se;
	struct ubbd_se_hdr *header;
	size_t command_size;
	u64 offset = (u64)blk_rq_pos(rq) << SECTOR_SHIFT;
	u64 length = blk_rq_bytes(rq);
	struct bio *bio = rq->bio;
	int ret = 0;

	pr_debug("queue_ubbd_op: %p", rq);
	ubbd_req->req = rq;
	ubbd_req->ubbd_dev = ubbd_dev;
	ubbd_req->pi_cnt = ubbd_bio_segments(bio);
	if (ubbd_req->pi_cnt > UBBD_REQ_INLINE_PI_MAX) {
		ubbd_req->pi = kcalloc(ubbd_req->pi_cnt - UBBD_REQ_INLINE_PI_MAX, sizeof(uint32_t), GFP_NOIO);
		if (!ubbd_req->pi) {
			pr_debug("kcalloc failed");
			return -ENOMEM;
		}

	}

	ret = ubbd_get_empty_block(ubbd_dev, bio, ubbd_req);
	if (ret) {
		pr_debug("get empty failed");
		goto err_free_pi;
	}

	command_size = ubbd_cmd_get_base_cmd_size(ubbd_req->pi_cnt);

	spin_lock(&ubbd_dev->req_lock);
	ubbd_req->req_tid = ++ubbd_dev->req_tid;
	pr_debug("req_tid: %llu", ubbd_req->req_tid);
	if (!submit_ring_space_enough(ubbd_dev, command_size)) {
		pr_debug("space is not enough");
		ret = -ENOMEM;
		spin_unlock(&ubbd_dev->req_lock);
		goto err_free_pages;
	}

	insert_padding(ubbd_dev, command_size);
	pr_debug("after insert padding");

	se = get_submit_entry(ubbd_dev);
	memset(se, 0, command_size);
	header = &se->header;

	ubbd_se_hdr_set_op(&header->len_op, op);
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
	spin_unlock(&ubbd_dev->req_lock);

	pr_debug("notify");
	uio_event_notify(&ubbd_dev->uio_info);

	return 0;

err_free_pages:
	if (ubbd_req->pi_cnt) {
		int cnt = ubbd_req->pi_cnt;
		int page_index = 0;
		while (cnt >= 0) {
			page_index = ubbd_req_get_pi(ubbd_req, cnt);
			clear_bit(page_index, ubbd_dev->data_bitmap);
			cnt--;
		}
	}
err_free_pi:
	if (ubbd_req->pi)
		kfree(ubbd_req->pi);

	return ret;
}

/* requests */
static void ubbd_req_release(struct ubbd_request *ubbd_req)
{
	uint32_t bvec_index = 0;
	uint32_t page_index;
	struct ubbd_device *ubbd_dev = ubbd_req->ubbd_dev;

	for (bvec_index = 0; bvec_index < ubbd_req->pi_cnt; bvec_index++) {
		page_index = ubbd_req_get_pi(ubbd_req, bvec_index);
		pr_debug("release page: %u", page_index);
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
	struct ubbd_request *req, *next;
	bool found = false;

	list_for_each_entry_safe(req, next, &ubbd_dev->inflight_reqs, inflight_reqs_node) {
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

	pr_debug("get oldest se: %p tail: %u, priv_data: %llu", se, ubbd_dev->sb_addr->cmd_tail, se->priv_data);
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
	spin_lock(&ubbd_dev->req_lock);
	ce = get_complete_entry(ubbd_dev);
	if (!ce) {
		spin_unlock(&ubbd_dev->req_lock);
		return;
	}

	ubbd_flush_dcache_range(ce, sizeof(*ce));
	pr_debug("ce: %p", ce);
	pr_debug("ce id: %llu", ce->priv_data);
	//req = ce->priv_data;
	req = find_inflight_req(ubbd_dev, ce->priv_data);
	WARN_ON(!req);
	if (!req) {
		spin_unlock(&ubbd_dev->req_lock);
		pr_debug("cant find inflight");
		udelay(100);
		goto again;
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
	UPDATE_COMPR_TAIL(ubbd_dev->sb_addr->compr_tail, sizeof(struct ubbd_ce), ubbd_dev->sb_addr->compr_size);
	pr_debug("update compr tail");
	spin_unlock(&ubbd_dev->req_lock);

	ubbd_flush_dcache_range(ubbd_dev->sb_addr, sizeof(*ubbd_dev->sb_addr));
	goto again;
}
