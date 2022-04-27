#include "ubbd_internal.h"
#include <linux/delay.h>

struct ubbd_se *get_submit_entry(struct ubbd_queue *ubbd_q)
{
	struct ubbd_se *se;

	pr_debug("get se head : %u", ubbd_q->sb_addr->cmd_head);
	se = (struct ubbd_se *)(ubbd_q->cmdr + ubbd_q->sb_addr->cmd_head);

	return se;
}

struct ubbd_se *get_oldest_se(struct ubbd_queue *ubbd_q)
{
	if (ubbd_q->sb_addr->cmd_tail == ubbd_q->sb_addr->cmd_head)
		return NULL;

	pr_debug("get tail se: %u", ubbd_q->sb_addr->cmd_tail);
	return (struct ubbd_se *)(ubbd_q->cmdr + ubbd_q->sb_addr->cmd_tail);
}

struct ubbd_ce *get_complete_entry(struct ubbd_queue *ubbd_q)
{
	if (ubbd_q->sb_addr->compr_tail == ubbd_q->sb_addr->compr_head)
		return NULL;

	pr_debug("get complete entry: %u, head: %u", ubbd_q->sb_addr->compr_tail, ubbd_q->sb_addr->compr_head);
	return (struct ubbd_ce *)(ubbd_q->compr + ubbd_q->sb_addr->compr_tail);
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

static struct page *ubbd_alloc_page(struct ubbd_queue *ubbd_q)
{
	struct page *page;

#ifdef UBBD_FAULT_INJECT
	if (ubbd_req_need_fault())
		return NULL;
#endif /* UBBD_FAULT_INJECT */

	page = alloc_page(GFP_NOIO);
	if (!page) {
		return NULL;
	}

	pr_debug("alloc page: %p", page);
	ubbd_q->data_pages_allocated++;

	return page;
}

static void __ubbd_release_page(struct ubbd_queue *ubbd_q, struct page *page)
{
	pr_debug("release page: %p", page);
	__free_page(page);
	ubbd_q->data_pages_allocated--;
}

static void ubbd_release_page(struct ubbd_queue *ubbd_q,
		struct ubbd_request *ubbd_req, int bvec_index)
{
	struct page *page = NULL;
	int page_index = ubbd_req_get_pi(ubbd_req, bvec_index);

	pr_debug("release page: %u, req: %p, bvec_index: %u ",
			page_index, ubbd_req, bvec_index);

	clear_bit(page_index, ubbd_q->data_bitmap);
	if (ubbd_q->data_pages_allocated > ubbd_q->data_pages_reserve) {
		loff_t off;

		page = xa_load(&ubbd_q->data_pages_array, page_index);
		if (!page)
			return;

		off = ubbd_q->data_off + page_index * 4096;
		unmap_mapping_range(ubbd_q->inode->i_mapping, off, 2, 1);

		xa_erase(&ubbd_q->data_pages_array, page_index);
		__ubbd_release_page(ubbd_q, page);
	}
}

static int ubbd_xa_store_page(struct ubbd_queue *ubbd_q, int page_index,
		struct page *page)
{
#ifdef UBBD_FAULT_INJECT
	if (ubbd_req_need_fault())
		return -ENOMEM;
#endif /* UBBD_FAULT_INJECT */
	return xa_err(xa_store(&ubbd_q->data_pages_array,
				page_index, page, GFP_NOIO));
}

static int ubbd_get_data_pages(struct ubbd_queue *ubbd_q, struct ubbd_request *req)
{
	struct page *page;
	int bvec_index = 0, page_index = 0;
	struct bio_vec bv;
	struct bvec_iter iter;
	struct bio *bio = req->req->bio;
	int ret = 0;

next_bio:
	bio_for_each_segment(bv, bio, iter) {
		page_index = find_first_zero_bit(ubbd_q->data_bitmap, ubbd_q->data_pages);
		if (page_index == ubbd_q->data_pages) {
			ret = -ENOMEM;
			goto out;
		}

		page = xa_load(&ubbd_q->data_pages_array, page_index);
		if (!page) {
			page = ubbd_alloc_page(ubbd_q);
			if (!page) {
				pr_err("failed to alloc page.");
				ret = -ENOMEM;
				goto out;
			}
			ret = ubbd_xa_store_page(ubbd_q, page_index, page);
			if (ret) {
				pr_err("xa_store failed.");
				__ubbd_release_page(ubbd_q, page);
				goto out;
			}
		}

		set_bit(page_index, ubbd_q->data_bitmap);
		ubbd_req_set_pi(req, bvec_index++, page_index);
	}

	if (bio->bi_next) {
		bio = bio->bi_next;
		goto next_bio;
	}

out:
	if (ret) {
		pr_err("ret is %d, bvec_index: %d", ret, bvec_index);
		while (bvec_index > 0) {
			ubbd_release_page(ubbd_q, req, --bvec_index);
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

next:
	bio_for_each_segment(bv, bio, iter) {
		page_index = ubbd_req_get_pi(ubbd_req, bvec_index);

		pr_debug("bvec_index: %u, page_index: %u", bvec_index, page_index);
		se->iov[bvec_index].iov_base = (void *)((page_index * PAGE_SIZE) + ubbd_req->ubbd_q->data_off + bv.bv_offset);
		se->iov[bvec_index].iov_len = bv.bv_len;
		bvec_index++;
	}

	if (bio->bi_next) {
		bio = bio->bi_next;
		goto next;
	}

	return;
}

static struct page *ubbd_req_get_page(struct ubbd_request *req, uint32_t bvec_index)
{
	struct ubbd_queue *ubbd_q = req->ubbd_q;

	return xa_load(&ubbd_q->data_pages_array, ubbd_req_get_pi(req, bvec_index));
}

static bool ubbd_req_nodata(struct ubbd_request *ubbd_req)
{
	switch (ubbd_req->op) {
		case UBBD_OP_WRITE:
		case UBBD_OP_READ:
			return false;
		case UBBD_OP_DISCARD:
		case UBBD_OP_WRITE_ZEROS:
		case UBBD_OP_FLUSH:
			return true;
		default:
			BUG();
	}
}

static uint32_t ubbd_req_segments(struct ubbd_request *ubbd_req)
{
	uint32_t segs = 0;
	struct bio *bio = ubbd_req->req->bio;

	if (ubbd_req_nodata(ubbd_req))
		return 0;

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

copy:
	bio_for_each_segment(bv, bio, iter) {
		page = ubbd_req_get_page(ubbd_req, bvec_index);
		BUG_ON(!page);

		src = kmap_atomic(bv.bv_page);
		dst = kmap_atomic(page);

		memcpy(dst + bv.bv_offset, src + bv.bv_offset, bv.bv_len);
		kunmap_atomic(dst);
		kunmap_atomic(src);

		bvec_index++;
	}

	if (bio->bi_next) {
		bio = bio->bi_next;
		goto copy;
	}

	return;
}

static bool submit_ring_space_enough(struct ubbd_queue *ubbd_q, u32 cmd_size)
{
	u32 space_available;
	u32 space_needed;
	u32 space_max, space_used;

	/* There is a CMDR_RESERVED we dont use to prevent the ring to be used up */
	space_max = ubbd_q->sb_addr->cmdr_size - CMDR_RESERVED;

	if (ubbd_q->sb_addr->cmd_head > ubbd_q->sb_addr->cmd_tail)
		space_used = ubbd_q->sb_addr->cmd_head - ubbd_q->sb_addr->cmd_tail;
	else if (ubbd_q->sb_addr->cmd_head < ubbd_q->sb_addr->cmd_tail)
		space_used = ubbd_q->sb_addr->cmd_head + (ubbd_q->sb_addr->cmdr_size - ubbd_q->sb_addr->cmd_tail);
	else
		space_used = 0;

	space_available = space_max - space_used;

	if (ubbd_q->sb_addr->cmdr_size - ubbd_q->sb_addr->cmd_head > cmd_size)
		space_needed = cmd_size;
	else
		space_needed = cmd_size + ubbd_q->sb_addr->cmdr_size - ubbd_q->sb_addr->cmd_head;

	if (space_available < space_needed)
		return false;

	return true;
}

static void insert_padding(struct ubbd_queue *ubbd_q, u32 cmd_size)
{
	struct ubbd_se_hdr *header;
	u32 pad_len;

	if (ubbd_q->sb_addr->cmdr_size - ubbd_q->sb_addr->cmd_head >= cmd_size)
		return;

	pad_len = ubbd_q->sb_addr->cmdr_size - ubbd_q->sb_addr->cmd_head;

	header = (struct ubbd_se_hdr *)get_submit_entry(ubbd_q);
	memset(header, 0, pad_len);
	ubbd_se_hdr_set_op(&header->len_op, UBBD_OP_PAD);
	ubbd_se_hdr_set_len(&header->len_op, pad_len);

	UPDATE_CMDR_HEAD(ubbd_q->sb_addr->cmd_head, pad_len, ubbd_q->sb_addr->cmdr_size);
}

void ubbd_req_init(struct ubbd_queue *ubbd_q, enum ubbd_op op, struct request *rq)
{
	struct ubbd_request *ubbd_req = blk_mq_rq_to_pdu(rq);

	ubbd_req->req = rq;
	ubbd_req->ubbd_q = ubbd_q;
	ubbd_req->op = op;
}

static int ubbd_req_pi_alloc(struct ubbd_request *ubbd_req)
{
#ifdef UBBD_FAULT_INJECT
	if (ubbd_req_need_fault())
		return -ENOMEM;
#endif /* UBBD_FAULT_INJECT */
	ubbd_req->pi = kcalloc(ubbd_req->pi_cnt - UBBD_REQ_INLINE_PI_MAX,
				sizeof(uint32_t), GFP_NOIO);
	if (!ubbd_req->pi)
		return -ENOMEM;

	return 0;
}

static inline size_t ubbd_get_cmd_size(struct ubbd_request *ubbd_req)
{
	u32 cmd_size = sizeof(struct ubbd_se) + (sizeof(struct iovec) * ubbd_req->pi_cnt);

	return round_up(cmd_size, UBBD_OP_ALIGN_SIZE);
}

static int queue_req_prepare(struct ubbd_request *ubbd_req)
{
	struct ubbd_queue *ubbd_q = ubbd_req->ubbd_q;
	size_t command_size;
	int ret;

	ubbd_req->pi_cnt = ubbd_req_segments(ubbd_req);
	command_size = ubbd_get_cmd_size(ubbd_req);

	if (!submit_ring_space_enough(ubbd_q, command_size)) {
		pr_debug("cmd ring space is not enough");
		ret = -ENOMEM;
		goto err;
	}

	if (ubbd_req->pi_cnt > UBBD_REQ_INLINE_PI_MAX) {
		ret = ubbd_req_pi_alloc(ubbd_req);
		if (ret) {
			pr_err("pi kcalloc failed");
			goto err;
		}

	}

	if (ubbd_req->pi_cnt) {
		ret = ubbd_get_data_pages(ubbd_q, ubbd_req);
		if (ret) {
			pr_err("get data page failed");
			goto err_free_pi;
		}
	}

	insert_padding(ubbd_q, command_size);
	ubbd_req->req_tid = ++ubbd_q->req_tid;

	return 0;

err_free_pi:
	if (ubbd_req->pi)
		kfree(ubbd_req->pi);
err:
	return ret;

}

static void queue_req_se_init(struct ubbd_request *ubbd_req)
{
	struct ubbd_se	*se;
	struct ubbd_se_hdr *header;
	u64 offset = (u64)blk_rq_pos(ubbd_req->req) << SECTOR_SHIFT;
	u64 length = blk_rq_bytes(ubbd_req->req);

	se = get_submit_entry(ubbd_req->ubbd_q);
	memset(se, 0, ubbd_get_cmd_size(ubbd_req));
	header = &se->header;

	ubbd_se_hdr_set_op(&header->len_op, ubbd_req->op);
	ubbd_se_hdr_set_len(&header->len_op, ubbd_get_cmd_size(ubbd_req));

	se->priv_data = ubbd_req->req_tid;
	se->offset = offset;
	se->len = length;
	se->iov_cnt = ubbd_req->pi_cnt;

	ubbd_req->se = se;
}

static void queue_req_data_init(struct ubbd_request *ubbd_req)
{
	if (ubbd_req->pi_cnt) {
		ubbd_set_se_iov(ubbd_req);
	}

	if (req_op(ubbd_req->req) == REQ_OP_WRITE) {
		copy_data_to_ubbdreq(ubbd_req);
	}
}

void ubbd_queue_workfn(struct work_struct *work)
{
	struct ubbd_request *ubbd_req =
		container_of(work, struct ubbd_request, work);
	struct ubbd_queue *ubbd_q = ubbd_req->ubbd_q;
	int ret = 0;

	/*
	 * If queue is removing, return directly. This would happen
	 * in force unmapping.
	 * */
	if (test_bit(UBBD_QUEUE_FLAGS_REMOVING, &ubbd_q->flags)) {
		ret = -EIO;
		goto end_request;
	}

	mutex_lock(&ubbd_q->req_lock);
	ret = queue_req_prepare(ubbd_req);
	if (ret) {
		mutex_unlock(&ubbd_q->req_lock);
		goto end_request;
	}

	queue_req_se_init(ubbd_req);
	queue_req_data_init(ubbd_req);

	/* ubbd_req is ready, submit it to cmd ring */
	list_add_tail(&ubbd_req->inflight_reqs_node, &ubbd_q->inflight_reqs);

	UPDATE_CMDR_HEAD(ubbd_q->sb_addr->cmd_head,
			ubbd_get_cmd_size(ubbd_req),
			ubbd_q->sb_addr->cmdr_size);

	ubbd_flush_dcache_range(ubbd_q->sb_addr, sizeof(*ubbd_q->sb_addr));
	mutex_unlock(&ubbd_q->req_lock);

	uio_event_notify(&ubbd_q->uio_info);

	return;

end_request:
	if (ret == -ENOMEM)
		blk_mq_requeue_request(ubbd_req->req, true);
	else
		blk_mq_end_request(ubbd_req->req, errno_to_blk_status(ret));

	return;
}

blk_status_t ubbd_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct ubbd_queue *ubbd_q = hctx->driver_data;
	struct request *req = bd->rq;
	struct ubbd_request *ubbd_req = blk_mq_rq_to_pdu(bd->rq);

	/*
	 * If queue is removing, return directly. This would happen
	 * in force unmapping.
	 * */
	if (test_bit(UBBD_QUEUE_FLAGS_REMOVING, &ubbd_q->flags)) {
		return BLK_STS_IOERR;
	}

	memset(ubbd_req, 0, sizeof(struct ubbd_request));
	INIT_LIST_HEAD(&ubbd_req->inflight_reqs_node);

	blk_mq_start_request(bd->rq);

	switch (req_op(bd->rq)) {
	case REQ_OP_FLUSH:
		ubbd_req_init(ubbd_q, UBBD_OP_FLUSH, req);
		break;
	case REQ_OP_DISCARD:
		ubbd_req_init(ubbd_q, UBBD_OP_DISCARD, req);
		break;
	case REQ_OP_WRITE_ZEROES:
		ubbd_req_init(ubbd_q, UBBD_OP_WRITE_ZEROS, req);
		break;
	case REQ_OP_WRITE:
		ubbd_req_init(ubbd_q, UBBD_OP_WRITE, req);
		break;
	case REQ_OP_READ:
		ubbd_req_init(ubbd_q, UBBD_OP_READ, req);
		break;
	default:
		return BLK_STS_IOERR;
	}

	INIT_WORK(&ubbd_req->work, ubbd_queue_workfn);
	queue_work_on(current->on_cpu, ubbd_q->ubbd_dev->task_wq, &ubbd_req->work);

	return BLK_STS_OK;
}

static void ubbd_req_release(struct ubbd_request *ubbd_req)
{
	uint32_t bvec_index = 0;
	struct ubbd_queue *ubbd_q = ubbd_req->ubbd_q;

	for (bvec_index = 0; bvec_index < ubbd_req->pi_cnt; bvec_index++) {
		ubbd_release_page(ubbd_q, ubbd_req, bvec_index);
	}

	if (ubbd_req->pi) {
		kfree(ubbd_req->pi);
		ubbd_req->pi = NULL;
	}
}

static void advance_cmd_ring(struct ubbd_queue *ubbd_q)
{
       struct ubbd_se *se;

again:
       se = get_oldest_se(ubbd_q);
        if (!se)
               goto out;

	if (ubbd_se_hdr_flags_test(se, UBBD_SE_HDR_DONE)) {
		UPDATE_CMDR_TAIL(ubbd_q->sb_addr->cmd_tail,
				ubbd_se_hdr_get_len(se->header.len_op),
				ubbd_q->sb_addr->cmdr_size);
		goto again;
       }
out:
       ubbd_flush_dcache_range(ubbd_q->sb_addr, sizeof(*ubbd_q->sb_addr));
       return;
}

static struct ubbd_request *fetch_inflight_req(struct ubbd_queue *ubbd_q, u64 req_tid)
{
	struct ubbd_request *req;
	bool found = false;

	list_for_each_entry(req, &ubbd_q->inflight_reqs, inflight_reqs_node) {
		if (req->req_tid == req_tid) {
			list_del_init(&req->inflight_reqs_node);
			found = true;
			break;
		}
	}

	if (found)
		return req;
	return NULL;
}

static void complete_inflight_req(struct ubbd_queue *ubbd_q, struct ubbd_request *req, int ret)
{
	if (!list_empty(&req->inflight_reqs_node)) {
		list_del_init(&req->inflight_reqs_node);
	}
	ubbd_se_hdr_flags_set(req->se, UBBD_SE_HDR_DONE);
	ubbd_req_release(req);
	blk_mq_end_request(req->req, errno_to_blk_status(ret));
	advance_cmd_ring(ubbd_q);
}

void complete_work_fn(struct work_struct *work)
{
	struct ubbd_queue *ubbd_q = container_of(work, struct ubbd_queue, complete_work);
	struct ubbd_ce *ce;
	struct ubbd_request *req;

	/*
	 * If queue is removing, return directly. This would happen
	 * in force unmapping. inflight request would be ended by unmapping
	 * */
	if (test_bit(UBBD_QUEUE_FLAGS_REMOVING, &ubbd_q->flags)) {
		return;
	}

again:
	mutex_lock(&ubbd_q->req_lock);
	ce = get_complete_entry(ubbd_q);
	if (!ce) {
		mutex_unlock(&ubbd_q->req_lock);
		return;
	}

	ubbd_flush_dcache_range(ce, sizeof(*ce));
	req = fetch_inflight_req(ubbd_q, ce->priv_data);
	if (!req) {
		goto advance_compr;
	}

	if (req_op(req->req) == REQ_OP_READ)
		copy_data_from_ubbdreq(req);

	complete_inflight_req(ubbd_q, req, ce->result);

advance_compr:
	UPDATE_COMPR_TAIL(ubbd_q->sb_addr->compr_tail, sizeof(struct ubbd_ce), ubbd_q->sb_addr->compr_size);
	mutex_unlock(&ubbd_q->req_lock);

	ubbd_flush_dcache_range(ubbd_q->sb_addr, sizeof(*ubbd_q->sb_addr));
	goto again;
}

void ubbd_queue_end_inflight_reqs(struct ubbd_queue *ubbd_q, int ret)
{
	struct ubbd_request *req;

	while (!list_empty(&ubbd_q->inflight_reqs)) {
		req = list_first_entry(&ubbd_q->inflight_reqs,
				struct ubbd_request, inflight_reqs_node);
		complete_inflight_req(ubbd_q, req, ret);
	}
}

void ubbd_end_inflight_reqs(struct ubbd_device *ubbd_dev, int ret)
{
	int i;

	for (i = 0; i < ubbd_dev->num_queues; i++) {
		ubbd_queue_end_inflight_reqs(&ubbd_dev->queues[i], ret);
	}
}

enum blk_eh_timer_return ubbd_timeout(struct request *req, bool reserved)
{
	struct ubbd_request *ubbd_req = blk_mq_rq_to_pdu(req);
	struct ubbd_queue *ubbd_q = ubbd_req->ubbd_q;
	struct ubbd_device *ubbd_dev = ubbd_q->ubbd_dev;

	if (req->timeout == UINT_MAX)
		return BLK_EH_RESET_TIMER;

	pr_err("ubbd timeouted.");
	ubbd_dev_stop_disk(ubbd_dev, true);

	return BLK_EH_DONE;
}
