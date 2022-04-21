#include <linux/kthread.h>
#include <linux/delay.h>

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
	smp_load_acquire(&ubbd_dev->sb_addr->compr_head);
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

static struct page *ubbd_alloc_page(struct ubbd_device *ubbd_dev)
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
	ubbd_dev->data_pages_allocated++;

	return page;
}

static void __ubbd_release_page(struct ubbd_device *ubbd_dev, struct page *page)
{
	pr_debug("release page: %p", page);
	__free_page(page);
	ubbd_dev->data_pages_allocated--;
}

static void ubbd_release_page(struct ubbd_device *ubbd_dev,
		struct ubbd_request *ubbd_req, int bvec_index)
{
	struct page *page = NULL;
	int page_index = ubbd_req_get_pi(ubbd_req, bvec_index);

	pr_debug("release page: %u, req: %p, bvec_index: %u ",
			page_index, ubbd_req, bvec_index);

	clear_bit(page_index, ubbd_dev->data_bitmap);
	if (ubbd_dev->data_pages_allocated > ubbd_dev->data_pages_reserve) {
		loff_t off;

		page = xa_load(&ubbd_dev->data_pages_array, page_index);
		if (!page)
			return;

		off = ubbd_dev->data_off + page_index * 4096;
		unmap_mapping_range(ubbd_dev->inode->i_mapping, off, 2, 1);

		xa_erase(&ubbd_dev->data_pages_array, page_index);
		__ubbd_release_page(ubbd_dev, page);
	}
}

static int ubbd_xa_store_page(struct ubbd_device *ubbd_dev, int page_index,
		struct page *page)
{
#ifdef UBBD_FAULT_INJECT
	if (ubbd_req_need_fault())
		return -ENOMEM;
#endif /* UBBD_FAULT_INJECT */
	return xa_err(xa_store(&ubbd_dev->data_pages_array,
				page_index, page, GFP_NOIO));
}

static int ubbd_get_data_pages(struct ubbd_device *ubbd_dev, struct ubbd_request *req)
{
	struct page *page;
	int bvec_index = 0, page_index = 0;
	struct bio_vec bv;
	struct bvec_iter iter;
	struct bio *bio = req->req->bio;
	int ret = 0;

next_bio:
	bio_for_each_segment(bv, bio, iter) {
		page_index = find_first_zero_bit(ubbd_dev->data_bitmap, ubbd_dev->data_pages);
		if (page_index == ubbd_dev->data_pages) {
			ret = -ENOMEM;
			goto out;
		}

		page = xa_load(&ubbd_dev->data_pages_array, page_index);
		if (!page) {
			page = ubbd_alloc_page(ubbd_dev);
			if (!page) {
				pr_err("failed to alloc page.");
				ret = -ENOMEM;
				goto out;
			}
			ret = ubbd_xa_store_page(ubbd_dev, page_index, page);
			if (ret) {
				pr_err("xa_store failed.");
				__ubbd_release_page(ubbd_dev, page);
				goto out;
			}
		}

		set_bit(page_index, ubbd_dev->data_bitmap);
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
			ubbd_release_page(ubbd_dev, req, --bvec_index);
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
		se->iov[bvec_index].iov_base = (void *)((page_index * PAGE_SIZE) + ubbd_req->ubbd_dev->data_off + bv.bv_offset);
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
	struct ubbd_device *ubbd_dev = req->ubbd_dev;

	return xa_load(&ubbd_dev->data_pages_array, ubbd_req_get_pi(req, bvec_index));
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

	UPDATE_CMDR_HEAD(ubbd_dev->sb_addr->cmd_head, pad_len, ubbd_dev->sb_addr->cmdr_size);
}

void ubbd_req_init(struct ubbd_device *ubbd_dev, enum ubbd_op op, struct request *rq)
{
	struct ubbd_request *ubbd_req = blk_mq_rq_to_pdu(rq);

	ubbd_req->req = rq;
	ubbd_req->ubbd_dev = ubbd_dev;
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
	struct ubbd_device *ubbd_dev = ubbd_req->ubbd_dev;
	size_t command_size;
	int ret;

	ubbd_req->pi_cnt = ubbd_req_segments(ubbd_req);
	command_size = ubbd_get_cmd_size(ubbd_req);

	if (ubbd_dev->status == UBBD_DEV_STATUS_REMOVING) {
		ret = -EIO;
		goto err;
	}

	if (!submit_ring_space_enough(ubbd_dev, command_size)) {
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
		ret = ubbd_get_data_pages(ubbd_dev, ubbd_req);
		if (ret) {
			pr_err("get data page failed");
			goto err_free_pi;
		}
	}

	insert_padding(ubbd_dev, command_size);
	ubbd_req->req_tid = ++ubbd_dev->req_tid;

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

	se = get_submit_entry(ubbd_req->ubbd_dev);
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
	struct ubbd_device *ubbd_dev = ubbd_req->ubbd_dev;
	int ret = 0;

	mutex_lock(&ubbd_dev->req_lock);

	ret = queue_req_prepare(ubbd_req);
	if (ret)
		goto end_request;

	queue_req_se_init(ubbd_req);
	queue_req_data_init(ubbd_req);

	/* ubbd_req is ready, submit it to cmd ring */
	spin_lock(&ubbd_dev->inflight_reqs_lock);
	list_add_tail(&ubbd_req->inflight_reqs_node, &ubbd_dev->inflight_reqs);
	spin_unlock(&ubbd_dev->inflight_reqs_lock);

	UPDATE_CMDR_HEAD(ubbd_dev->sb_addr->cmd_head,
			ubbd_get_cmd_size(ubbd_req),
			ubbd_dev->sb_addr->cmdr_size);

	ubbd_flush_dcache_range(ubbd_dev->sb_addr, sizeof(*ubbd_dev->sb_addr));
	mutex_unlock(&ubbd_dev->req_lock);

	uio_event_notify(&ubbd_dev->uio_info);
	blk_mq_end_request(ubbd_req->req, errno_to_blk_status(0));

	return;

end_request:
	mutex_unlock(&ubbd_dev->req_lock);
	if (ret == -ENOMEM)
		blk_mq_requeue_request(ubbd_req->req, true);
	else
		blk_mq_end_request(ubbd_req->req, errno_to_blk_status(ret));

	return;
}

static void ubbd_wakeup_sq_thread(struct ubbd_device *ubbd_dev)
{
	struct ubbd_sb *sb = ubbd_dev->sb_addr;

	if (sb->flags & UBBD_SB_FLAG_NEED_WAKEUP) {
		uio_event_notify(&ubbd_dev->uio_info);
	}
}

void submit_req(struct ubbd_request *ubbd_req)
{
	struct ubbd_device *ubbd_dev = ubbd_req->ubbd_dev;
	int ret = 0;

	mutex_lock(&ubbd_dev->req_lock);

	ret = queue_req_prepare(ubbd_req);
	if (ret)
		goto end_request;

	queue_req_se_init(ubbd_req);
	queue_req_data_init(ubbd_req);

	/* ubbd_req is ready, submit it to cmd ring */
	list_add_tail(&ubbd_req->inflight_reqs_node, &ubbd_dev->inflight_reqs);

	UPDATE_CMDR_HEAD(ubbd_dev->sb_addr->cmd_head,
			ubbd_get_cmd_size(ubbd_req),
			ubbd_dev->sb_addr->cmdr_size);

	ubbd_flush_dcache_range(ubbd_dev->sb_addr, sizeof(*ubbd_dev->sb_addr));
	mutex_unlock(&ubbd_dev->req_lock);

	//uio_event_notify(&ubbd_dev->uio_info);
	ubbd_wakeup_sq_thread(ubbd_dev);

	return;

end_request:
	mutex_unlock(&ubbd_dev->req_lock);
	if (ret == -ENOMEM)
		blk_mq_requeue_request(ubbd_req->req, true);
	else
		blk_mq_end_request(ubbd_req->req, errno_to_blk_status(ret));

	return;
}

static void ubbd_req_release(struct ubbd_request *ubbd_req);
int submit_thread_fn(void *arg)
{
	struct ubbd_device *ubbd_dev = arg;
	struct ubbd_request *ubbd_req, *next_req;
	bool need_schedule = false;
	LIST_HEAD(tmp_list);
	cpumask_var_t cpumask;

	alloc_cpumask_var(&cpumask, GFP_KERNEL);
	cpumask_clear(cpumask);
	cpumask_set_cpu(1, cpumask);
	set_cpus_allowed_ptr(current, cpumask);
	free_cpumask_var(cpumask);

	while (!kthread_should_stop() &&
	       !(ubbd_dev->status == UBBD_DEV_STATUS_REMOVING)) {
		need_schedule = false;

		spin_lock(&ubbd_dev->pending_reqs_lock);
		if (list_empty(&ubbd_dev->pending_reqs)) {
			//pr_err("empty");
			need_schedule = true;
		} else {
			//pr_err("not empty");
			list_splice_init(&ubbd_dev->pending_reqs, &tmp_list);
		}
		spin_unlock(&ubbd_dev->pending_reqs_lock);

		if (need_schedule) {
			if (true) {
				//pr_err("before schedule");
				set_current_state(TASK_INTERRUPTIBLE);
				schedule();
				//pr_err("after schedule.");
			} else {
				yield();
			}
			continue;
		}
		set_current_state(TASK_RUNNING);

		//pr_err("before process");
		list_for_each_entry_safe(ubbd_req, next_req, &tmp_list, inflight_reqs_node) {
			list_del_init(&ubbd_req->inflight_reqs_node);
			submit_req(ubbd_req);
		}
	}


	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}

	return 0;
}

blk_status_t ubbd_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct ubbd_device *ubbd_dev = hctx->queue->queuedata;
	struct request *req = bd->rq;
	struct ubbd_request *ubbd_req = blk_mq_rq_to_pdu(bd->rq);

	memset(ubbd_req, 0, sizeof(struct ubbd_request));
	INIT_LIST_HEAD(&ubbd_req->inflight_reqs_node);

	blk_mq_start_request(bd->rq);

	switch (req_op(bd->rq)) {
	case REQ_OP_FLUSH:
		ubbd_req_init(ubbd_dev, UBBD_OP_FLUSH, req);
		break;
	case REQ_OP_DISCARD:
		ubbd_req_init(ubbd_dev, UBBD_OP_DISCARD, req);
		break;
	case REQ_OP_WRITE_ZEROES:
		ubbd_req_init(ubbd_dev, UBBD_OP_WRITE_ZEROS, req);
		break;
	case REQ_OP_WRITE:
		ubbd_req_init(ubbd_dev, UBBD_OP_WRITE, req);
		break;
	case REQ_OP_READ:
		ubbd_req_init(ubbd_dev, UBBD_OP_READ, req);
		break;
	default:
		return BLK_STS_IOERR;
	}

	spin_lock(&ubbd_dev->pending_reqs_lock);
	list_add_tail(&ubbd_req->inflight_reqs_node, &ubbd_dev->pending_reqs);
	spin_unlock(&ubbd_dev->pending_reqs_lock);

	//pr_err("before wakeup");
	wake_up_process(ubbd_dev->submit_thread);
	//pr_err("after wakeup");

	return BLK_STS_OK;

	INIT_WORK(&ubbd_req->work, ubbd_queue_workfn);
	queue_work(ubbd_wq, &ubbd_req->work);

	return BLK_STS_OK;
}

static void ubbd_req_release(struct ubbd_request *ubbd_req)
{
	uint32_t bvec_index = 0;
	struct ubbd_device *ubbd_dev = ubbd_req->ubbd_dev;

	for (bvec_index = 0; bvec_index < ubbd_req->pi_cnt; bvec_index++) {
		ubbd_release_page(ubbd_dev, ubbd_req, bvec_index);
	}

	if (ubbd_req->pi) {
		kfree(ubbd_req->pi);
		ubbd_req->pi = NULL;
	}
}

static void advance_cmd_ring(struct ubbd_device *ubbd_dev)
{
       struct ubbd_se *se;

again:
       se = get_oldest_se(ubbd_dev);
        if (!se)
               goto out;

	if (ubbd_se_hdr_flags_test(se, UBBD_SE_HDR_DONE)) {
		UPDATE_CMDR_TAIL(ubbd_dev->sb_addr->cmd_tail,
				ubbd_se_hdr_get_len(se->header.len_op),
				ubbd_dev->sb_addr->cmdr_size);
		goto again;
       }
out:
       ubbd_flush_dcache_range(ubbd_dev->sb_addr, sizeof(*ubbd_dev->sb_addr));
       return;
}

static struct ubbd_request *find_inflight_req(struct ubbd_device *ubbd_dev, u64 req_tid)
{
	struct ubbd_request *req;
	bool found = false;

	list_for_each_entry(req, &ubbd_dev->inflight_reqs, inflight_reqs_node) {
		if (req->req_tid == req_tid) {
			found = true;
			break;
		}
	}

	if (found)
		return req;
	return NULL;
}

static void complete_inflight_req(struct ubbd_device *ubbd_dev, struct ubbd_request *req, int ret)
{
	ubbd_se_hdr_flags_set(req->se, UBBD_SE_HDR_DONE);
	spin_lock(&ubbd_dev->inflight_reqs_lock);
	list_del_init(&req->inflight_reqs_node);
	spin_unlock(&ubbd_dev->inflight_reqs_lock);
	ubbd_req_release(req);
	blk_mq_end_request(req->req, errno_to_blk_status(ret));
	advance_cmd_ring(ubbd_dev);
}

int complete_thread_fn(void *arg)
{
	struct ubbd_device *ubbd_dev = arg;
	struct ubbd_ce *ce;
	struct ubbd_request *ubbd_req;
	cpumask_var_t cpumask;

	alloc_cpumask_var(&cpumask, GFP_KERNEL);
	cpumask_clear(cpumask);
	cpumask_set_cpu(5, cpumask);
	set_cpus_allowed_ptr(current, cpumask);
	free_cpumask_var(cpumask);

	while (!kthread_should_stop() &&
	       !(ubbd_dev->status == UBBD_DEV_STATUS_REMOVING)) {

		ce = get_complete_entry(ubbd_dev);
		if (!ce) {
			if (false) {
				//pr_err("before schedule");
				set_current_state(TASK_INTERRUPTIBLE);
				schedule();
				//pr_err("after schedule.");
			} else {
				udelay(2);
				yield();
			}
			continue;
		}

		ubbd_flush_dcache_range(ce, sizeof(*ce));
		mutex_lock(&ubbd_dev->req_lock);
		ubbd_req = find_inflight_req(ubbd_dev, ce->priv_data);
		WARN_ON(!ubbd_req);
		if (!ubbd_req) {
			mutex_unlock(&ubbd_dev->req_lock);
			goto advance_compr;
		}

		if (req_op(ubbd_req->req) == REQ_OP_READ)
			copy_data_from_ubbdreq(ubbd_req);

		complete_inflight_req(ubbd_dev, ubbd_req, ce->result);
		mutex_unlock(&ubbd_dev->req_lock);

	advance_compr:
		UPDATE_COMPR_TAIL(ubbd_dev->sb_addr->compr_tail, sizeof(struct ubbd_ce), ubbd_dev->sb_addr->compr_size);

		ubbd_flush_dcache_range(ubbd_dev->sb_addr, sizeof(*ubbd_dev->sb_addr));
	}


	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}

	return 0;
}

void complete_work_fn(struct work_struct *work)
{
	struct ubbd_device *ubbd_dev = container_of(work, struct ubbd_device, complete_work);
	struct ubbd_ce *ce;
	struct ubbd_request *req;
	cpumask_var_t cpumask;

	alloc_cpumask_var(&cpumask, GFP_KERNEL);
	cpumask_clear(cpumask);
	cpumask_set_cpu(1, cpumask);
	set_cpus_allowed_ptr(current, cpumask);
	free_cpumask_var(cpumask);

again:
	if (ubbd_dev->status == UBBD_DEV_STATUS_REMOVING) {
		return;
	}

	ce = get_complete_entry(ubbd_dev);
	if (!ce) {
		if (false) {
			udelay(1);
			yield();
			goto again;
		} else {
			return;
		}
	}

	ubbd_flush_dcache_range(ce, sizeof(*ce));
	req = find_inflight_req(ubbd_dev, ce->priv_data);
	WARN_ON(!req);
	if (!req) {
		goto advance_compr;
	}

	if (req_op(req->req) == REQ_OP_READ)
		copy_data_from_ubbdreq(req);

	mutex_lock(&ubbd_dev->req_lock);
	complete_inflight_req(ubbd_dev, req, ce->result);
	mutex_unlock(&ubbd_dev->req_lock);

advance_compr:
	UPDATE_COMPR_TAIL(ubbd_dev->sb_addr->compr_tail, sizeof(struct ubbd_ce), ubbd_dev->sb_addr->compr_size);

	ubbd_flush_dcache_range(ubbd_dev->sb_addr, sizeof(*ubbd_dev->sb_addr));
	goto again;
}

void ubbd_end_inflight_reqs(struct ubbd_device *ubbd_dev, int ret)
{
	struct ubbd_request *req;

	while (!list_empty(&ubbd_dev->inflight_reqs)) {
		req = list_first_entry(&ubbd_dev->inflight_reqs,
				struct ubbd_request, inflight_reqs_node);
		complete_inflight_req(ubbd_dev, req, ret);
	}
}

enum blk_eh_timer_return ubbd_timeout(struct request *req, bool reserved)
{
	struct ubbd_request *ubbd_req = blk_mq_rq_to_pdu(req);
	struct ubbd_device *ubbd_dev = ubbd_req->ubbd_dev;

	if (req->timeout == UINT_MAX)
		return BLK_EH_RESET_TIMER;

	mutex_lock(&ubbd_dev->req_lock);
	if (!list_empty(&ubbd_req->inflight_reqs_node)) {
		complete_inflight_req(ubbd_dev, ubbd_req, -ETIMEDOUT);
	}
	mutex_unlock(&ubbd_dev->req_lock);

	return BLK_EH_DONE;
}
