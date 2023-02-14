#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <pthread.h>

#include "utils.h"
#include "list.h"
#include "ubbd_queue.h"
#include "ubbd_uio.h"
#include "ubbd_netlink.h"
#include "ubbd_backend.h"

static bool compr_space_enough(struct ubbd_queue *ubbd_q, uint32_t required)
{
	struct ubbd_sb *sb = ubbd_q->uio_info.map;
	uint32_t space_available;
	uint32_t space_max, space_used;

	/* There is a CMPR_RESERVED we dont use to prevent the ring to be used up */
	space_max = sb->compr_size - CMPR_RESERVED;

	if (sb->compr_head > sb->compr_tail)
		space_used = sb->compr_head - sb->compr_tail;
	else if (sb->compr_head < sb->compr_tail)
		space_used = sb->compr_head + (sb->compr_size - sb->compr_tail);
	else
		space_used = 0;

	space_available = space_max - space_used;
	if (space_available < required)
		return false;

	return true;
}

struct ubbd_ce *get_available_ce(struct ubbd_queue *ubbd_q)
{
	struct ubbd_sb *sb = ubbd_q->uio_info.map;

	while (!compr_space_enough(ubbd_q, sizeof(struct ubbd_ce))) {
		pthread_mutex_unlock(&ubbd_q->req_lock);
		ubbd_err(" compr not enough head: %u, tail: %u\n", sb->compr_head, sb->compr_tail);
		ubbd_processing_complete(&ubbd_q->uio_info);
                usleep(50000);
		pthread_mutex_lock(&ubbd_q->req_lock);
	}

	return compr_head(ubbd_q);
}


static void wait_for_compr_empty(struct ubbd_queue *ubbd_q)
{
	struct ubbd_sb *sb = ubbd_q->uio_info.map;
 
         ubbd_info("waiting for ring to clear\n");
         while (sb->compr_head != sb->compr_tail) {
		 ubbd_info("head: %u, tail: %u\n", sb->compr_head, sb->compr_tail);
                 usleep(50000);
		 ubbd_processing_complete(&ubbd_q->uio_info);
		 if (ubbd_q->status == UBBD_QUEUE_USTATUS_STOPPING) {
			 ubbd_err("ubbd device is stopping\n");
			 break;
		 }
	 }
         ubbd_info("ring clear\n");
}
static void handle_cmd(struct ubbd_queue *ubbd_q, struct ubbd_se *se);
void *cmd_process(void *arg)
{
	struct ubbd_queue *ubbd_q = arg;
	struct ubbd_se *se;
	uint32_t op_len = 0;
	struct ubbd_sb *sb;
	struct pollfd pollfds[128];
	int ret;

	ret = ubbd_open_uio(&ubbd_q->uio_info);
	if (ret) {
		ubbd_err("failed to open shm: %d\n", ret);
		return NULL;
	}

	sb = ubbd_q->uio_info.map;

	if (ubbd_processing_complete(&ubbd_q->uio_info))
		goto out;

	wait_for_compr_empty(ubbd_q);

	ubbd_q->se_to_handle = sb->cmd_tail;
	ubbd_dbg("cmd_tail: %u, cmd_head: %u\n", sb->cmd_tail, sb->cmd_head);

	pthread_mutex_lock(&ubbd_q->lock);
	if (ubbd_q->status == UBBD_QUEUE_USTATUS_STOPPING) {
		pthread_mutex_unlock(&ubbd_q->lock);
		goto out;
	}
	ubbd_q->status = UBBD_QUEUE_USTATUS_RUNNING;
	pthread_mutex_unlock(&ubbd_q->lock);

	while (1) {
		while (1) {
			if (ubbd_processing_start(&ubbd_q->uio_info)) {
				ubbd_err("failed to start processing\n");
				goto out;
			}

			se = ubbd_cmd_to_handle(ubbd_q);
			if (se == ubbd_cmd_head(&ubbd_q->uio_info)) {
				break;
			}
			op_len = ubbd_se_hdr_get_len(se->header.len_op);
			ubbd_dbg("len_op: %x\n", se->header.len_op);
			ubbd_dbg("op: %d, length: %u\n", ubbd_se_hdr_get_op(se->header.len_op), ubbd_se_hdr_get_len(se->header.len_op));
			if (ubbd_se_hdr_get_op(se->header.len_op) != UBBD_OP_PAD)
				ubbd_dbg("se id: %llu\n", se->priv_data);
			handle_cmd(ubbd_q, se);
			UBBD_UPDATE_QUEUE_TO_HANDLE(ubbd_q, sb, op_len);
			ubbd_dbg("finish handle_cmd\n");
		}

poll:
		pollfds[0].fd = ubbd_q->uio_info.fd;
		pollfds[0].events = POLLIN;
		pollfds[0].revents = 0;

		ret = poll(pollfds, 1, 60);
		if (ret == -1) {
			ubbd_err("poll() returned %d, exiting\n", ret);
			goto out;
		}

		if (ubbd_q->status == UBBD_QUEUE_USTATUS_STOPPING) {
			ubbd_err("queue%d exit cmd_process\n", ubbd_q->index);
			goto out;
		}

		ubbd_dbg("poll cmd: %d\n", ret);
		if (!pollfds[0].revents) {
			goto poll;
		}

	}

out:
	ubbd_close_uio(&ubbd_q->uio_info);
	return NULL;
}

void ubbd_queue_stop(struct ubbd_queue *ubbd_q)
{
	if (!ubbd_q)
		return;

	pthread_mutex_lock(&ubbd_q->lock);
	ubbd_q->status = UBBD_QUEUE_USTATUS_STOPPING;
	pthread_mutex_unlock(&ubbd_q->lock);
}

struct q_backend_io_ctx_data {
	struct ubbd_queue *ubbd_q;
	struct ubbd_backend_io *io;
	struct ubbd_se *se;
};

static int q_backend_io_finish(struct context *ctx, int ret)
{
	struct q_backend_io_ctx_data *data = (struct q_backend_io_ctx_data *)ctx->data;
	struct ubbd_queue *ubbd_q = data->ubbd_q;
	struct ubbd_backend_io *io = data->io;
	struct ubbd_se *se = data->se;

	if (ret) {
		ubbd_err("ret of backend_io: %llu: %s\n", se->priv_data, strerror(-ret));
	}

	ubbd_queue_add_ce(ubbd_q, se->priv_data, ret);

	free(io);

	return 0;
}

static struct ubbd_backend_io *q_prepare_backend_io(struct ubbd_queue *ubbd_q,
		struct ubbd_se *se,  enum ubbd_backend_io_type type)
{
	struct ubbd_backend_io *io;
	struct context *ctx;
	struct q_backend_io_ctx_data *data;
	int i;

	io = calloc(1, sizeof(struct ubbd_backend_io) + sizeof(struct iovec) * se->iov_cnt);
	if (!io) {
		ubbd_err("failed to calloc for backend io\n");
		return NULL;
	}

	ctx = context_alloc(sizeof(struct q_backend_io_ctx_data));
	if (!ctx) {
		ubbd_err("failed to calloc for backend_io_ctx\n");
		free(io);
		return NULL;
	}

	data = (struct q_backend_io_ctx_data *)ctx->data;
	data->ubbd_q = ubbd_q;
	data->io = io;
	data->se = se;

	ctx->parent = NULL;
	ctx->finish = q_backend_io_finish;

	io->ctx = ctx;
	io->io_type = type;
	io->offset = se->offset;
	io->len = se->len;
	io->iov_cnt = se->iov_cnt;
	for (i = 0; i < se->iov_cnt; i++) {
		ubbd_dbg("iov_base: %lu\n", (size_t)se->iov[i].iov_base);
		io->iov[i].iov_base = (void*)ubbd_q->uio_info.map + (size_t)se->iov[i].iov_base;
		io->iov[i].iov_len = se->iov[i].iov_len;
	}

	return io;
}

static void handle_cmd(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	struct ubbd_backend *ubbd_b = ubbd_q->ubbd_b;
	struct ubbd_se_hdr *header = &se->header;
#ifdef	UBBD_REQUEST_STATS
	uint64_t start_ns = get_ns();
#endif
	int ret;
	struct ubbd_backend_io *io;

	ubbd_dbg("handle_cmd: se: %p\n", se);

	if (ubbd_b->status == UBBD_BACKEND_STATUS_ERROR) {
		ubbd_queue_add_ce(ubbd_q, se->priv_data, -EIO);
		return;
	}

	if (ubbd_se_hdr_flags_test(se, UBBD_SE_HDR_DONE)) {
		ubbd_dbg("flags is done\n");
		return;
	}

	switch (ubbd_se_hdr_get_op(header->len_op)) {
	case UBBD_OP_PAD:
		ubbd_dbg("set pad op to done\n");
		ubbd_se_hdr_flags_set(se, UBBD_SE_HDR_DONE);
		ret = 0;
		ubbd_processing_complete(&ubbd_q->uio_info);
		break;
	case UBBD_OP_WRITE:
		ubbd_dbg("UBBD_OP_WRITE\n");
		io = q_prepare_backend_io(ubbd_q, se, UBBD_BACKEND_IO_WRITE);
		if (!io) {
			ubbd_err("failed to prepare backend io\n");
			ret = -ENOMEM;
			goto out;
		}
		ret = ubbd_b->backend_ops->writev(ubbd_b, io);
		break;
	case UBBD_OP_READ:
		ubbd_dbg("UBBD_OP_READ\n");
		io = q_prepare_backend_io(ubbd_q, se, UBBD_BACKEND_IO_READ);
		if (!io) {
			ubbd_err("failed to prepare backend io\n");
			ret = -ENOMEM;
			goto out;
		}
		ret = ubbd_b->backend_ops->readv(ubbd_b, io);
		break;
	case UBBD_OP_FLUSH:
		ubbd_dbg("UBBD_OP_FLUSH\n");
		if (!ubbd_b->backend_ops->flush) {
			ret = -EOPNOTSUPP;
			ubbd_err("flush is not supportted.\n");
			goto out;
		}
		io = q_prepare_backend_io(ubbd_q, se, UBBD_BACKEND_IO_FLUSH);
		if (!io) {
			ubbd_err("failed to prepare backend io\n");
			ret = -ENOMEM;
			goto out;
		}
		ret = ubbd_b->backend_ops->flush(ubbd_b, io);
		break;
	case UBBD_OP_DISCARD:
		ubbd_dbg("UBBD_OP_DISCARD\n");
		if (!ubbd_b->backend_ops->discard) {
			ret = -EOPNOTSUPP;
			ubbd_err("discard is not supportted.\n");
			goto out;
		}
		io = q_prepare_backend_io(ubbd_q, se, UBBD_BACKEND_IO_DISCARD);
		if (!io) {
			ubbd_err("failed to prepare backend io\n");
			ret = -ENOMEM;
			goto out;
		}
		ret = ubbd_b->backend_ops->discard(ubbd_b, io);
		break;
	case UBBD_OP_WRITE_ZEROS:
		ubbd_dbg("UBBD_OP_WRITE_ZEROS\n");
		if (!ubbd_b->backend_ops->write_zeros) {
			ret = -EOPNOTSUPP;
			ubbd_err("write_zeros is not supportted.\n");
			goto out;
		}
		io = q_prepare_backend_io(ubbd_q, se, UBBD_BACKEND_IO_WRITEZEROS);
		if (!io) {
			ubbd_err("failed to prepare backend io\n");
			ret = -ENOMEM;
			goto out;
		}
		ret = ubbd_b->backend_ops->write_zeros(ubbd_b, io);
		break;
	default:
		ubbd_err("error handle_cmd\n");
	}

out:
	if (ret) {
		ubbd_err("ret of se: %llu: %d\n", se->priv_data, ret);
#ifdef	UBBD_REQUEST_STATS
	} else {
		pthread_mutex_lock(&ubbd_q->req_stats_lock);
		ubbd_q->req_stats.reqs++;
		ubbd_q->req_stats.handle_time += (get_ns() - start_ns);
		pthread_mutex_unlock(&ubbd_q->req_stats_lock);
#endif
	}

	return;
}

int ubbd_queue_setup(struct ubbd_queue *ubbd_q)
{
	int ret;

	ret = pthread_create(&ubbd_q->cmdproc_thread, NULL, cmd_process, ubbd_q);
	if (ret) {
		ubbd_err("failed to create cmdproc_thread: %d\n", ret);
		goto out;
	}
	pthread_setaffinity_np(ubbd_q->cmdproc_thread, CPU_SETSIZE, &ubbd_q->cpuset);

out:
	return ret;
}

int ubbd_queue_wait_stopped(struct ubbd_queue *ubbd_q)
{
	return pthread_join(ubbd_q->cmdproc_thread, NULL);
}

void ubbd_queue_init(struct ubbd_queue *ubbd_q)
{
	pthread_mutex_init(&ubbd_q->lock, NULL);
	pthread_mutex_init(&ubbd_q->req_lock, NULL);
	pthread_mutex_init(&ubbd_q->req_stats_lock, NULL);
	CPU_ZERO(&ubbd_q->cpuset);
}

void ubbd_queue_add_ce(struct ubbd_queue *ubbd_q, uint64_t priv_data,
		int result)
{
	struct ubbd_ce *ce;
	struct ubbd_sb *sb = ubbd_q->uio_info.map;

	pthread_mutex_lock(&ubbd_q->req_lock);
	ce = get_available_ce(ubbd_q);
	memset(ce, 0, sizeof(*ce));
	ce->priv_data = priv_data;
	ce->flags = 0;

	ce->result = result;
	ubbd_dbg("append ce: %llu, result: %d\n", ce->priv_data, ce->result);
	UBBD_UPDATE_COMPR_HEAD(ubbd_q, sb, ce);
	pthread_mutex_unlock(&ubbd_q->req_lock);
	ubbd_processing_complete(&ubbd_q->uio_info);
}
