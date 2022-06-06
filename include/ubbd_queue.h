#define _GNU_SOURCE
#ifndef UBBD_QUEUE_H
#define UBBD_QUEUE_H
#include <sched.h>
#include "ubbd_uio.h"
#include "ubbd_log.h"
#include "ubbd.h"
#include "ubbd_limits.h"

struct ubbd_req_stats {
	uint64_t reqs;
	uint64_t handle_time;
};

#define UBBD_QUEUE_USTATUS_INIT		0
#define UBBD_QUEUE_USTATUS_RUNNING	1
#define UBBD_QUEUE_USTATUS_STOPPING	2

struct ubbd_queue_info {
	int32_t	uio_id;
	uint64_t uio_map_size;
	cpu_set_t cpuset;
	pid_t backend_pid;
	int status;
};

struct ubbd_backend;
struct ubbd_queue {
	struct ubbd_backend		*ubbd_b;
	struct ubbd_uio_info		uio_info;
	cpu_set_t			cpuset;
	int				status;
	uint32_t			se_to_handle;
	pthread_t			cmdproc_thread;
	pthread_mutex_t			req_lock;
	pthread_mutex_t			lock;
	pid_t				backend_pid;
	int				index;

	pthread_mutex_t			req_stats_lock;
	struct ubbd_req_stats		req_stats;
};

static inline struct ubbd_ce *
compr_head(struct ubbd_queue *ubbd_q)
{
	struct ubbd_sb *sb = ubbd_q->uio_info.map;

	ubbd_dbg("comp: head: %u\n", sb->compr_head);

	return (struct ubbd_ce *) ((char *) sb + sb->compr_off + sb->compr_head);
}

struct ubbd_ce *get_available_ce(struct ubbd_queue *ubbd_q);
void ubbd_queue_add_ce(struct ubbd_queue *ubbd_q, uint64_t priv_data,
		int result);

#define UBBD_UPDATE_CMDR_TAIL(queue, sb, se) \
do { \
        sb->cmd_tail = (sb->cmd_tail + ubbd_se_hdr_get_len(se->header.len_op)) % sb->cmdr_size; \
	ubbd_dbg("cmd_tail: %u, cmd_head: %u\n", sb->cmd_tail, sb->cmd_head); \
} while (0)

#define UBBD_UPDATE_COMPR_HEAD(queue, sb, ce) \
do { \
        sb->compr_head = (sb->compr_head + sizeof(struct ubbd_ce)) % sb->compr_size; \
	ubbd_dbg("compr_head: %u, compr_tail: %u\n", sb->compr_head, sb->compr_tail); \
} while (0)

#define UBBD_UPDATE_QUEUE_TO_HANDLE(queue, sb, len) \
do { \
        queue->se_to_handle = (queue->se_to_handle + len) % sb->cmdr_size; \
} while (0)


void ubbd_queue_stop(struct ubbd_queue *ubbd_q);
int ubbd_queue_setup(struct ubbd_queue *ubbd_q);
int ubbd_queue_wait_stopped(struct ubbd_queue *ubbd_q);
#endif /* UBBD_QUEUE_H */
