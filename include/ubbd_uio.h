#ifndef UBBD_UIO_H
#define UBBD_UIO_H
#include "utils.h"

struct ubbd_queue;
struct ubbd_uio_info {
	int fd;
	uint32_t uio_id;
	uint64_t uio_map_size;
	struct ubbd_sb *map;
};

int ubbd_close_uio(struct ubbd_uio_info *info);
int ubbd_open_uio(struct ubbd_uio_info *info);
int ubbd_processing_start(struct ubbd_uio_info *uio_info);
int ubbd_processing_complete(struct ubbd_uio_info *uio_info);
struct ubbd_se *ubbd_cmd_head(struct ubbd_uio_info *uio_info);
struct ubbd_se *ubbd_cmd_to_handle(struct ubbd_queue *ubbd_q);
void *ubbd_uio_get_info(struct ubbd_uio_info *uio_info);

#endif	/* UBBD_UIO_H */
