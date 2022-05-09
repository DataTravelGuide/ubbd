#ifndef UBBD_UIO_H
#define UBBD_UIO_H
#include "ubbd_dev.h"

int ubbd_close_uio(struct ubbd_uio_info *info);
int ubbd_open_uio(struct ubbd_uio_info *info);
int ubbd_processing_start(struct ubbd_queue *ubbd_q);
int ubbd_processing_complete(struct ubbd_queue *ubbd_q);
struct ubbd_se *ubbd_cmd_head(struct ubbd_queue *ubbd_q);
struct ubbd_se *ubbd_cmd_to_handle(struct ubbd_queue *ubbd_q);
struct ubbd_dev_info *ubbd_uio_get_dev_info(void *map);

#endif	/* UBBD_UIO_H */
