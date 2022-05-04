#ifndef UBBD_UIO_H
#define UBBD_UIO_H
#include "ubbd_dev.h"

int device_close_shm(struct ubbd_uio_info *info);
int device_open_shm(struct ubbd_uio_info *info);
void ubbdlib_processing_start(struct ubbd_queue *ubbd_q);
void ubbdlib_processing_complete(struct ubbd_queue *ubbd_q);
struct ubbd_se *device_cmd_head(struct ubbd_queue *ubbd_q);
struct ubbd_se *device_cmd_tail(struct ubbd_queue *ubbd_q);
struct ubbd_dev_info *ubbd_uio_get_dev_info(void *map);
struct ubbd_se *device_cmd_to_handle(struct ubbd_queue *ubbd_q);

#endif	/* UBBD_UIO_H */
