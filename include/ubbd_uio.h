#ifndef UBBD_UIO_H
#define UBBD_UIO_H
#include "ubbd_dev.h"

int device_close_shm(struct ubbd_device *ubbd_dev);
int device_open_shm(struct ubbd_device *ubbd_dev);
void ubbdlib_processing_start(struct ubbd_device *dev);
void ubbdlib_processing_complete(struct ubbd_device *dev);
struct ubbd_se *device_cmd_head(struct ubbd_device *dev);
struct ubbd_se *device_cmd_tail(struct ubbd_device *dev);
struct ubbd_dev_info *ubbd_uio_get_dev_info(void *map);
struct ubbd_se *device_cmd_to_handle(struct ubbd_device *dev);
void ubbd_uio_advance_cmd_ring(struct ubbd_device *ubbd_dev);

#endif	/* UBBD_UIO_H */
