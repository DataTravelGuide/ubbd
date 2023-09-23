#ifndef UBBD_KRING_H
#define UBBD_KRING_H
#include "utils.h"

struct ubbd_queue;
struct ubbd_kring_info {
	int fd;
	uint32_t kring_id;
	uint64_t kring_map_size;
	struct ubbd_sb *map;
};

int ubbd_close_kring(struct ubbd_kring_info *info);
int ubbd_open_kring(struct ubbd_kring_info *info);
int ubbd_processing_start(struct ubbd_kring_info *kring_info);
int ubbd_processing_complete(struct ubbd_kring_info *kring_info);
struct ubbd_se *ubbd_cmd_head(struct ubbd_kring_info *kring_info);
struct ubbd_se *ubbd_cmd_to_handle(struct ubbd_queue *ubbd_q);
void *ubbd_kring_get_info(struct ubbd_kring_info *kring_info);

static inline bool ubbd_kring_opened(struct ubbd_kring_info *kring_info)
{
	return (kring_info->map != NULL);
}

#endif	/* UBBD_KRING_H */
