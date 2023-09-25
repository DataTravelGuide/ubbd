#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>

#define ubbd_info printf
#define ubbd_err printf
#include "ubbd_mempool.h"

#define DATA_NUM	10000000000
#define DATA_SIZE	40
#define THREAD_NUM	100
#define BATCH_NUM	128

#define MEMPOOL	1

struct thread_info {
	int64_t test_num;
	pthread_t thread;
	struct ubbd_mempool *pool;
};

static int do_test(struct thread_info *info)
{
	void *datas[BATCH_NUM];
	void *data;
	int ret;
	int i;

	for (i = 0; i < BATCH_NUM; i++) {
		if (MEMPOOL) {
			ret = ubbd_mempool_get(info->pool, &datas[i]);
		} else {
			datas[i] = malloc(DATA_SIZE);
		}
	}

	for (i = 0; i < BATCH_NUM; i++) {
		if (MEMPOOL) {
			ubbd_mempool_put(datas[i]);
		} else {
			free(datas[i]);
		}
	}
	
	return BATCH_NUM;
}

static void *thread_fn(void *arg)
{
	struct thread_info *info = (struct thread_info *)arg;
	int64_t test_num = info->test_num;

	while (test_num >= 0) {
		test_num -= do_test(info);
	}
	return NULL;
}

int main()
{
	struct thread_info infos[THREAD_NUM] = { 0 };
	void *retval;
	int i;
	int ret;
	struct timeval then, now;
	gettimeofday(&then, NULL);
		 

	for (i = 0; i < THREAD_NUM; i++) {
		struct thread_info *info = &infos[i];

		info->pool = ubbd_mempool_alloc(DATA_SIZE, 1024);
		info->test_num = DATA_NUM / THREAD_NUM;
		ret = pthread_create(&info->thread, NULL, thread_fn, info);
		if (ret) {
			printf("failed to start thread %d\n", i);
			goto out;
		}
	}

	ret = 0;

out:
	for (i--;i >= 0; i--) {
		struct thread_info *info = &infos[i];

		pthread_join(info->thread, &retval);
		if (info->pool) {
			ubbd_mempool_free(info->pool);
		}
	}

	gettimeofday(&now, NULL);
	printf("Executions in %.3g seconds\n", now.tv_sec - then.tv_sec + 1e-6 * (now.tv_usec - then.tv_usec));

	return ret;
}
