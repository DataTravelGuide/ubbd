#define _GNU_SOURCE
#include<stdlib.h>
#include<stdio.h>
#include<unistd.h>
#include<string.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <sys/mman.h>

#include "ubbd_queue.h"
#include "ubbd_kring.h"
#include "ubbd.h"

int __real_open(const char *path, int flags, int mode);
int __wrap_open(const char *path, int flags, int mode)
{
	if (strlen(path) > 5 && !strcmp(path + strlen(path) - 5, ".gcda"))
		return __real_open(path, flags, mode);

	check_expected(path);
	return mock();
}

void *__wrap_mmap(void *addr, size_t length, int prot, int flags,
		                         int fd, off_t offset)
{
	check_expected(length);
	check_expected(fd);

	return mock_ptr_type(void *);
}

int __wrap_munmap(void *addr, size_t length)
{
	check_expected(addr);
	check_expected(length);

	return mock();
}

int __wrap_close(int fd)
{
	check_expected(fd);
	return mock();
}

ssize_t __wrap_read(int fd, void *buf, size_t count)
{
	check_expected(fd);
	check_expected(count);

	return mock();
}

ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
	check_expected(fd);
	check_expected(count);

	return mock();
}

int __wrap_asprintf(char **strp, const char *fmt, ...)
{
	va_list ap;
	int kring_id;
	int ret;

	va_start(ap, fmt);
	kring_id = va_arg(ap, int);
	va_end(ap);

	if (kring_id != -1) {
		va_start(ap, fmt);
		ret = vasprintf(strp, fmt, ap);
		va_end(ap);
		return ret;
	}

	return mock();
}


void test_get_dev_info(void **state)
{
	struct ubbd_kring_info kring_info = { 0 };
	struct ubbd_sb sb = { 0 };
	void *info;

	// invalid ubbd magic
	kring_info.map = &sb;
	info = ubbd_kring_get_info(&kring_info);
	assert_null(info);

	// set magic and info_off is zero
	sb.magic = UBBD_MAGIC;
	sb.info_off = 0;

	info = ubbd_kring_get_info(&kring_info);
	assert_ptr_equal(info, &sb);

	// set info_off to 1
	sb.info_off = 1;
	info = ubbd_kring_get_info(&kring_info);
	assert_ptr_equal(info, (char *)(&sb) + 1);
}

void test_open_shm(void **state)
{
	int ret;
	struct ubbd_kring_info kring_info = { 0 };
	struct ubbd_sb sb = { 0 };

	// asprintf fail
	kring_info.kring_id = -1;
	will_return(__wrap_asprintf, -1);
	ret = ubbd_open_kring(&kring_info);
	assert_int_equal(ret, -1);

	// faild to open ubbd_kring0
	kring_info.kring_id = 0;
	expect_string(__wrap_open, path, "/dev/ubbd_kring0");
	will_return(__wrap_open, -1);

	ret = ubbd_open_kring(&kring_info);
	assert_int_equal(ret, -1);

	// open kring1 failed to mmap
	kring_info.kring_id = 1;
	expect_string(__wrap_open, path, "/dev/ubbd_kring1");
	will_return(__wrap_open, 1);

	kring_info.kring_map_size = 0;
	expect_value(__wrap_mmap, fd, 1);
	expect_value(__wrap_mmap, length, 0);
	will_return(__wrap_mmap, MAP_FAILED);

	expect_value(__wrap_close, fd, 1);
	will_return(__wrap_close, 0);

	ret = ubbd_open_kring(&kring_info);
	assert_int_equal(ret, -1);

	// open_shm ok
	kring_info.kring_id = 1;
	expect_string(__wrap_open, path, "/dev/ubbd_kring1");
	will_return(__wrap_open, 1);

	sb.version = 1;
	kring_info.kring_map_size = 10;
	expect_value(__wrap_mmap, fd, 1);
	expect_value(__wrap_mmap, length, 10);
	will_return(__wrap_mmap, &sb);

	ret = ubbd_open_kring(&kring_info);
	assert_int_equal(ret, 0);
	
	// close shm
	expect_value(__wrap_close, fd, 1);
	will_return(__wrap_close, 0);

	expect_value(__wrap_munmap, addr, &sb);
	expect_value(__wrap_munmap, length, 10);
	will_return(__wrap_munmap, 0);

	ret = ubbd_close_kring(&kring_info);
	assert_int_equal(ret, 0);
}


void test_close_shm(void **state)
{
	struct ubbd_kring_info kring_info = { 0 };
	int ret;

	// munmap failed
	kring_info.map = (void *)1;
	kring_info.kring_map_size = 10;
	kring_info.fd = 1;

	expect_value(__wrap_munmap, addr, 1);
	expect_value(__wrap_munmap, length, 10);
	will_return(__wrap_munmap, -1);

	expect_value(__wrap_close, fd, 1);
	will_return(__wrap_close, 0);

	ret = ubbd_close_kring(&kring_info);
	assert_int_equal(ret, -1);

	// close failed
	kring_info.map = (void *)1;
	expect_value(__wrap_munmap, addr, 1);
	expect_value(__wrap_munmap, length, 10);
	will_return(__wrap_munmap, 0);

	expect_value(__wrap_close, fd, 1);
	will_return(__wrap_close, -2);

	ret = ubbd_close_kring(&kring_info);
	assert_int_equal(ret, -2);

	// both munmap and close failed
	kring_info.map = (void *)1;
	expect_value(__wrap_munmap, addr, 1);
	expect_value(__wrap_munmap, length, 10);
	will_return(__wrap_munmap, -1);

	expect_value(__wrap_close, fd, 1);
	will_return(__wrap_close, -2);

	// expect return the first err retval
	ret = ubbd_close_kring(&kring_info);
	assert_int_equal(ret, -1);

	// close ok
	kring_info.map = (void *)1;
	expect_value(__wrap_munmap, addr, 1);
	expect_value(__wrap_munmap, length, 10);
	will_return(__wrap_munmap, 0);

	expect_value(__wrap_close, fd, 1);
	will_return(__wrap_close, 0);

	ret = ubbd_close_kring(&kring_info);
	assert_int_equal(ret, 0);
}

void test_processing_start(void **state)
{
	struct ubbd_kring_info kring_info = { 0 };
	int ret;

	kring_info.fd = 1;

	// read eagain
	expect_value(__wrap_read, fd, 1);
	expect_value(__wrap_read, count, 4);
	will_return(__wrap_read, -1);
	errno = EAGAIN;

	ret = ubbd_processing_start(&kring_info);
	assert_int_equal(ret, 0);
	// read ioerror
	expect_value(__wrap_read, fd, 1);
	expect_value(__wrap_read, count, 4);
	will_return(__wrap_read, -1);
	errno = EIO;

	ret = ubbd_processing_start(&kring_info);
	assert_int_equal(ret, -EIO);
	// read ok
	expect_value(__wrap_read, fd, 1);
	expect_value(__wrap_read, count, 4);
	will_return(__wrap_read, 0);

	ret = ubbd_processing_start(&kring_info);
	assert_int_equal(ret, 0);
}

void test_processing_complete(void **state)
{
	struct ubbd_kring_info kring_info = { 0 };
	int ret;

	kring_info.fd = 1;

	// write eagain
	expect_value(__wrap_write, fd, 1);
	expect_value(__wrap_write, count, 4);
	will_return(__wrap_write, -1);
	errno = EAGAIN;

	ret = ubbd_processing_complete(&kring_info);
	assert_int_equal(ret, 0);

	// write ioerror
	expect_value(__wrap_write, fd, 1);
	expect_value(__wrap_write, count, 4);
	will_return(__wrap_write, -1);
	errno = EIO;

	ret = ubbd_processing_complete(&kring_info);
	assert_int_equal(ret, -EIO);
	// write ok
	expect_value(__wrap_write, fd, 1);
	expect_value(__wrap_write, count, 4);
	will_return(__wrap_write, 0);

	ret = ubbd_processing_complete(&kring_info);
	assert_int_equal(ret, 0);
}

void test_cmd_se(void **state)
{
	struct ubbd_queue ubbd_q = { 0 };
	struct ubbd_sb sb = { 0 };
	struct ubbd_se *cmd_head, *to_handle;

	// get cmd_head
	sb.cmdr_off = 1;
	sb.cmd_head = 10;
	ubbd_q.kring_info.map = &sb;

	cmd_head = ubbd_cmd_head(&ubbd_q.kring_info);
	assert_ptr_equal(cmd_head, ((char *)&sb) + 11);

	// get to_handle
	sb.cmdr_off = 1;
	sb.cmd_head = 10;
	ubbd_q.se_to_handle = 8;
	ubbd_q.kring_info.map = &sb;

	to_handle = ubbd_cmd_to_handle(&ubbd_q);
	assert_ptr_equal(to_handle, ((char *)&sb) + 9);
}

int main(int argc, char **argv){

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_get_dev_info),
		cmocka_unit_test(test_open_shm),
		cmocka_unit_test(test_close_shm),
		cmocka_unit_test(test_processing_start),
		cmocka_unit_test(test_processing_complete),
		cmocka_unit_test(test_cmd_se),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
