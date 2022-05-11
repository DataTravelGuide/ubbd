#include<stdlib.h>
#include<stdio.h>
#include<unistd.h>
#include<string.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "utils.h"


extern void *__real_calloc(size_t nmemb, size_t size);
void *__wrap_calloc(size_t nmemb, size_t size)
{
	void *data;

	if (size < 1024 * 1024 * 1024)
		return __real_calloc(nmemb, size);

	check_expected(nmemb);
	check_expected(size);

	data = mock_ptr_type(void *);
	
	return data;
}

extern void __real_free(void *ptr);
void __wrap_free(void *ptr)
{
	if (ptr != (void *)1)
		return __real_free(ptr);

	check_expected_ptr(ptr);
}

void test_context_alloc(void **state)
{
	struct context *ctx;
	size_t context_size = sizeof(struct context);
	size_t mem_off = 1024 * 1024 * 1024;

	// failed to alloc context
	expect_value(__wrap_calloc, nmemb, 1);
	expect_value(__wrap_calloc, size, context_size + mem_off);
	will_return(__wrap_calloc, NULL);

	ctx = context_alloc(mem_off);
	assert_null(ctx);

	// alloc a context
	expect_value(__wrap_calloc, nmemb, 1);
	expect_value(__wrap_calloc, size, context_size + mem_off + 10);
	will_return(__wrap_calloc, 1);

	ctx = context_alloc(mem_off + 10);
	assert_ptr_equal(ctx, 1);

	expect_value(__wrap_free, ptr, 1);
	context_free(ctx);
}

int main(int argc, char **argv){

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_context_alloc),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
