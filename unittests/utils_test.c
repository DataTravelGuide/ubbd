#include<stdlib.h>
#include<stdio.h>
#include<unistd.h>
#include<string.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "utils.h"

void *__wrap_calloc(size_t nmemb, size_t size)
{
	void *data;

	check_expected(nmemb);
	check_expected(size);

	data = mock_ptr_type(void *);
	
	return data;
}


void __wrap_free(void *ptr)
{
	check_expected_ptr(ptr);
}

void test_context_alloc(void **state)
{
	struct context *ctx;
	size_t context_size = sizeof(struct context);

	// failed to alloc context
	expect_value(__wrap_calloc, nmemb, 1);
	expect_value(__wrap_calloc, size, context_size);
	will_return(__wrap_calloc, NULL);

	ctx = context_alloc(0);
	assert_null(ctx);

	// alloc a context
	expect_value(__wrap_calloc, nmemb, 1);
	expect_value(__wrap_calloc, size, context_size + 10);
	will_return(__wrap_calloc, 1);

	ctx = context_alloc(10);
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
