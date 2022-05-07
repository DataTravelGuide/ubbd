#include <net/genetlink.h>

int main(void)
{
	struct genl_ops ops = {
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	};

	return 0;
}
