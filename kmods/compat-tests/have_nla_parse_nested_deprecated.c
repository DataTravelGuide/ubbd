#include <net/genetlink.h>

int main(void)
{
        struct nlattr *config[1];
	struct nlattr attr;
        struct nla_policy policy;
	int ret;

        ret = nla_parse_nested_deprecated(NULL, 1,
                        NULL,
                        NULL, NULL);

        return 0;
}
