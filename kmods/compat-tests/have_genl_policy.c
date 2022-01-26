#include <net/genetlink.h>

int main(void)
{
	static struct nla_policy ubbd_attr_policy[1];
	static struct genl_family ubbd_genl_family = {
		.policy = ubbd_attr_policy
	};

	return 0;
}
