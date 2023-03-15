#include <rbd/librbd.h>

int main(void)
{
	rbd_quiesce_complete(NULL, 0, 0);

	return 0;
}
