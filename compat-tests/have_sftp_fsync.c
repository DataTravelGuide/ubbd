#include <libssh/sftp.h>

int main(void)
{
	struct sftp_file_struct file;

	sftp_fsync(&file);

	return 0;
}
