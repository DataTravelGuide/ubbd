#define _GNU_SOURCE
#include "utils.h"
#include "ubbd_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h> 
#include <dirent.h>


int execute(char* program, char** arg_list)
{
	pid_t pid;
	int status;

  	pid = fork();

	switch(pid) {
	case 0:
		/* child */
		execvp(program, arg_list);
		ubbd_err("error execing %s : %s\n", program, strerror(errno));
		exit(-1);
	case -1:
		ubbd_err("fork failed: %s\n", strerror(errno));
		return -1;
	default:
		/* parent */
		ubbd_info("start process %d to execute %s\n", pid, program);
		wait(&status);
		ubbd_info("status of child is : %d\n", status);
	}

	return 0;
}

int ubbd_util_get_file_size(const char *filepath, uint64_t *file_size)
{
	int fd;
	off_t len;

	fd = open(filepath, O_RDWR | O_DIRECT);
	if (fd < 0) {
		ubbd_err("failed to open filepath: %s: %d\n", filepath, fd);
		return fd;
	}

	len = lseek(fd, 0, SEEK_END);
	if (len < 0) {
		ubbd_err("failed to get size of file: %ld.", len);
		close(fd);
		return len;
	}
	close(fd);

	*file_size = len;

	return 0;
}

int ubbd_load_module(char *mod_name)
{
	char *arg_list[] = {
		"modprobe",
		"ubbd",
		NULL
	};

	return execute("modprobe", arg_list);
}


int ubbd_mkdir(const char *path)
{
	DIR *dir;

	dir = opendir(path);
	if (dir) {
		closedir(dir);
	} else if (errno == ENOENT) {
		if (mkdir(path, 0755) == -1) {
			ubbd_err("mkdir(%s) failed: %m\n", path);
			return -errno;
		}
	} else {
		ubbd_err("opendir(%s) failed: %m\n", path);
		return -errno;
	}

	return 0;
}

int ubbd_mkdirs(const char *pathname)
{
	char path[PATH_MAX], *ch;
	int ind = 0, ret;

	strncpy(path, pathname, PATH_MAX);

	if (path[0] == '/')
		ind++;

	do {
		ch = strchr(path + ind, '/');
		if (!ch)
			break;

		*ch = '\0';

		ret = ubbd_mkdir(path);
		if (ret)
			return ret;

		*ch = '/';
		ind = ch - path + 1;
	} while (1);

	return ubbd_mkdir(path);
}

int ubbd_rmdir(const char *path)
{
	int ret;

	ret = rmdir(path);
	if (ret < 0) {
		if (errno == ENOENT) {
			ret = 0;
		} else {
			ubbd_err("failed to rmdir %s: %d\n", path, errno);
			ret = -errno;
		}
	}

	return ret;
}

int ubbd_rmdirs(const char *pathname, const char *remain)
{
	char path[PATH_MAX], *ch;
	int ret;

	strncpy(path, pathname, PATH_MAX);

	do {
		ret = ubbd_rmdir(path);
		if (ret < 0) {
			break;
		}

		ch = strrchr(path, '/');
		if (!ch)
			break;

		*ch = '\0';
		if (!strcmp(path, remain)) {
			ret = 0;
			break;
		}
	} while (1);

	return ret;
}
