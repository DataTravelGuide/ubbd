#include "utils.h"
#include "ubbd_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h> 


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
