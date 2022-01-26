/*
 * This module is mostly taken from tcmu-runner.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>

#include "ubbd_log.h"
#include "ubbd_dev.h"

#define LOG_ENTRY_LEN 256
#define LOG_MSG_LEN (LOG_ENTRY_LEN - 1)
#define LOG_ENTRYS (1024 * 32)

#define UBBD_LOG_FILENAME_MAX	32
#define UBBD_LOG_FILENAME	"ubbdd.log"

typedef int (*log_output_fn_t)(int priority, const char *timestamp,
			       const char *str, void *data);
typedef void (*log_close_fn_t)(void *data);

struct log_output {
	log_output_fn_t output_fn;
	log_close_fn_t close_fn;
	int priority;
	void *data;
};

struct log_buf {
	pthread_cond_t cond;
	pthread_mutex_t lock;

	bool thread_active;

	unsigned int head;
	unsigned int tail;
	char buf[LOG_ENTRYS][LOG_ENTRY_LEN];
	struct log_output *file_out;
	pthread_mutex_t file_out_lock;
	pthread_t thread_id;
};

static int ubbd_log_level = UBBD_LOG_INFO;
static struct log_buf *ubbd_logbuf;

static char *ubbd_log_dir;
static pthread_mutex_t ubbd_log_dir_lock = PTHREAD_MUTEX_INITIALIZER;


/* get the log level of ubbd-runner */
unsigned int ubbd_get_log_level(void)
{
	return ubbd_log_level;
}

static const char *loglevel_string(int priority)
{
	switch (priority) {
	case UBBD_LOG_ERROR:
		return "ERROR";
	case UBBD_LOG_INFO:
		return "INFO";
	case UBBD_LOG_DEBUG:
		return "DEBUG";
	}
	return "UNKONWN";
}

void ubbd_set_log_level(int level)
{
	if (ubbd_log_level == level) {
		ubbd_dbg("No changes to current log_level: %s, skipping it.\n",
		         loglevel_string(level));
		return;
	}
	if (level > UBBD_LOG_LEVEL_MAX)
		level = UBBD_LOG_LEVEL_MAX;
	else if (level < UBBD_LOG_LEVEL_MIN)
		level = UBBD_LOG_LEVEL_MIN;

	ubbd_info("log level now is %s\n", loglevel_string(level));
	ubbd_log_level = level;
}

static void log_cleanup_output(struct log_output *output)
{
	if (output->close_fn != NULL)
		output->close_fn(output->data);
	free(output);
}

static void ubbd_log_dir_free(void)
{
	if (ubbd_log_dir) {
		free(ubbd_log_dir);
		ubbd_log_dir = NULL;
	}
}

static void log_cleanup(void *arg)
{
	struct log_buf *logbuf = arg;

	pthread_cond_destroy(&logbuf->cond);
	pthread_mutex_destroy(&logbuf->lock);
	pthread_mutex_destroy(&logbuf->file_out_lock);

	if (logbuf->file_out)
		log_cleanup_output(logbuf->file_out);

	free(logbuf);
	ubbd_log_dir_free();
}

static void log_output(struct log_buf *logbuf, int pri, const char *msg,
		       struct log_output *output)
{
	char timestamp[UBBD_TIME_STRING_BUFLEN] = {0, };

	if (!output)
		return;

	if (time_string_now(timestamp) < 0)
		return;

	output->output_fn(pri, timestamp, msg, output->data);
}

static void cleanup_file_out_lock(void *arg)
{
	struct log_buf *logbuf = arg;

	pthread_mutex_unlock(&logbuf->file_out_lock);
}

static void
log_internal(int pri, struct ubbd_device *dev, const char *funcname,
	     int linenr, const char *fmt, va_list args)
{
	char buf[LOG_MSG_LEN];
	int n;

	if (pri > ubbd_log_level)
		return;

	if (!fmt)
		return;

	if (!ubbd_logbuf) {
		/* handle early log calls by config and deamon setup */
		vfprintf(stderr, fmt, args);
		return;
	}

	/* Format the log msg */
	if (dev) {
		n = sprintf(buf, "%s:%d %s: ", funcname, linenr,
		            dev->dev_name);
	} else {
		n = sprintf(buf, "%s:%d: ", funcname, linenr);
	}

	vsnprintf(buf + n, LOG_MSG_LEN - n, fmt, args);
	pthread_cleanup_push(cleanup_file_out_lock, ubbd_logbuf);
	pthread_mutex_lock(&ubbd_logbuf->file_out_lock);

	log_output(ubbd_logbuf, pri, buf, ubbd_logbuf->file_out);

	pthread_mutex_unlock(&ubbd_logbuf->file_out_lock);
	pthread_cleanup_pop(0);
}

void ubbd_err_message(struct ubbd_device *dev, const char *funcname,
		      int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(UBBD_LOG_ERROR, dev, funcname, linenr, fmt, args);
	va_end(args);
}

void ubbd_info_message(struct ubbd_device *dev, const char *funcname,
		       int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(UBBD_LOG_INFO, dev, funcname, linenr, fmt, args);
	va_end(args);
}

void ubbd_dbg_message(struct ubbd_device *dev, const char *funcname,
		      int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(UBBD_LOG_DEBUG, dev, funcname, linenr, fmt, args);
	va_end(args);
}

static struct log_output *
create_output(log_output_fn_t output_fn, log_close_fn_t close_fn, void *data,
	      int pri)
{
	struct log_output *output;

	output = calloc(1, sizeof(*output));
	if (!output)
		return NULL;

	output->output_fn = output_fn;
	output->close_fn = close_fn;
	output->data = data;
	output->priority = pri;

	return output;
}

static void close_fd(void *data)
{
	int fd = (intptr_t) data;
	close(fd);
}

static int output_to_fd(int pri, const char *timestamp,
                        const char *str,void *data)
{
	int fd = (intptr_t) data;
	char *buf, *msg;
	int count, ret, written = 0, r, pid = 0;

	if (fd == -1)
		return -1;

	pid = getpid();
	if (pid <= 0)
		return -1;

	/*
	 * format: timestamp pid [loglevel] msg
	 */
	ret = asprintf(&msg, "%s %d [%s] %s", timestamp, pid,
		       loglevel_string(pri), str);
	if (ret < 0)
		return -1;

	buf = msg;

	/* safe write */
	count = strlen(buf);
	while (count > 0) {
		r = write(fd, buf, count);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0) {
			written = r;
			goto out;
		}
		if (r == 0)
			break;
		buf = (char *) buf + r;
		count -= r;
		written += r;
	}
out:
	free(msg);
	return written;
}

static int create_file_output(struct log_buf *logbuf, int pri,
			      const char *filename)
{
	char log_file_path[PATH_MAX];
	struct log_output *output;
	int fd, ret;

	ret = ubbd_make_absolute_logfile(log_file_path, filename);
	if (ret < 0) {
		ubbd_err("ubbd_make_absolute_logfile failed\n");
		return ret;
	}

	ubbd_dbg("Attempting to use '%s' as the log file path\n", log_file_path);

	fd = open(log_file_path, O_CREAT | O_APPEND | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		ubbd_err("Failed to open %s:%m\n", log_file_path);
		return fd;
	}

	output = create_output(output_to_fd, close_fd, (void *)(intptr_t) fd,
			       pri);
	if (!output) {
		close(fd);
		ubbd_err("Failed to create output file: %s\n", log_file_path);
		return -ENOMEM;
	}

	pthread_cleanup_push(cleanup_file_out_lock, logbuf);
	pthread_mutex_lock(&logbuf->file_out_lock);

	if (logbuf->file_out) {
		log_cleanup_output(logbuf->file_out);
	}
	logbuf->file_out = output;

	pthread_mutex_unlock(&logbuf->file_out_lock);
	pthread_cleanup_pop(0);

	ubbd_info("log file path now is '%s'\n", log_file_path);
	return 0;
}

static void *log_thread_start(void *arg)
{
	pthread_cleanup_push(log_cleanup, arg);

	while (1) {
		pthread_mutex_lock(&ubbd_logbuf->lock);
		pthread_cond_wait(&ubbd_logbuf->cond, &ubbd_logbuf->lock);
		ubbd_logbuf->thread_active = true;
		pthread_mutex_unlock(&ubbd_logbuf->lock);
	}

	pthread_cleanup_pop(1);
	return NULL;
}

static bool ubbd_log_dir_check(const char *path)
{
	if (!path)
		return false;

	if (strlen(path) >= PATH_MAX - UBBD_LOG_FILENAME_MAX) {
		ubbd_err("The length of log dir path '%s' exceeds %d characters\n",
			 path, PATH_MAX - UBBD_LOG_FILENAME_MAX - 1);
		return false;
	}

	return true;
}

static int ubbd_log_dir_set(const char *log_dir)
{
	char *new_dir;

	new_dir = strdup(log_dir);
	if (!new_dir) {
		ubbd_err("Failed to copy log dir: %s\n", log_dir);
		return -ENOMEM;
	}

	ubbd_log_dir_free();
	ubbd_log_dir = new_dir;
	return 0;
}

static int ubbd_mkdir(const char *path)
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

static int ubbd_mkdirs(const char *pathname)
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

static void cleanup_log_dir_lock(void *arg)
{
	pthread_mutex_unlock(&ubbd_log_dir_lock);
}

static int ubbd_log_dir_create(const char *path)
{
	int ret = 0;

	if (!ubbd_log_dir_check(path))
		return -EINVAL;

	pthread_cleanup_push(cleanup_log_dir_lock, NULL);
	pthread_mutex_lock(&ubbd_log_dir_lock);
	if (ubbd_log_dir && !strcmp(path, ubbd_log_dir))
		goto unlock;

	ret = ubbd_mkdirs(path);
	if (ret)
		goto unlock;

	ret = ubbd_log_dir_set(path);
unlock:
	pthread_mutex_unlock(&ubbd_log_dir_lock);
	pthread_cleanup_pop(0);
	return ret;
}

int ubbd_make_absolute_logfile(char *path, const char *filename)
{
	int ret = 0;

	pthread_mutex_lock(&ubbd_log_dir_lock);
	if (!ubbd_log_dir) {
		ret = -EINVAL;
		goto unlock;
	}

	if (snprintf(path, PATH_MAX, "%s/%s", ubbd_log_dir, filename) < 0)
		ret = -EINVAL;
unlock:
	pthread_mutex_unlock(&ubbd_log_dir_lock);
	return ret;
}

int ubbd_setup_log(char *log_dir)
{
	struct log_buf *logbuf;
	int ret;

	ret = ubbd_log_dir_create(log_dir);
	if (ret) {
		ubbd_err("Could not setup log dir %s. Error %d.\n", log_dir,
			  ret);
		return ret;
	}

	logbuf = calloc(1, sizeof(struct log_buf));
	if (!logbuf)
		goto free_log_dir;

	logbuf->thread_active = false;
	logbuf->head = 0;
	logbuf->tail = 0;
	pthread_cond_init(&logbuf->cond, NULL);
	pthread_mutex_init(&logbuf->lock, NULL);
	pthread_mutex_init(&logbuf->file_out_lock, NULL);

	ret = create_file_output(logbuf, UBBD_LOG_DEBUG,
				 UBBD_LOG_FILENAME);
	if (ret < 0)
		ubbd_err("create file output error \n");

	ubbd_logbuf = logbuf;
	ret = pthread_create(&logbuf->thread_id, NULL, log_thread_start,
			     logbuf);
	if (ret) {
		ubbd_logbuf = NULL;
		log_cleanup(logbuf);
		return ret;
	}

	return 0;

free_log_dir:
	ubbd_log_dir_free();
	return -ENOMEM;
}

void ubbd_destroy_log()
{
	pthread_t thread;
	void *join_retval;

	thread = ubbd_logbuf->thread_id;
	if (pthread_cancel(thread))
		return;

	pthread_join(thread, &join_retval);
}

int time_string_now(char* buf)
{
	struct tm *tm;
	struct timeval tv;

	if (gettimeofday (&tv, NULL) < 0)
		return -1;

	/* The value maybe changed in multi-thread*/
	tm = localtime(&tv.tv_sec);
	if (tm == NULL)
		return -1;

	tm->tm_year += 1900;
	tm->tm_mon += 1;

	if (snprintf(buf, UBBD_TIME_STRING_BUFLEN,
	    "%4d-%02d-%02d %02d:%02d:%02d.%03d",
	    tm->tm_year, tm->tm_mon, tm->tm_mday,
	    tm->tm_hour, tm->tm_min, tm->tm_sec,
	    (int) (tv.tv_usec / 1000ull % 1000)) >= UBBD_TIME_STRING_BUFLEN)
		return ERANGE;

	return 0;
}
