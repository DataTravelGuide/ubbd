#ifndef UBBD_LOG_H
#define UBBD_LOG_H
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>

#define UBBD_LOG_ERROR	0
#define UBBD_LOG_INFO	1
#define UBBD_LOG_DEBUG	2

#define UBBD_LOG_LEVEL_MIN	UBBD_LOG_ERROR
#define UBBD_LOG_LEVEL_MAX	UBBD_LOG_DEBUG

/* default ubbd log dir path */
# define UBBD_TIME_STRING_BUFLEN \
    (4 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 3 + 1)

/* generate localtime string into buf */
int time_string_now(char* buf);

void ubbd_set_log_level(int level);
unsigned int ubbd_get_log_level(void);
int ubbd_setup_log(char *log_dir, char *filename);
void ubbd_destroy_log(void);
int ubbd_make_absolute_logfile(char *path, const char *filename);

__attribute__ ((format (printf, 4, 5)))
void ubbd_err_message(void *dev, const char *funcname, int linenr, const char *fmt, ...);
__attribute__ ((format (printf, 4, 5)))
void ubbd_info_message(void *dev, const char *funcname, int linenr, const char *fmt, ...);
__attribute__ ((format (printf, 4, 5)))
void ubbd_dbg_message(void *dev, const char *funcname, int linenr, const char *fmt, ...);

#define ubbd_dev_err(dev, ...)  do { ubbd_err_message(dev, __func__, __LINE__, __VA_ARGS__);} while (0)
#define ubbd_dev_info(dev, ...) do { ubbd_info_message(dev, __func__, __LINE__, __VA_ARGS__);} while (0)
#define ubbd_dev_dbg(dev, ...)  do { ubbd_dbg_message(dev, __func__, __LINE__, __VA_ARGS__);} while (0)

#define ubbd_err(...)  do { ubbd_err_message(NULL, __func__, __LINE__, __VA_ARGS__);} while (0)
#define ubbd_info(...) do { ubbd_info_message(NULL, __func__, __LINE__, __VA_ARGS__);} while (0)
#define ubbd_dbg(...)  do { ubbd_dbg_message(NULL, __func__, __LINE__, __VA_ARGS__);} while (0)
#endif /* UBBD_LOG_H */
