/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef UTILS_H
#define UTILS_H
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define container_of(ptr, type, member) ({                      \
        const typeof(((type *)0)->member) *__mptr = (ptr);      \
        (type *)((char *)__mptr - offsetof(type, member));      \
})
#endif
