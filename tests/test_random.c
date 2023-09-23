#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include "pthread.h"
#include <string.h>
#include "errno.h"
#include <time.h>

#define USKIPLIST_MAXLEVEL              8
#define USKIPLIST_P	0.25
#define THREAD_NUM	10

static int usl_random_level(void) {
    int level = 1;

    while ((random()&0xFFFF) < (USKIPLIST_P * 0xFFFF))
        level += 1;

    return (level < USKIPLIST_MAXLEVEL) ? level : USKIPLIST_MAXLEVEL;
}

uint64_t u64_random_data[256] = {
	0x101010001       , 0x1               , 0x10100000000     , 0x101010000010001 ,
       	0x100000000000000 , 0x1               , 0x100010000000000 , 0x1000101000000   ,
	0x100000000       , 0x100000000000000 , 0x101010101000100 , 0x100010000000000 ,
	0x100000000000101 , 0x0               , 0x0               , 0x10000000100     ,
	0x100000101010000 , 0x1010100000000   , 0x1000000000000   , 0x1000100000000   ,
	0x1000000000000   , 0x101000001010000 , 0x1010001         , 0x100000101010001 ,
	0x10000000001     , 0x10000000000     , 0x0               , 0x10000           ,
	0x100             , 0x0               , 0x10000           , 0x1000000000000   ,
	0x1000001000000   , 0x1000000010100   , 0x101000000       , 0x101000000000001 ,
	0x100             , 0x1000000         , 0x10000010100     , 0x10000000000     ,
	0x0               , 0x0               , 0x10000010001     , 0x1               ,
	0x100000000010000 , 0x100010001       , 0x100000000000000 , 0x0               ,
	0x101010100000000 , 0x101000000       , 0x100000000010000 , 0x100             ,
	0x100010001000000 , 0x10000           , 0x100010001000100 , 0x10100000000     ,
	0x10001           , 0x10001000000     , 0x0               , 0x101000000000000 ,
	0x101010001       , 0x100000000000001 , 0x100010000000000 , 0x0               ,
	0x100010100       , 0x100000000010000 , 0x1000000         , 0x1               ,
	0x100000000000000 , 0x100000000010100 , 0x1000000         , 0x1000100010100   ,
	0x1000100000000   , 0x100000000       , 0x1               , 0x101000000010100 ,
	0x100000101       , 0x10000           , 0x100000001000101 , 0x1000100         ,
	0x0               , 0x101010000       , 0x10000010100     , 0x100000101       ,
	0x100000000000100 , 0x1               , 0x10001000000     , 0x1000000010000   ,
	0x100000000000001 , 0x10101           , 0x10000000001     , 0x100000000000000 ,
	0x1000000         , 0x1               , 0x10001000000     , 0x10100010101     ,
	0x1000100000000   , 0x100             , 0x101000000000000 , 0x1               ,
	0x101000001010100 , 0x10000000101     , 0x100000000       , 0x0               ,
	0x1000100         , 0x1000000         , 0x100000001       , 0x101010000000001 ,
	0x1               , 0x10100000100     , 0x100010000000000 , 0x100000000010001 ,
	0x101010000000101 , 0x10000           , 0x100000000000000 , 0x101010001       ,
	0x10001010100     , 0x1000000010000   , 0x100000101000001 , 0x1000000         ,
	0x10000000000     , 0x10101           , 0x10000000000     , 0x1               ,
	0x10000000000     , 0x1               , 0x10000000000     , 0x1000100         ,
};

uint8_t *u8_random_data = u64_random_data;

int new_usl_random_level(uint64_t i)
{
	int l;

	for (l = 1; l < USKIPLIST_MAXLEVEL; l++) {
		if (u8_random_data[i % 1024] == 1) {
			i = i * 0.618;
		} else {
			break;
		}
	}

	return l;
}

int main() {
	uint64_t i;
	int level;

	for (i = 0; i < 10240000; i++) {
		//level = new_usl_random_level(i);
		level = usl_random_level();
		level++;
	}
}
