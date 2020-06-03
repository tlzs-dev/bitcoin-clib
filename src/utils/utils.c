/*
 * utils.c
 * 
 * Copyright 2020 Che Hongwei <htc.chehw@gmail.com>
 * 
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person 
 * obtaining a copy of this software and associated documentation 
 * files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, 
 * publish, distribute, sublicense, and/or sell copies of the Software, 
 * and to permit persons to whom the Software is furnished to do so, 
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 *  in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR 
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#include <time.h>
#include <pthread.h>

#include <stdint.h>
#include "utils.h"
#include "crypto.h"

//~ static const char * s_hex_digits = "0123456789abcdef";
static const char s_hex_digits[256 * 2 + 1] = 
	"00" "01" "02" "03" "04" "05" "06" "07"    "08" "09" "0a" "0b" "0c" "0d" "0e" "0f" 
	"10" "11" "12" "13" "14" "15" "16" "17"    "18" "19" "1a" "1b" "1c" "1d" "1e" "1f" 
	"20" "21" "22" "23" "24" "25" "26" "27"    "28" "29" "2a" "2b" "2c" "2d" "2e" "2f" 
	"30" "31" "32" "33" "34" "35" "36" "37"    "38" "39" "3a" "3b" "3c" "3d" "3e" "3f" 
	"40" "41" "42" "43" "44" "45" "46" "47"    "48" "49" "4a" "4b" "4c" "4d" "4e" "4f" 
	"50" "51" "52" "53" "54" "55" "56" "57"    "58" "59" "5a" "5b" "5c" "5d" "5e" "5f" 
	"60" "61" "62" "63" "64" "65" "66" "67"    "68" "69" "6a" "6b" "6c" "6d" "6e" "6f" 
	"70" "71" "72" "73" "74" "75" "76" "77"    "78" "79" "7a" "7b" "7c" "7d" "7e" "7f" 
	"80" "81" "82" "83" "84" "85" "86" "87"    "88" "89" "8a" "8b" "8c" "8d" "8e" "8f" 
	"90" "91" "92" "93" "94" "95" "96" "97"    "98" "99" "9a" "9b" "9c" "9d" "9e" "9f" 
	"a0" "a1" "a2" "a3" "a4" "a5" "a6" "a7"    "a8" "a9" "aa" "ab" "ac" "ad" "ae" "af" 
	"b0" "b1" "b2" "b3" "b4" "b5" "b6" "b7"    "b8" "b9" "ba" "bb" "bc" "bd" "be" "bf" 
	"c0" "c1" "c2" "c3" "c4" "c5" "c6" "c7"    "c8" "c9" "ca" "cb" "cc" "cd" "ce" "cf" 
	"d0" "d1" "d2" "d3" "d4" "d5" "d6" "d7"    "d8" "d9" "da" "db" "dc" "dd" "de" "df" 
	"e0" "e1" "e2" "e3" "e4" "e5" "e6" "e7"    "e8" "e9" "ea" "eb" "ec" "ed" "ee" "ef" 
	"f0" "f1" "f2" "f3" "f4" "f5" "f6" "f7"    "f8" "f9" "fa" "fb" "fc" "fd" "fe" "ff" 
;

static const unsigned char s_hex_table[256] = { 
/* 0x00 */	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/* 0x10 */	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/* 0x20 */	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/* 0x30 */	   0,    1,    2,    3,    4,    5,    6,    7,        8,    9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/* 0x40 */	0xff,   10,   11,   12,   13,   14,   15, 0xff,     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/* 0x50 */	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/* 0x60 */	0xff,   10,   11,   12,   13,   14,   15, 0xff,     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/* 0x70 */	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,

/* 0x80 */	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/* 0x90 */	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/* 0xa0 */	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/* 0xb0 */	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/* 0xc0 */	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/* 0xd0 */	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/* 0xe0 */	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/* 0xf0 */	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};


ssize_t bin2hex(const void * data, size_t length, char ** p_hex)
{
	if(length == 0 || NULL == data) return 0;
	ssize_t size = length * 2;
	if(NULL == p_hex) return size + 1;
	const unsigned char * p = data;
	const unsigned char * p_end = p + length;
	
	char * hex = *p_hex;
	if(NULL == hex)
	{
		hex = malloc(size + 1);
		if(NULL == hex) return -1;
		*p_hex = hex;
	}
	
	char * dst = hex;
	for(; p < p_end; ++p)
	{
		int c = *p;
		dst[0] = s_hex_digits[c * 2];
		dst[1] = s_hex_digits[c * 2 + 1];
		dst += 2;
	}
	*dst = '\0';
	return size;
}

ssize_t hex2bin(const char * hex, size_t length, void ** p_data)
{
	if(NULL == hex) return 0;
	if(((ssize_t)length) <= 0) length = strlen(hex);
	if(length == 0) return 0;
	
	
	if(length % 2) return -1;
	ssize_t size = length / 2;
	
	if(NULL == p_data) return size;
	unsigned char * data = * p_data;
	if(NULL == data)
	{
		data = malloc(size);
		if(NULL == data) return -1;
	}
	
	for(size_t i = 0; i < size; ++i)
	{
		unsigned char hi = s_hex_table[(int)hex[i * 2]];
		unsigned char lo = s_hex_table[(int)hex[i * 2 + 1]];
		if(hi > 0x0F || lo > 0x0F) goto label_err;
		data[i] = (hi << 4) | lo;
	}

	*p_data = data;
	return size;
label_err:
	if(NULL == *p_data) free(data);
	return -1;
}

void dump2(FILE * fp, const void * data, ssize_t length)
{
	const unsigned char * p = data;
	const unsigned char * p_end = p + length;
	
#define BUF_SIZE (4096)
	
	global_lock();
	char buffer[BUF_SIZE * 2 + 1];
	char * p_buf = buffer;
	while(p < p_end)
	{
		memset(buffer, 0, sizeof(buffer));
		int len = (length > BUF_SIZE)?BUF_SIZE:length;
		int cb = bin2hex(p, len, &p_buf);
		assert(cb >= 0);
		fprintf(fp, "%*s", (int)cb, buffer);
		p += len;
		length -= len;
	}
	
	global_unlock();
#undef BUF_SIZE
	return;
}

void hash256(const void * data, size_t length, uint8_t hash[32])
{
	sha256_ctx_t sha[1];
	uint8_t hash32[32];
	sha256_init(sha);
	sha256_update(sha, data, length);
	sha256_final(sha, hash32);
	
	sha256_init(sha);
	sha256_update(sha, hash32, 32);
	sha256_final(sha, hash);
}

void hash160(const void * data, size_t length, uint8_t hash[20])
{
	sha256_ctx_t sha[1];
	ripemd160_ctx_t ripemd[1];
	uint8_t hash32[32];
	
	sha256_init(sha);
	sha256_update(sha, data, length);
	sha256_final(sha, hash32);
	
	ripemd160_init(ripemd);
	ripemd160_update(ripemd, hash32, 32);
	ripemd160_final(ripemd, hash);
}

int make_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	if(flags < 0) return -1;
	
	flags |= O_NONBLOCK;
	int rc = fcntl(fd, F_SETFL, flags);
	assert(0 == rc);
	return 0;
}

static pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;
void global_lock() 		{ pthread_mutex_lock(&s_mutex); }
void global_unlock() 	{ pthread_mutex_unlock(&s_mutex); }

static app_timer_t s_timer[1];
double app_timer_start(app_timer_t * timer)
{
	if(NULL == timer) timer = s_timer;
	struct timespec ts[1];
	clock_gettime(CLOCK_MONOTONIC, ts);
	
	timer->begin = (double)ts->tv_sec + (double)ts->tv_nsec / 1000000000;
	return timer->begin;
}
double app_timer_stop(app_timer_t * timer)
{
	if(NULL == timer) timer = s_timer;
	struct timespec ts[1];
	clock_gettime(CLOCK_MONOTONIC, ts);
	
	timer->end = (double)ts->tv_sec + (double)ts->tv_nsec / 1000000000;
	return (timer->end - timer->begin);
}
