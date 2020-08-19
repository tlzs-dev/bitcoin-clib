/*
 * auto_buffer.c
 * 
 * Copyright 2020 Che Hongwei <htc.chehw@gmail.com>
 * 
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"), to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
 * copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
 * IN THE SOFTWARE.
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <unistd.h>

#include "auto_buffer.h"
static ssize_t auto_buffer_write(struct auto_buffer * buf, int fd, size_t length);
static ssize_t auto_buffer_read(struct auto_buffer * buf, int fd, size_t length);
static ssize_t auto_buffer_fwrite(struct auto_buffer * buf, FILE * fp, size_t length);
static ssize_t auto_buffer_fread(struct auto_buffer * buf, FILE * fp, size_t length);
static int auto_buffer_push_data(struct auto_buffer * buf, const unsigned char * data, size_t length);
static ssize_t auto_buffer_pop_data(struct auto_buffer * buf, unsigned char ** p_dst, size_t length);
static int auto_buffer_trim(struct auto_buffer * buf);
static int auto_buffer_resize(struct auto_buffer * buf, ssize_t new_size);

auto_buffer_t * auto_buffer_init(auto_buffer_t * buf, int size)
{
	if(NULL == buf) buf = calloc(1, sizeof(*buf));
	assert(buf);
	
	buf->write = auto_buffer_write;
	buf->read = auto_buffer_read;
	buf->fwrite = auto_buffer_fwrite;
	buf->fread = auto_buffer_fread;
	buf->push_data = auto_buffer_push_data;
	buf->pop_data = auto_buffer_pop_data;
	buf->trim = auto_buffer_trim;
	buf->resize = auto_buffer_resize;

	return buf;
}
void auto_buffer_cleanup(auto_buffer_t * buf)
{
	if(NULL == buf) return;
	free(buf->data);
	buf->data = NULL;
	buf->size = 0;
	buf->length = 0;
	buf->start_pos = 0;
	return;
}



#define AUTO_BUFFER_ALLOC_SIZE	(65536)

static ssize_t auto_buffer_write(struct auto_buffer * buf, int fd, size_t length)
{
	ssize_t cb = -1;
	ssize_t cb_total = 0;
	if(length == 0 || length > buf->length) length = buf->length;
	if(length == 0) return 0;
	
	unsigned char * p = buf->data + buf->start_pos;
	while(length)
	{
		cb = write(fd, p, length);
		if(cb <= 0) break;
		length -= cb;
		p += cb;
		cb_total += cb;
	}
	
	if(cb <= 0) {	// async write (non-block mode)
		if(cb == 0 || errno != EWOULDBLOCK) {
			perror("auto_buffer_write()");
			return -1;	
		}
	}
	buf->length -= cb_total;
	buf->start_pos += cb_total;
	
	if(buf->length == 0) auto_buffer_trim(buf);
	return cb_total;
}
static ssize_t auto_buffer_read(struct auto_buffer * buf, int fd, size_t length)
{
	ssize_t cb = -1;
	ssize_t cb_total = 0;
	
	if(length == 0) length = AUTO_BUFFER_ALLOC_SIZE;
	int rc = auto_buffer_resize(buf, buf->length + length);
	assert(0 == rc);
	
	unsigned char * p = buf->data + buf->start_pos + buf->length;
	while(length)
	{
		cb = read(fd, p, length);
		if(cb <= 0) break;
		
		length -= cb;
		cb_total += cb;
		p += cb;
	}
	
	if(cb <= 0) {	// async read (non-block mode)
		if(cb == 0 || errno != EWOULDBLOCK) {
			perror("auto_buffer_read()");
			return -1;	
		}
	}
	
	buf->length += cb_total;
	return cb_total;
}

static ssize_t auto_buffer_fwrite(struct auto_buffer * buf, FILE * fp, size_t length)
{
	assert(fp);
	if(NULL == buf || NULL == buf->data || 0 == buf->length) return 0;
	
	ssize_t cb_total = -1;
	if(length == 0 || length > buf->length) length = buf->length;
	
	unsigned char * p = buf->data + buf->start_pos;
	cb_total = fwrite(p, 1, length, fp);
	if(cb_total != length) {
		perror("auto_buffer_fwrite()");
		return -1;
	}
	
	buf->length -= cb_total;
	buf->start_pos += cb_total;
	
	if(buf->length == 0) auto_buffer_trim(buf);
	return cb_total;
}

static ssize_t auto_buffer_fread(struct auto_buffer * buf, FILE * fp, size_t length)
{
	assert(fp && buf);
	if(length == 0) length = AUTO_BUFFER_ALLOC_SIZE;
	
	ssize_t cb_total = -1;
	int rc = auto_buffer_resize(buf, buf->length + length);
	assert(0 == rc);
	
	unsigned char * p = buf->data + buf->start_pos + buf->length;
	cb_total = fread(p, 1, length, fp);
	if(cb_total != length) {
		perror("auto_buffer_fread()");
		return -1;
	}
	
	buf->length += cb_total;
	return cb_total;
}

static int auto_buffer_push_data(struct auto_buffer * buf, const unsigned char * data, size_t length)
{
	assert(data && length);
	int rc = auto_buffer_resize(buf, buf->length + length);
	assert(0 == rc);
	
	unsigned char * p = buf->data + buf->start_pos + buf->length;
	memcpy(p, data, length);
	buf->length += length;
	return 0;
}

static ssize_t auto_buffer_pop_data(struct auto_buffer * buf, unsigned char ** p_dst, size_t length)
{
	assert(p_dst);
	if(length == 0 || length > buf->length) length = buf->length;
	if(0 == length || NULL == buf || NULL == buf->data) return 0;
	
	unsigned char * src = buf->data + buf->start_pos;
	unsigned char * dst = *p_dst; 
	if(NULL == dst) dst = malloc(length);
	memcpy(dst, src, length);
	
	buf->start_pos += length;
	buf->length -= length;
	if(0 == buf->length) auto_buffer_trim(buf);
	
	return length;
}

static int auto_buffer_trim(struct auto_buffer * buf)
{
	if(buf->length == 0) buf->start_pos = 0;
	if(buf->start_pos > 0) {
		void * data = memmove(buf->data, buf->data + buf->start_pos, buf->length);
		assert(data == buf->data);
		if(data != buf->data) return -1;
	}
	return 0;
}

static int auto_buffer_resize(struct auto_buffer * buf, ssize_t new_size)
{
	if(new_size <= 0) new_size = AUTO_BUFFER_ALLOC_SIZE;
	else new_size = (new_size + AUTO_BUFFER_ALLOC_SIZE - 1) / AUTO_BUFFER_ALLOC_SIZE * AUTO_BUFFER_ALLOC_SIZE;
	if(new_size <= buf->size) return 0;
	
	unsigned char * data = realloc(buf->data, new_size);
	assert(data);
	if(NULL == data) return -1;
	
	buf->data = data;
	buf->size = new_size;
	return 0;
}
