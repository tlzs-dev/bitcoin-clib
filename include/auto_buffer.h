#ifndef _AUTO_BUFFER_H_
#define _AUTO_BUFFER_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct auto_buffer
{
	unsigned char * data;
	ssize_t size;
	ssize_t length;
	ssize_t start_pos;
	
	ssize_t (* write)(struct auto_buffer * buf, int fd, size_t length);
	ssize_t (* read)(struct auto_buffer * buf, int fd, size_t length);
	
	ssize_t (* fwrite)(struct auto_buffer * buf, FILE * fp, size_t length);
	ssize_t (* fread)(struct auto_buffer * buf, FILE * fp, size_t length);
	
	int (* resize)(struct auto_buffer * buf, ssize_t new_size);
	int (* push_data)(struct auto_buffer * buf, const unsigned char * data, size_t length);
	ssize_t (* pop_data)(struct auto_buffer * buf, unsigned char ** p_dst, size_t length);
	int (* trim)(struct auto_buffer * buf);
}auto_buffer_t;
auto_buffer_t * auto_buffer_init(auto_buffer_t * buf, int size);
void auto_buffer_cleanup(auto_buffer_t * buf);

#ifdef __cplusplus
}
#endif
#endif
