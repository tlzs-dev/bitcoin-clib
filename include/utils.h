#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

ssize_t bin2hex(const void * data, size_t length, char ** p_hex);
ssize_t hex2bin(const char * hex, size_t length, void ** p_data);
void dump2(FILE * fp, const void * data, ssize_t length);
#define dump(data, length) dump2(stdout, data, length)

void hash256(const void * data, size_t length, uint8_t hash[32]);
void hash160(const void * data, size_t length, uint8_t hash[20]);

int make_nonblock(int fd);
void global_lock();
void global_unlock();

typedef struct app_timer
{
	double begin;
	double end;
}app_timer_t;
double app_timer_start(app_timer_t * timer);
double app_timer_stop(app_timer_t * timer);

typedef char * string;
#define json_get_value(jobj, type, key) ({								\
		type value = (type)0;											\
		json_object * jvalue = NULL;									\
		json_bool ok = json_object_object_get_ex(jobj, #key, &jvalue);		\
		if(ok) { value = (type)json_object_get_##type(jvalue); }	\
		value;															\
	})


#ifdef __cplusplus
}
#endif
#endif
