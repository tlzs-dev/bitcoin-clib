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
#define dump_line(prefix, data, length) do { printf("%s", prefix); dump(data, length); printf("\n"); } while(0)

void hash256(const void * data, size_t length, uint8_t hash[static 32]);
void hash160(const void * data, size_t length, uint8_t hash[static 20]);

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

#ifdef _DEBUG
#define debug_printf(fmt, ...) do {	\
		fprintf(stderr, "\e[33m" "%s@%d::%s(): " fmt " \e[39m\n",	\
			__FILE__, __LINE__, __FUNCTION__,						\
			##__VA_ARGS__);											\
	} while(0)
	
#define debug_dump_line(prefix, data, length) do {				\
		fprintf(stderr, "\e[33m" "%s", prefix); 				\
		dump2(stderr, data, length); 							\
		fprintf(stderr, "\e[39m\n");							\
	} while(0)
#else
#define debug_printf(fmt, ...) do { } while(0)
#define debug_dump_line(prefix, data, length) do { } while(0)
#endif

#ifdef __cplusplus
}
#endif
#endif
