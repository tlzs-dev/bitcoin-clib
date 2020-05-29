#ifndef _SATOSHI_SCRIPT_H_
#define _SATOSHI_SCRIPT_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <pthread.h>

#include <stdint.h>
#include <stdbool.h>

enum script_data_type
{
	script_data_type_unknown,
	script_data_type_bool,
	script_data_type_op_code,
	script_data_type_varint,
	script_data_type_varstr,
	script_data_type_uint8,
	script_data_type_uint16,
	script_data_type_uint32,
	script_data_type_uint64,
	script_data_type_hash256,
	script_data_type_hash160,
	script_data_type_uchars,	// array, no-free
	script_data_type_pointer,	// need free
};


typedef struct script_data
{
	enum script_data_type type;
	union
	{
		bool b;
		uint64_t u64;
		unsigned char * data;
		unsigned char h256[32];
		unsigned char h160[20];
	};
	size_t size;
	
}script_data_t;


typedef struct stack_node
{
	script_data_t data[1];
	struct stack_node * next;
}stack_node_t;

typedef struct satoshi_script_stack
{
	stack_node_t * top;
	ssize_t count;
}satoshi_script_stack_t;

stack_node_t * stack_node_new(const stack_node_t * data, size_t size, int copy_memory);
void stack_node_free(stack_node_t * node);

typedef struct script_stack
{
	stack_node_t * top;
	ssize_t count;
	pthread_mutex_t mutex;
}script_stack_t;

script_stack_t * script_stack_init(script_stack_t * stack);
void script_stack_cleanup(script_stack_t * stack);

int script_stack_push(script_stack_t * stack, const void * data, size_t size);
stack_node_t * script_stack_pop(script_stack_t * stack);
const stack_node_t * script_stack_peek(script_stack_t * stack);


int satoshi_script_parse(const unsigned char * script_varstr, const unsigned char * p_end,
	script_stack_t * op_stack, script_stack_t * params_stack, script_stack_t * alt_stack
);

int satoshi_script_eval(script_stack_t * op_stack, script_stack_t * params_stack, script_stack_t * alt_stack);
int satoshi_script_add(const unsigned char op_code, ...);

#ifdef __cplusplus
}
#endif
#endif
