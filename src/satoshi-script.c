/*
 * satoshi-script.c
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

#include "satoshi-script.h"
#include "satoshi-types.h"
#include "utils.h"

#include "blockchain.h"
#include "crypto.h"

/*******************************************************
 * satoshi_script_data
 *******************************************************/
ssize_t satoshi_script_data_set(satoshi_script_data_t * sdata, enum satoshi_script_data_type type, const void * data, size_t size)
{
	assert(type != satoshi_script_data_type_unknown);
	assert(sdata);
	
	sdata->type = type;
	if(type == satoshi_script_data_type_null) return 0;
	
	assert(data);
	size_t vint_size = 0;
	const unsigned char * p = data;
	
	ssize_t payload_size = 0;
	
	switch(type)
	{
	case satoshi_script_data_type_bool:
	case satoshi_script_data_type_op_code:
		sdata->b = *(uint8_t *)data;
		payload_size = 1;
		break;
	case satoshi_script_data_type_varint:
		vint_size = varint_size((varint_t *)p);
		assert(vint_size > 0);
		sdata->u64 = varint_get((varint_t *)p);
		sdata->size = 0;
		break;
	case satoshi_script_data_type_varstr:
		vint_size = varint_size((varint_t *)p);
		assert(vint_size > 0);
		sdata->size = varint_get((varint_t *)p);
		p += vint_size;
		payload_size = vint_size + sdata->size;
		if(size > 0) assert(payload_size <= size);
		
		if(sdata->size > 0)
		{
			sdata->data = malloc(sdata->size);
			assert(sdata->data);
			memcpy(sdata->data, p, sdata->size);
		}
		break;
	case satoshi_script_data_type_uint8:
		payload_size = sizeof(uint8_t);
		sdata->u64 = *(uint8_t *)data;
		sdata->size = 0;
		break;
	case satoshi_script_data_type_uint16:
		payload_size = sizeof(uint16_t);
		sdata->u64 = *(uint16_t *)data;
		sdata->size = 0;
		break;
	case satoshi_script_data_type_uint32:
		payload_size = sizeof(uint32_t);
		sdata->u64 = *(uint32_t *)data;
		sdata->size = 0;
		break;
	case satoshi_script_data_type_uint64:
		payload_size = sizeof(uint64_t);
		sdata->u64 = *(uint64_t *)data;
		sdata->size = 0;
		break;
	case satoshi_script_data_type_hash256:
		payload_size = 32;
		memcpy(sdata->h256, data, 32);
		sdata->size = 0;
		break;
	case satoshi_script_data_type_hash160:
		payload_size = 20;
		memcpy(sdata->h160, data, 20);
		sdata->size = 0;
		break;
	case satoshi_script_data_type_uchars:
		payload_size = size;
		sdata->data = (unsigned char *)data;
		sdata->size = size;
		break;
	case satoshi_script_data_type_pointer:
		payload_size = size;
		sdata->size = size;
		if(size > 0)
		{
			sdata->data = malloc(size);
			assert(sdata->data);
			
			memcpy(sdata->data, data, size);
		}
		break;
	default:
		return -1;	// unknown error
	}
	return payload_size;
}

enum satoshi_script_data_type  satoshi_script_data_get(satoshi_script_data_t * sdata, unsigned char ** p_data, ssize_t * p_length)
{
	assert(sdata && p_data && p_length);
	enum satoshi_script_data_type type = sdata->type;
	assert(type != satoshi_script_data_type_unknown);
	
	if(type == satoshi_script_data_type_null) return type;
	unsigned char * data = *p_data;
	ssize_t length = 0;
	switch(type)
	{
	case satoshi_script_data_type_bool:
	case satoshi_script_data_type_op_code:
		length = 1;
		if(NULL == data) {
			data = malloc(length);
			*p_data = data;
		}
		assert(data);
		*(uint8_t *)data = sdata->b;
		break;
	case satoshi_script_data_type_varint:
		length = varint_calc_size(sdata->u64);
		assert(length > 0);
		if(NULL == data) {
			data = malloc(length);
			*p_data = data;
		}
		assert(data);
		varint_set((varint_t *)data, sdata->u64);
		break;
	case satoshi_script_data_type_varstr:
		length = varint_calc_size(sdata->size) + sdata->size;
		if(NULL == data)
		{
			data = malloc(length);
			*p_data = data;
		}
		assert(data);
		varstr_set((varstr_t *)data, sdata->data, sdata->size);
		break;
	case satoshi_script_data_type_uint8:
	case satoshi_script_data_type_uint16:
	case satoshi_script_data_type_uint32:
	case satoshi_script_data_type_uint64:
		length = sizeof(uint64_t);
		if(NULL == data)
		{
			data = calloc(1, sizeof(uint64_t));
			assert(data);
			*p_data = data;
		}
		*(uint64_t *)data = sdata->u64;
		break;

	case satoshi_script_data_type_hash256:
	case satoshi_script_data_type_hash160:
		length = (type == satoshi_script_data_type_hash256)?32:20;
		if(NULL == data)
		{
			data = malloc(length);
			assert(data);
			*p_data = data;
		}
		memcpy(data, sdata->h256, length);
		break;
	case satoshi_script_data_type_uchars:
	case satoshi_script_data_type_pointer:
		length = sdata->size;
		if(sdata->data && length > 0)
		{
			if(NULL == data)
			{
				data = malloc(length);
				assert(data);
				*p_data = data;
			}
			memcpy(data, sdata->data, length);
		}
		break;
	default:
		return satoshi_script_data_type_unknown;	// unknown error
	}
	
	if(p_length) *p_length = length;
	return type;
}

void satoshi_script_data_cleanup(satoshi_script_data_t * sdata)
{
	if(NULL == sdata) return;
	switch(sdata->type)
	{
	case satoshi_script_data_type_pointer:
	case satoshi_script_data_type_varstr:
		free(sdata->data);
		sdata->data = NULL;
	default:
		break;
	}
	return;
}

satoshi_script_data_t * satoshi_script_data_new(enum satoshi_script_data_type type, const void * data, size_t size)
{
	satoshi_script_data_t * sdata = calloc(1, sizeof(*sdata));
	assert(sdata);
	ssize_t cb = satoshi_script_data_set(sdata, type, data, size);
	assert(cb >= 0);
	return sdata;
}
/*******************************************************
 * satoshi_script_stack
*******************************************************/
#define SATOSHI_SCRIPT_STACK_ALLOC_SIZE	(64)
static int satoshi_script_stack_resize(satoshi_script_stack_t * stack, ssize_t new_size)
{
	if(new_size <= 0) {
		new_size = SATOSHI_SCRIPT_STACK_ALLOC_SIZE;
	}
	else {
		new_size = (new_size + SATOSHI_SCRIPT_STACK_ALLOC_SIZE - 1) / SATOSHI_SCRIPT_STACK_ALLOC_SIZE * SATOSHI_SCRIPT_STACK_ALLOC_SIZE;
	}
	
	if(new_size <= stack->max_size) return 0;
	
	satoshi_script_data_t ** p_data = realloc(stack->data, new_size * sizeof(*p_data));
	assert(p_data);
	memset(p_data, 0, (new_size - stack->max_size) * sizeof(*p_data));
	
	stack->data = p_data;
	stack->max_size = new_size;
	
	return 0;
}

static int stack_push(struct satoshi_script_stack * stack, satoshi_script_data_t * sdata)
{
	int rc = 0;
	assert(sdata);
	rc = satoshi_script_stack_resize(stack, stack->count + 1);
	assert(0 == rc);
	
	stack->data[stack->count++] = sdata;
	return 0;
}

satoshi_script_data_t * stack_pop(struct satoshi_script_stack * stack)
{
	if(stack->count <= 0) return NULL;
	
	satoshi_script_data_t * sdata = stack->data[--stack->count];
	stack->data[stack->count] = NULL;
	
	return sdata;
}

satoshi_script_stack_t * satoshi_script_stack_init(satoshi_script_stack_t * stack, ssize_t size, void * user_data)
{
	if(NULL == stack) stack = calloc(1, sizeof(*stack));
	assert(stack);
	
	stack->user_data = user_data;
	stack->push = stack_push;
	stack->pop = stack_pop;
	
	int rc = satoshi_script_stack_resize(stack, size);
	assert(0 == rc);
	return stack;
}

void satoshi_script_stack_cleanup(satoshi_script_stack_t * stack)
{
	if(NULL == stack) return;
	
	if(stack->data)
	{
		for(ssize_t i = 0; i < stack->count; ++i)
		{
			satoshi_script_data_t * sdata = stack->data[i];
			if(sdata)
			{
				satoshi_script_data_cleanup(sdata);
				free(sdata);
			}
		}
		free(stack->data);
		stack->data = NULL;
	}
	stack->count = 0;
	stack->max_size = 0;
	return;
}


/***********************************************
 * satoshi_script
***********************************************/
//~ typedef struct satoshi_script
//~ {
	//~ void * user_data;
	//~ void * priv;
	//~ script_stack_t main[1];
	//~ script_stack_t alt[1];
	//~ int flags;
	
	//~ int (* eval)(struct satoshi_script * scripts);
	//~ ssize_t (* parse)(struct satoshi_script * scripts, const unsigned char * payload, size_t length);
//~ }satoshi_script_t;

#ifndef UNUSED
#define UNUSED(x) ((void)(x))
#endif
ssize_t scripts_parse(struct satoshi_script * scripts, const unsigned char * payload, size_t length)
{
	assert(scripts && payload && (length > 0));
	bitcoin_blockchain_t * chain = scripts->user_data;
	
	UNUSED(chain);
	
	const unsigned char * p = payload;
	const unsigned char * p_end = p + length;
	
	satoshi_script_stack_t * main_stack = scripts->main;
	satoshi_script_stack_t * alt = scripts->alt;
	
	assert(main_stack && alt);
	
	while(p < p_end)
	{
		int rc = 0;
		uint8_t op_code = *p++;
		satoshi_script_data_t * sdata = NULL; 
		ssize_t data_size = 0;
		ssize_t cb = 0;
		
		if(op_code < satoshi_script_opcode_op_pushdata1)
		{
			data_size = op_code;
			sdata = calloc(1, sizeof(*sdata));
			assert(sdata);
			
			cb = satoshi_script_data_set(sdata, satoshi_script_data_type_pointer, p, data_size);
			
			assert(cb == data_size);
			p += cb;
			
			rc = main_stack->push(main_stack, sdata);
			assert(0 == rc);
			continue;
		}
		
		switch(op_code)
		{
		case satoshi_script_opcode_op_pushdata1:
		case satoshi_script_opcode_op_pushdata2:
		case satoshi_script_opcode_op_pushdata4:
			if(op_code == satoshi_script_opcode_op_pushdata1) { data_size = *(uint8_t *)p++; }
			else if(op_code == satoshi_script_opcode_op_pushdata2) { data_size = *(uint16_t *)p; p += 2; }
			else if(op_code == satoshi_script_opcode_op_pushdata4) { data_size = *(uint32_t *)p; p += 4; }

			sdata = calloc(1, sizeof(*sdata));
			assert(sdata);
			
			cb = satoshi_script_data_set(sdata, satoshi_script_data_type_pointer, p, data_size);
			assert(cb == data_size);
			p += cb;
			
			rc = main_stack->push(main_stack, sdata);
			break;
		
		// crypto
		case satoshi_script_opcode_op_ripemd160:
		case satoshi_script_opcode_op_hash160:
		case satoshi_script_opcode_op_sha256:
		case satoshi_script_opcode_op_hash256:
			sdata = main_stack->pop(main_stack);
			if(NULL == sdata) return -1;		// parse failed
			else {
				unsigned char * data = NULL;
				ssize_t cb_data = 0;
				int type = satoshi_script_data_get(sdata, &data, &cb_data);
				assert(type > satoshi_script_data_type_null );
				
				unsigned char hash[32];
				ssize_t cb_hash = 20;
				
				enum satoshi_script_data_type data_type = satoshi_script_data_type_hash160;
				if(op_code == satoshi_script_opcode_op_ripemd160)
				{
					
					ripemd160_ctx_t ctx[1];
					ripemd160_init(ctx);
					ripemd160_update(ctx, data, cb_data);
					ripemd160_final(ctx, hash);
					
				}else if(op_code == satoshi_script_opcode_op_hash160)
				{
					hash160(data, cb_data, hash);
				}else
				{
					sha256_ctx_t ctx[1];
					sha256_init(ctx);
					sha256_update(ctx, data, cb_data);
					sha256_final(ctx, hash);
					
					if(op_code == satoshi_script_opcode_op_hash256)
					{
						sha256_init(ctx);
						sha256_update(ctx, hash, 32);
						sha256_final(ctx, hash);
					}
					cb_hash = 32;
					data_type = satoshi_script_data_type_hash256;
				}
				free(data);
				satoshi_script_data_cleanup(sdata);
				free(sdata);
			
				rc = main_stack->push(main_stack,
					satoshi_script_data_new(data_type, hash, cb_hash));
				assert(0 == rc);
			}
			break;
		default:
			return -1;	// parse failed
		}
		
	}
	
	assert(p <= p_end);
	return (p_end - payload);
}
satoshi_script_t * satoshi_script_init(satoshi_script_t * scripts, void * user_data)
{
	if(NULL == scripts) scripts = calloc(1, sizeof(*scripts));
	assert(scripts);
	
	scripts->user_data = user_data;
	scripts->parse = scripts_parse;
	
	satoshi_script_stack_t * main_stack = satoshi_script_stack_init(scripts->main, 0, scripts);
	satoshi_script_stack_t * alt = satoshi_script_stack_init(scripts->alt, 0, scripts);
	assert(main_stack == scripts->main);
	assert(alt == scripts->alt);
	
	return scripts;
}
void satoshi_script_reset(satoshi_script_t * scripts)
{
	satoshi_script_stack_cleanup(scripts->main);
	satoshi_script_stack_cleanup(scripts->alt);
}
void satoshi_script_cleanup(satoshi_script_t * scripts)
{
	if(NULL == scripts) return;
	satoshi_script_reset(scripts);
	return;
}


#if defined(_TEST_SATOSHI_SCRIPT) && defined(_STAND_ALONE)
int main(int argc, char **argv)
{
	
	return 0;
}
#endif

