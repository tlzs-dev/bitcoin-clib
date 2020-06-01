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

/*******************************************************
 * satoshi_script_data
 *******************************************************/
ssize_t satoshi_script_data_set(satoshi_script_data_t * sdata, enum satoshi_node_data_type type, const void * data, size_t size)
{
	assert(type != satoshi_node_data_type_unknown);
	assert(sdata);
	
	sdata->type = type;
	if(type == satoshi_node_data_type_null) return 0;
	
	assert(data);
	size_t vint_size = 0;
	unsigned char * p = data;
	
	ssize_t payload_size = 0;
	
	switch(type)
	{
	case satoshi_node_data_type_bool:
	case satoshi_node_data_type_op_code:
		sdata->b = *(uint8_t *)data;
		payload_size = 1;
		break;
	case satoshi_node_data_type_varint:
		vint_size = varint_size((varint_t *)p);
		assert(vint_size > 0);
		sdata->u64 = varint_get((varint_t *)p);
		sdata->size = 0;
		break;
	case satoshi_node_data_type_varstr:
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
	case satoshi_node_data_type_uint8:
		payload_size = sizeof(uint8_t);
		sdata->u64 = *(uint8_t *)data;
		sdata->size = 0;
		break;
	case satoshi_node_data_type_uint16:
		payload_size = sizeof(uint16_t);
		sdata->u64 = *(uint16_t *)data;
		sdata->size = 0;
		break;
	case satoshi_node_data_type_uint32:
		payload_size = sizeof(uint32_t);
		sdata->u64 = *(uint32_t *)data;
		sdata->size = 0;
		break;
	case satoshi_node_data_type_uint64:
		payload_size = sizeof(uint64_t);
		sdata->u64 = *(uint64_t *)data;
		sdata->size = 0;
		break;
	case satoshi_node_data_type_hash256:
		payload_size = 32;
		memcpy(sdata->h256, data, 32);
		sdata->size = 0;
		break;
	case satoshi_node_data_type_hash160:
		payload_size = 20;
		memcpy(sdata->h160, data, 20);
		sdata->size = 0;
		break;
	case satoshi_node_data_type_uchars:
		payload_size = size;
		sdata->data = (unsigned char *)data;
		sdata->size = size;
		break;
	case satoshi_node_data_type_pointer:
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

void satoshi_script_data_cleanup(satoshi_script_data_t * sdata)
{
	if(NULL == s_data) return;
	switch(sdata->type)
	{
	case satoshi_node_data_type_pointer:
	case satoshi_node_data_type_varstr:
		free(sdata->data);
		sdata->data = NULL;
	}
	return;
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
	
	satoshi_script_data_t ** p_data = realloc(stack->data, new_size * sizeof(*data));
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
	stack->data[count] = NULL;
	
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

#if defined(_TEST_SATOSHI_SCRIPT) && defined(_STAND_ALONE)
int main(int argc, char **argv)
{
	
	return 0;
}
#endif

