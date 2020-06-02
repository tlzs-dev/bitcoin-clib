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


#ifndef UNUSED
#define UNUSED(x) ((void)(x))
#endif

#define AUTO_FREE_PTR __attribute__((cleanup(auto_free_ptr)))
static void auto_free_ptr(void * ptr)
{
	void * p = *(void **)ptr;
	if(p)
	{
		free(p);
		*(void **)ptr = NULL;
	}
}


/*******************************************************
 * satoshi_script_data
 *******************************************************/
int satoshi_script_data_compare(const satoshi_script_data_t * sdata1, const satoshi_script_data_t * sdata2)
{
	assert(sdata1 && sdata2);
	if(sdata1->type != sdata2->type) return -1;
	enum satoshi_script_data_type type = sdata1->type;
	
	if(type == satoshi_script_data_type_unknown ||
		type == satoshi_script_data_type_null) return -1;
		
	switch(type)
	{
	case satoshi_script_data_type_bool:
	case satoshi_script_data_type_op_code:
		return (int)(sdata1->b - sdata2->b);
	case satoshi_script_data_type_varint:
	case satoshi_script_data_type_uint8:
	case satoshi_script_data_type_uint16:
	case satoshi_script_data_type_uint32:
	case satoshi_script_data_type_uint64:
		if(sdata1->u64 == sdata2->u64) return 0;
		return -1;
	default:
		if(sdata1->size > 0 && (sdata1->size == sdata2->size))
		{
			return memcmp(sdata1->data, sdata2->data, sdata1->size);
		}
		break;
	}
	return -1;
}
 
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
		payload_size = vint_size;
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
		sdata->size = payload_size;
		break;
	case satoshi_script_data_type_uint32:
		payload_size = sizeof(uint32_t);
		sdata->u64 = *(uint32_t *)data;
		sdata->size = payload_size;
		break;
	case satoshi_script_data_type_uint64:
		payload_size = sizeof(uint64_t);
		sdata->u64 = *(uint64_t *)data;
		sdata->size = payload_size;
		break;
	case satoshi_script_data_type_hash256:
		payload_size = 32;
		memcpy(sdata->h256, data, 32);
		sdata->size = 32;
		break;
	case satoshi_script_data_type_hash160:
		payload_size = 20;
		memcpy(sdata->h160, data, 20);
		sdata->size = 20;
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

enum satoshi_script_data_type  satoshi_script_data_get(const satoshi_script_data_t * sdata, unsigned char ** p_data, ssize_t * p_length)
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

satoshi_script_data_t * satoshi_script_data_clone(const satoshi_script_data_t * sdata)
{
	//~ AUTO_FREE_PTR unsigned char * data = NULL;
	//~ ssize_t length = 0;
	//~ enum satoshi_script_data_type type = satoshi_script_data_get(sdata, &data, &length);
	//~ assert(type != satoshi_script_data_type_unknown);
	
	//~ return satoshi_script_data_new(type, data, length);
	assert(sdata && (sdata->type != satoshi_script_data_type_unknown));
	satoshi_script_data_t * new_data = calloc(1, sizeof(*new_data));
	assert(new_data);
	switch(sdata->type)
	{
	case satoshi_script_data_type_varstr:
	case satoshi_script_data_type_pointer:
		satoshi_script_data_set(new_data, sdata->type, sdata->data, sdata->size);
		break;
	default:
		memcpy(new_data, sdata, sizeof(*new_data));
	}
	return new_data;
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

#define scripts_parser_error_handler(fmt, ...) do {	\
		fprintf(stderr, "\e[33m" "%s@%d::%s(): " fmt "\e[39m" "\n",	\
			__FILE__, __LINE__, __FUNCTION__,		\
			##__VA_ARGS__ 							\
		);											\
		goto label_error;							\
	} while(0)


static inline int parse_op_hash(satoshi_script_stack_t * stack, uint8_t op_code, const unsigned char * p, const unsigned char * p_end)
{
	int rc = 0;
	ripemd160_ctx_t ripemd[1];
	sha256_ctx_t sha[1];
	
	satoshi_script_data_t * sdata = stack->pop(stack);
	if(NULL == sdata)
	{
		scripts_parser_error_handler("invalid operation: opcode=%.2x, stack empty.", op_code); 
	}
	unsigned char hash[32];
	size_t cb_hash = 32;
	
	AUTO_FREE_PTR unsigned char * data = NULL;
	ssize_t length = 0;
	enum satoshi_script_data_type type = satoshi_script_data_get(sdata, &data, &length);
	assert(type != satoshi_script_data_type_unknown);
	
	switch(op_code)
	{
	case satoshi_script_opcode_op_ripemd160:
		ripemd160_init(ripemd);
		ripemd160_update(ripemd, data, length);
		ripemd160_final(ripemd, hash);
		cb_hash = 20;
		type = satoshi_script_data_type_hash160;
		break;
	
	case satoshi_script_opcode_op_sha256:	
	case satoshi_script_opcode_op_hash160:
	case satoshi_script_opcode_op_hash256:
		sha256_init(sha);
		sha256_update(sha, data, length);
		sha256_final(sha, hash);
		
		type = satoshi_script_data_type_hash256;
		if(op_code ==  satoshi_script_opcode_op_hash160)	// ripemd160(sha256(data))
		{
			ripemd160_ctx_t ripemd[1];
			ripemd160_init(ripemd);
			ripemd160_update(ripemd, hash, 32);
			ripemd160_final(ripemd, hash);
			cb_hash = 20;
			type = satoshi_script_data_type_hash160;
		}else if(op_code == satoshi_script_opcode_op_hash256) // sha256(sha256(data))
		{
			sha256_init(sha);
			sha256_update(sha, hash, 32);
			sha256_final(sha, hash);
		}
		break;
	default:
		scripts_parser_error_handler("unsupported hash_type: %.2x", op_code);
	}
	
	rc = stack->push(stack, satoshi_script_data_new(type, hash, cb_hash));
	assert(0 == rc);
	
	return 0;
label_error:
	return -1;
}

static inline ssize_t parse_op_push_data(satoshi_script_stack_t * stack, uint8_t op_code, const unsigned char * p, const unsigned char * p_end)
{
	assert(op_code <= satoshi_script_opcode_op_pushdata4);
	int rc = 0;
	ssize_t data_size = op_code;
	ssize_t offset = 0;

	switch(op_code)
	{
	case satoshi_script_opcode_op_pushdata1:
		offset = 1;
		if((p + offset) > p_end) scripts_parser_error_handler("invalid payload length.");
		data_size = *(uint8_t *)p;
		break;
	case satoshi_script_opcode_op_pushdata2:
		offset = 2;
		if((p + offset) > p_end) scripts_parser_error_handler("invalid payload length.");
		data_size = *(uint16_t *)p; 
		
		break;
	case satoshi_script_opcode_op_pushdata4:
		offset = 4;
		if((p + offset) > p_end) scripts_parser_error_handler("invalid payload length.");
		data_size = *(uint32_t *)p;
		break;
	default:
		break;
	}

	p += offset;
	if((p + data_size) > p_end) {
		scripts_parser_error_handler("invalid payload length.");
	}
			
	rc = stack->push(stack, 
		satoshi_script_data_new(satoshi_script_data_type_pointer, p, data_size)
	);
	assert(0 == rc);
	return (offset + data_size);
label_error:
	return -1;
}

static inline int parse_op_dup(satoshi_script_stack_t * stack)
{
	int rc = 0;
	if(stack->count <= 0)
	{
		scripts_parser_error_handler("invalid operation: opcode=%.2x, stack empty.", 
			satoshi_script_opcode_op_dup);
	}
	const satoshi_script_data_t * sdata = stack->data[stack->count - 1];
	assert(sdata);
	
	rc = stack->push(stack, satoshi_script_data_clone(sdata));
	return rc;
label_error:
	return -1;
}


static inline int parse_op_equalverify(satoshi_script_stack_t * stack)
{
	if(stack->count < 2 )
	{
		scripts_parser_error_handler("invalid operation: opcode=%.2x, stack empty.", 
			satoshi_script_opcode_op_equalverify);
	}
	satoshi_script_data_t * sdata1 = stack->pop(stack);
	satoshi_script_data_t * sdata2 = stack->pop(stack);
	
	int rc = satoshi_script_data_compare(sdata1, sdata2);
	
	satoshi_script_data_cleanup(sdata1);
	satoshi_script_data_cleanup(sdata2);
	free(sdata1);
	free(sdata2);
	return rc;
label_error:
	return -1;
}


static inline int parse_op_checksig(satoshi_script_stack_t * stack, satoshi_script_t * scripts)
{
	int8_t ok = 0;
	if(stack->count <= 0)
	{
		scripts_parser_error_handler("invalid operation: opcode=%.2x, stack empty.", 
			satoshi_script_opcode_op_equalverify);
	}
	//~ satoshi_script_data_t * sdata = stack->pop(stack);
	
	//~ AUTO_FREE_PTR unsigned char * sig_scripts = NULL;
	//~ ssize_t cb_scripts = 0;
	//~ satoshi_script_data_get(sdata, &sig_scripts, &cb_script);
	//~ satoshi_script_data_cleanup(sdata);
	//~ free(sdata);
	
	//~ assert(p && cb_script > 0);	///< @todo: 
	//~ unsigned char * p = sig_scripts;
	//~ unsigned char * p_end = p + cb_script;
	
	//~ ssize_t cb_sig_with_type = varstr_size((varstr_t *)p);
	//~ assert(cb_sig > 0);
	//~ p++;
	
	//~ unsigned char * vstr_sig = p;
	//~ ssize_t cb_sig = varstr_size((varstr_t *)p);
	//~ assert(cb_sig_with_type == (cb_sig + 1));
	//~ p += cb_sig;
	
	//~ uint32_t hash_type = *p++; 

	//~ unsigned char * vstr_pubkey = p;
	//~ p += varstr_size((varstr_t *)p);
	
	//~ assert(p == p_end);
	
	//~ secp256k1_context * secp = secp256k1_context_create(
		//~ SECP256K1_FLAGS_BIT_CONTEXT_VERIFY | SECP256K1_CONTEXT_VERIFY);
	//~ assert(secp);
	
	//~ secp256k1_pubkey pubkey;
	//~ secp256k1_ecdsa_signature sig;
	
	//~ ok = secp256k1_ec_pubkey_parse(secp, &pubkey, 
		//~ vstr_pubkey + varint_size((varint_t *)vstr_pubkey),
		//~ varint_get((varint_t *)vstr_pubkey)
	//~ );
	//~ assert(ok);
	
	//~ ok = secp256k1_ecdsa_signature_parse_der(secp, &sig, 
		//~ vstr_sig + varint_size((varint_t *)vstr_sig),
		//~ varint_get((varint_t *)vstr_sig)
	//~ );
	//~ assert(ok);
		
	//~ uint256_t hash;
	//~ memset(&hash, 0, sizeof(hash));
	//~ satoshi_script_get_rawtx_hash(scripts, &hash);
	
	//~ ok = secp256k1_ecdsa_verify(secp, &sig, (unsigned char *)&hash, &pubkey);
	
	//~ secp256k1_context_destroy(secp);
	
	if(!ok) goto label_error;
	return 0;
label_error:
	return -1;
}


static ssize_t scripts_parse(struct satoshi_script * scripts, const unsigned char * payload, size_t length)
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
		ssize_t data_size = 0;
	
		if(op_code <= satoshi_script_opcode_op_pushdata4)
		{
			data_size = parse_op_push_data(main_stack, op_code, p, p_end);
			
			if(data_size < 0) return -1;
			p += data_size;
			continue;
		}
		
		switch(op_code)
		{
		// crypto
		case satoshi_script_opcode_op_ripemd160:
		case satoshi_script_opcode_op_hash160:
		case satoshi_script_opcode_op_sha256:
		case satoshi_script_opcode_op_hash256:
			rc = parse_op_hash(main_stack, op_code, p, p_end); 
			break;
		case satoshi_script_opcode_op_dup:
			rc = parse_op_dup(main_stack);
			break;
		case satoshi_script_opcode_op_equalverify:
			rc = parse_op_equalverify(main_stack);
			break;
		case satoshi_script_opcode_op_checksig:
			rc = parse_op_checksig(main_stack, scripts);
			break;
		default:
			goto label_error;	// parse failed
		}
		if(rc < 0) goto label_error;
		
	}
	
	assert(p <= p_end);
	return (p_end - payload);
	
label_error:
	return -1;
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

