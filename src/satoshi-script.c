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

#include "satoshi-tx.h"


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

ssize_t scripts_data_get_ptr(const satoshi_script_data_t * sdata, void ** p_data)
{
	if(sdata->type == satoshi_script_data_type_unknown) return -1;
	if(sdata->type == satoshi_script_data_type_null) return 0;
	
	switch(sdata->type)
	{
	case satoshi_script_data_type_varstr:
	case satoshi_script_data_type_pointer:
	case satoshi_script_data_type_uchars:
		*p_data = (void *)sdata->data;
		break;
	default: 
		*p_data = (void *)&sdata->u64;
		break;
	}
	return sdata->size;
}
 
int satoshi_script_data_compare(const satoshi_script_data_t * sdata1, const satoshi_script_data_t * sdata2)
{
	assert(sdata1 && sdata2);
	void * data1 = NULL;
	void * data2 = NULL;
	
	ssize_t cb_data1 = scripts_data_get_ptr(sdata1, &data1);
	ssize_t cb_data2 = scripts_data_get_ptr(sdata2, &data2);
	
	dump_line("\t--> data1: ", data1, cb_data1);
	dump_line("\t--> data2: ", data2, cb_data2);
	
	if(cb_data1 <= 0 || cb_data2 <= 0 || cb_data1 != cb_data2) return -1;
	
	return memcmp(data1, data2, cb_data1);
}
 
ssize_t satoshi_script_data_set(satoshi_script_data_t * sdata, 
	enum satoshi_script_data_type type, 
	const void * data, size_t size)
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
		break;
	case satoshi_script_data_type_uint16:
		payload_size = sizeof(uint16_t);
		sdata->u64 = *(uint16_t *)data;
		break;
	case satoshi_script_data_type_uint32:
		payload_size = sizeof(uint32_t);
		sdata->u64 = *(uint32_t *)data;
		break;
	case satoshi_script_data_type_uint64:
		payload_size = sizeof(uint64_t);
		sdata->u64 = *(uint64_t *)data;
		break;
	case satoshi_script_data_type_hash256:
		payload_size = 32;
		memcpy(sdata->h256, data, payload_size);
		break;
	case satoshi_script_data_type_hash160:
		payload_size = 20;
		memcpy(sdata->h160, data, payload_size);
		break;
	case satoshi_script_data_type_uchars:
		payload_size = size;
		sdata->data = (unsigned char *)data;
		break;
	case satoshi_script_data_type_pointer:
		payload_size = size;
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
	
	sdata->size = payload_size;
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

void satoshi_script_data_free(satoshi_script_data_t * sdata)
{
	if(sdata)
	{
		satoshi_script_data_cleanup(sdata);
		free(sdata);
	}
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
	
	fprintf(stderr, "\t --> stack_push()::data_type=%d, size=%zd, stack.count=%d\n",
		sdata->type,
		sdata->size,
		(int)stack->count);
		
	dump_line("\t\t --> data pushed: ", 
		(sdata->type >= satoshi_script_data_type_varstr)?sdata->data:sdata->h256, 
		sdata->size);
	return 0;
}

satoshi_script_data_t * stack_pop(struct satoshi_script_stack * stack)
{
	if(stack->count <= 0) return NULL;
	
	satoshi_script_data_t * sdata = stack->data[--stack->count];
	stack->data[stack->count] = NULL;
	
	
	printf("\t --> stack_pop()::data_type=%d, size=%zd, stack.count=%d\n",
		sdata->type,
		sdata->size,
		(int)stack->count);
	dump_line("\t\t --> data popped: ", 
		(sdata->type >= satoshi_script_data_type_varstr)?sdata->data:sdata->h256, 
		sdata->size);
		
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

#define scripts_parser_error_handler(fmt, ...) do {	\
		fprintf(stderr, "\e[33m" "%s@%d::%s(): " fmt "\e[39m" "\n",	\
			__FILE__, __LINE__, __FUNCTION__,		\
			##__VA_ARGS__ 							\
		);											\
		goto label_error;							\
	} while(0)


typedef struct satoshi_script_private
{
	crypto_context_t crypto[1]; 
	int crypto_init_flags;	
	
	int if_statement_depth;		// 0 == top_level
}satoshi_script_private_t;

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
	return rc;
label_error:
	return -1;
}

static inline ssize_t parse_op_push_data(satoshi_script_stack_t * stack, uint8_t op_code, const unsigned char * p, const unsigned char * p_end)
{
	assert(op_code <= satoshi_script_opcode_op_pushdata4);
	int rc = 0;
	uint32_t data_size = op_code;
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
	data_size = le32toh(data_size);	// to support big-endian system ( every integer in bitcoin system is little-endian )
	
	if((p + data_size) > p_end) {
		scripts_parser_error_handler("invalid payload length.");
	}
	
	dump_line("\t\t--> push_data: ", p, data_size);
			
	rc = stack->push(stack, 
		satoshi_script_data_new(satoshi_script_data_type_pointer, 
			p, data_size)
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

static inline int parse_op_equal(satoshi_script_stack_t * stack)
{
	int rc = parse_op_equalverify(stack);
	int8_t ok = (0 == rc);
	
	debug_printf("is_equal() = [%s]", ok?"True":"False");
	return stack->push(stack, satoshi_script_data_new(satoshi_script_data_type_bool, &ok, 1));
}

static inline int parse_op_checksig(satoshi_script_stack_t * stack, satoshi_script_t * scripts)
{
	int rc = 0;
	crypto_pubkey_t * pubkey = NULL;
	crypto_signature_t * sig = NULL;
	
	if(stack->count < 2)	// must have { sig_with_hashtype, pubkey }
	{
		scripts_parser_error_handler("invalid operation: opcode=%.2x, stack empty.", 
			satoshi_script_opcode_op_checksig);
	}
	
	satoshi_tx_t * tx = scripts->tx;
	const satoshi_txout_t * utxo = scripts->utxo;
	assert(tx && tx->txins);
	
	ssize_t txin_index = scripts->txin_index;
	//~ satoshi_txin_t * txins = tx->txins;
	assert(txin_index >= 0 && txin_index < tx->txin_count);
	
	crypto_context_t * crypto = scripts->crypto;
	assert(crypto);
	
	// pop pubkey
	satoshi_script_data_t * sdata_pubkey = stack->pop(stack);
	pubkey = crypto_pubkey_import(crypto, 
		sdata_pubkey->data, sdata_pubkey->size);
	if(NULL == pubkey) {
		scripts_parser_error_handler("invalid pubkey.");
	} 
	
	// pop signature with hashtype
	satoshi_script_data_t * sdata_sig_hashtype = stack->pop(stack);
	ssize_t cb_sig = sdata_sig_hashtype->size - 1;
	assert(sdata_sig_hashtype && sdata_sig_hashtype->data && cb_sig > 0);
	sig = crypto_signature_import(crypto,
		sdata_sig_hashtype->data, cb_sig);
		
	uint32_t hash_type = sdata_sig_hashtype->data[cb_sig];
	satoshi_script_data_free(sdata_sig_hashtype);
	
	if(NULL == sig) {
		scripts_parser_error_handler("invalid signature.");
	} 
	
	uint256_t digest;
	memset(&digest, 0, sizeof(digest));
	rc = satoshi_tx_get_digest(tx, txin_index, hash_type, utxo, &digest);
	
	if(rc) {
		scripts_parser_error_handler("get tx_digest failed.");
	}
	
	unsigned char * sig_der = NULL;
	ssize_t cb_sig_der = crypto_signature_export(crypto, sig, &sig_der);
	assert(sig_der && cb_sig_der > 0); 
	rc = crypto->verify(crypto, (unsigned char *)&digest, 32,
		pubkey, 
		sig_der, cb_sig_der);
		
	int8_t ok = (0 == rc);
	stack->push(stack, satoshi_script_data_new(satoshi_script_data_type_bool, 
		&ok, 1));

	if(rc)
	{
		scripts_parser_error_handler("verify signature failed.");
	}else
	{
		debug_printf("verify ok");
		
	}
	
	if(pubkey) crypto_pubkey_free(pubkey);
	if(sig) crypto_signature_free(sig);
	
	return rc;
label_error:
	if(pubkey) crypto_pubkey_free(pubkey);
	if(sig) crypto_signature_free(sig);
	
	return -1;
}

static inline int parse_op_checkmultisig(satoshi_script_stack_t * stack, satoshi_script_t * scripts)
{
	int rc = -1;
	int num_pubkeys = 0, num_sigs = 0;
	
	satoshi_tx_t * tx = scripts->tx;
	ssize_t txin_index = scripts->txin_index;
	assert(tx && txin_index >= 0 && txin_index < tx->txin_count);
	
	satoshi_script_data_t * sdata = NULL;
	crypto_pubkey_t ** pubkeys = NULL;
	crypto_signature_t ** sigs = NULL;
	crypto_context_t * crypto = scripts->crypto;
	assert(crypto);
	
	// pop num_pubkeys
	sdata = stack->pop(stack);
	if(NULL == sdata) {
		scripts_parser_error_handler("pop num_pubkeys failed.");
	}
	
	num_pubkeys = sdata->b;
	satoshi_script_data_free(sdata);
	
	if(num_pubkeys < 1 || num_pubkeys > 16) {
		scripts_parser_error_handler("invalid operation: stack empty.");
	}
	
	// pop pubkeys
	pubkeys = calloc(num_pubkeys, sizeof(*pubkeys));
	assert(pubkeys);
	
	for(int i = 0; i < num_pubkeys; ++i)
	{
		sdata = stack->pop(stack);
		if(NULL == sdata || !(sdata->size == 33 || sdata->size ==65) ) {
			scripts_parser_error_handler("stack empty or invalid pubkey data.");
		}
		
		pubkeys[i] = crypto_pubkey_import(crypto, sdata->data, sdata->size);
		satoshi_script_data_free(sdata);
		
		if(NULL == pubkeys[i]) {
			scripts_parser_error_handler("import pubkeys[%d] failed.", i);
		}
	}
	
	// pop num_sigs
	sdata = stack->pop(stack);
	if(NULL == sdata) {
		scripts_parser_error_handler("pop num_sigs failed");
	}
	
	num_sigs = sdata->b;
	satoshi_script_data_free(sdata);
	
	if(num_sigs < 0 || num_sigs > num_pubkeys) {
		scripts_parser_error_handler("invalid num_siganatures.");
	}
	
	// pop sigs
	sigs = calloc(num_sigs, sizeof(*sigs));
	assert(sigs);
	
	uint32_t prev_sighash_type = 0;
	uint256_t digest;
	int num_verified = 0;
	int pubkey_index = 0;
	
	for(int i = 0; i < num_sigs; ++i)
	{
		sdata = stack->pop(stack);
		if(NULL == sdata || sdata->size < 1 ) {
			scripts_parser_error_handler("stack empty or invalid sig data.");
		}
		
		unsigned char * sig_der = NULL;
		ssize_t cb_sig_der = sdata->size - 1;
		uint32_t sighash_type = sdata->data[cb_sig_der];
		
		// verify signature format
		sigs[i] = crypto_signature_import(crypto, sdata->data, cb_sig_der);
		satoshi_script_data_free(sdata);
		if(NULL == sigs[i]) {
			scripts_parser_error_handler("import sigs[%d] failed.", i);
		}
		
		// get DER format signature
		cb_sig_der = crypto_signature_export(crypto, sigs[i], &sig_der); 
		assert(cb_sig_der > 0);
		
		// recalulate tx_digest if need
		if(sighash_type != prev_sighash_type)
		{
			rc = satoshi_tx_get_digest(tx, txin_index, sighash_type, 
				scripts->utxo, &digest);
			if(rc){
				scripts_parser_error_handler("get tx_digest failed.");
			}
			prev_sighash_type = sighash_type;
		}
		

		// verify signature
		rc = -1;
		for(; pubkey_index < num_pubkeys; ++pubkey_index)
		{
			rc = crypto->verify(crypto, (unsigned char *)&digest, 32,
				pubkeys[pubkey_index],
				sig_der, cb_sig_der);
			if(0 == rc) {
				++num_verified;
				break;
			}
		}
		printf("\t\t\t ==> verify sig[%d] = %d\n", (int)i, rc);
		free(sig_der);
	}
	
	int8_t ok = (num_verified == num_sigs);
	rc= stack->push(stack, 
		satoshi_script_data_new(satoshi_script_data_type_bool, &ok, 1));
	
label_error:
	if(pubkeys)
	{
		for(int i = 0; i < num_pubkeys; ++i)
		{
			crypto_pubkey_free(pubkeys[i]);
		}
		free(pubkeys);
	}
	
	if(sigs)
	{
		for(int i = 0; i < num_sigs; ++i)
		{
			crypto_signature_free(sigs[i]);
		}
		free(sigs);
	}
	
	return rc;
}

static ssize_t parse_op_if_notif(satoshi_script_stack_t * stack, satoshi_script_t * scripts, 
	int depth, // depth of if/notif branch, 0 == top-level 
	unsigned char op_code, 
	const unsigned char * p, 
	const unsigned char *p_end)
{
	assert(op_code == satoshi_script_opcode_op_if || op_code == satoshi_script_opcode_op_notif);
	
	// pop top item and check value
	int8_t ok = 1;
	int rc = scripts->verify(scripts);	// 0 == ok (no error).
	if(rc) ok = 0;
	
	/**
	 *  Check if the conditions are met
	 *  (op_code == op_if) and (0 == rc)
	 *  (op_code == op_notif) and (0 != rc)
	 */ 
	//~ int condition = ( ((0 == rc) && (op_code == satoshi_script_opcode_op_if))
		//~ || (rc && (op_code == satoshi_script_opcode_op_notif) ));
	int condition_matched = ((op_code - satoshi_script_opcode_op_if) ^ ok );  // xor 
	
	if(condition_matched)
	{
		// todo
	}
	
	return -1;	// todo
}

static ssize_t scripts_parse(struct satoshi_script * scripts, 
	enum satoshi_tx_script_type type, 	// if is_txin, only allows opcode < OP_PUSHDATA4
	const unsigned char * payload, size_t length)
{
	assert(scripts && payload && (length > 0));
	bitcoin_blockchain_t * chain = scripts->user_data;
	
	UNUSED(chain);
	
	const unsigned char * p = payload;
	const unsigned char * p_end = p + length;
	
	satoshi_script_stack_t * main_stack = scripts->main_stack;
	satoshi_script_stack_t * alt = scripts->alt_stack;
	
	assert(main_stack && alt);
	
	
	
	int is_p2sh = 0;
	int segwit_flag = 0;
	if(p[0] == 0)
	{
		if(type == satoshi_tx_script_type_txin) {
			is_p2sh = 1;
		}else
		{
			segwit_flag = 1;
		}
		++p;
	}
	
	(void)((segwit_flag));	// todo: ...
	ssize_t data_size = 0;
	while(p < p_end)
	{
		int rc = 0;
		uint8_t op_code = *p++;
		
		
		if(op_code <= satoshi_script_opcode_op_pushdata4)
		{
			assert(op_code < satoshi_script_opcode_op_pushdata4); // LIMIT the scripts length can not exceed 65535 bytes
			
			debug_printf("parse op_pushdata (0x%.2x)", op_code);
			data_size = parse_op_push_data(main_stack, op_code, p, p_end);
			
			if(data_size < 0) return -1;
			p += data_size;
			
			continue;
		}
		
		if(type == satoshi_tx_script_type_txin) { // only allows push-data opcodes
			scripts_parser_error_handler("parse txin scripts failed(opcode=0x%.2x): %s",
				op_code,
				"not a push data opcode.");
			return -1;
		}
		
		if(op_code >= satoshi_script_opcode_op_1 && 
			op_code <= satoshi_script_opcode_op_16)
		{
			debug_printf("parse op_1 .. op_16 (0x%.2x)", op_code);
			op_code -= (satoshi_script_opcode_op_1 - 1);
			main_stack->push(main_stack, 
				satoshi_script_data_new(satoshi_script_data_type_uint8, &op_code, 1)
			);
			continue;
		}
		
		switch(op_code)
		{
		// crypto
		case satoshi_script_opcode_op_ripemd160:
		case satoshi_script_opcode_op_hash160:
		case satoshi_script_opcode_op_sha256:
		case satoshi_script_opcode_op_hash256:
			debug_printf("parse op_hash (0x%.2x)", op_code);
			rc = parse_op_hash(main_stack, op_code, p, p_end); 
			break;
		case satoshi_script_opcode_op_dup:
			debug_printf("parse op_dup (0x%.2x)", op_code);
			rc = parse_op_dup(main_stack);
			break;
		case satoshi_script_opcode_op_equalverify:
			debug_printf("parse op_equalverify (0x%.2x)", op_code);
			rc = parse_op_equalverify(main_stack);
			break;
		case satoshi_script_opcode_op_equal:
			debug_printf("parse op_equalverify (0x%.2x)", op_code);
			rc = parse_op_equal(main_stack);
			break;

		case satoshi_script_opcode_op_checksig:
			debug_printf("parse op_checksig (0x%.2x)", op_code);
			rc = parse_op_checksig(main_stack, scripts);
			break;
		case satoshi_script_opcode_op_checkmultisig:
			debug_printf("parse op_checkmultisig (0x%.2x)", op_code);
			rc = parse_op_checkmultisig(main_stack, scripts);
			// todo
			break;
		
		// Flow control
		case satoshi_script_opcode_op_nop:	// = 0x61, Does nothing.
			continue;
			
		case satoshi_script_opcode_op_if: 		// = 0x63,
		case satoshi_script_opcode_op_notif: 	// = 0x64,
			data_size = parse_op_if_notif(main_stack, scripts, 
				0, // depth of if/notif branch, 0 == top-level 
				op_code, p, p_end);
			if(data_size < 0) return -1;
			p += data_size;
			break;
		case satoshi_script_opcode_op_else:		// = 0x67,
		case satoshi_script_opcode_op_endif:	// = 0x68,
			// op_else/op_endif should only be processed within parse_op_if_notif() function, with depth >= 0
			scripts_parser_error_handler("invalid op_code(0x%.2x), op_if / op_notif was not found.\n", op_code);
			return -1;
		
		case satoshi_script_opcode_op_verify: // = 0x69,
			rc = scripts->verify(scripts);
			break;
		case satoshi_script_opcode_op_return: // = 0x6a,
		/**
			 * https://en.bitcoin.it/wiki/Script
			 * Marks transaction as invalid. 
			 * Since bitcoin 0.9, a standard way of attaching extra data to transactions is 
			 * to add a zero-value output with a scriptPubKey consisting of OP_RETURN followed by data. 
			 * Such outputs are provably unspendable and specially discarded from storage in the UTXO set, 
			 * reducing their cost to the network. 
			 * Since 0.12, standard relay rules allow a single output with OP_RETURN, 
			 * that contains any sequence of push statements (or OP_RESERVED[1]) 
			 * after the OP_RETURN provided the total scriptPubKey length is at most 83 bytes.
		 */
		// todo:
			continue;

		/**
		 * ignores:
		 * 	OP_NOP1, OP_NOP4-OP_NOP10	176, 179-185	0xb0, 0xb3-0xb9	
		 * 	The word is ignored. 
		 * 	Does not mark transaction as invalid.
		 */
		case satoshi_script_opcode_op_nop1:
		case satoshi_script_opcode_op_nop4:
		case satoshi_script_opcode_op_nop5:
		case satoshi_script_opcode_op_nop6:
		case satoshi_script_opcode_op_nop7:
		case satoshi_script_opcode_op_nop8:
		case satoshi_script_opcode_op_nop9:
		case satoshi_script_opcode_op_nop10:
			continue;
		
		/**
		 * Reserved words: 
		 *  Any opcode not assigned is also reserved. 
		 *  Using an unassigned opcode makes the transaction invalid.
		 */
		case satoshi_script_opcode_op_reserved:
		case satoshi_script_opcode_op_ver:
		case satoshi_script_opcode_op_verif:	// = 0x65,
		case satoshi_script_opcode_op_vernotif: // = 0x66,
		case satoshi_script_opcode_op_reserved1:
		case satoshi_script_opcode_op_reserved2:
		default:
			debug_printf("unsupporting op_code (0x%.2x)", op_code);
			goto label_error;	// parse failed
		}
		if(rc) goto label_error;
		
	}
	
	if(p != p_end){ // only allows push-data opcodes
		scripts_parser_error_handler("parse scripts failed or invalid payload length");
	}
	
	if(type == satoshi_tx_script_type_txin && is_p2sh)
	{
		satoshi_tx_t * tx = scripts->tx;
		int txin_index = scripts->txin_index;
		assert(tx && txin_index >= 0 && txin_index < tx->txin_count);
		tx->txins[txin_index].is_p2sh = 1;
		
		satoshi_script_data_t * sdata = NULL;
		ssize_t cb = 0;
		// parse redeem scripts;
		sdata = main_stack->pop(main_stack);
		if(NULL == sdata || sdata->type < satoshi_script_data_type_varstr)
		{
			fprintf(stderr, "invalid redeem scripts\n");
			satoshi_script_data_free(sdata);
			return -1;
		}
		
		debug_printf("parse redeem_scripts %p, length=%ld...", sdata->data, (long)sdata->size);
		dump_line("redeem scripts: ", sdata->data, sdata->size);
		
		tx->txins[txin_index].redeem_scripts = varstr_new(sdata->data, sdata->size);
		
		cb = scripts->parse(scripts, 
			satoshi_tx_script_type_p2sh_redeem_scripts, 
			sdata->data, sdata->size);
		
		if(cb == sdata->size) // if parsed ok, push back redeem_scripts
		{
			/**
			 * There might be a bug on p2sh design:
			 * By definition, the last op_code(OP_CHECKMULTISIG) will push a 'true/false' value to the stack, 
			 * but nowhere else can this value be used.
			 * It might be more reasonable if OP_CHECKMULTISIGVERIFY is used here.
			 * 
			 * so, when we are processing the txin scripts, 
			 * we need to manually pop this extra value from the stack before push back redeem scripts
			 */
			satoshi_script_data_free(main_stack->pop(main_stack));
			
			// push back redeem_scripts
			main_stack->push(main_stack, sdata);
		}else
		{
			satoshi_script_data_free(sdata);
			scripts_parser_error_handler("parse redeem scripts failed");
		}
		
	}
	
	return (p_end - payload);
	
label_error:
	return -1;
}


static int scripts_verify(satoshi_script_t * scripts)
{
	debug_printf("txin_index: %d", (int)scripts->txin_index);
	
	satoshi_script_stack_t * stack = scripts->main_stack;
	if(NULL == stack || stack->count <= 0) return -1;
	
	satoshi_script_data_t * sdata = stack->pop(stack);
	if(NULL == sdata) return -1;
	
	int8_t ok = (sdata->type == satoshi_script_data_type_bool)?sdata->b:0;
	satoshi_script_data_free(sdata);
	
	if(!ok) return -1;

	return 0;
}

satoshi_script_t * satoshi_script_init(satoshi_script_t * scripts, 
	crypto_context_t * crypto, 
	void * user_data)
{
	if(NULL == scripts) scripts = calloc(1, sizeof(*scripts));
	assert(scripts);
	scripts->user_data = user_data;
	
	satoshi_script_private_t * priv = calloc(1, sizeof(*priv));
	assert(priv);
	scripts->priv = priv;
	
	if(NULL == crypto)
	{
		if(!priv->crypto_init_flags)
		{
			crypto = crypto_context_init(priv->crypto, crypto_backend_libsecp256, scripts);
			assert(crypto);
			
			priv->crypto_init_flags = 1;
		}else
		{
			crypto = priv->crypto;
		}
	}
	scripts->crypto = crypto;
	scripts->parse = scripts_parse;
	scripts->verify = scripts_verify;
	
	satoshi_script_stack_t * main_stack = satoshi_script_stack_init(scripts->main_stack, 0, scripts);
	satoshi_script_stack_t * alt = satoshi_script_stack_init(scripts->alt_stack, 0, scripts);
	assert(main_stack == scripts->main_stack);
	assert(alt == scripts->alt_stack);
	
	return scripts;
}
void satoshi_script_reset(satoshi_script_t * scripts)
{
	satoshi_script_stack_cleanup(scripts->main_stack);
	satoshi_script_stack_cleanup(scripts->alt_stack);
}

void satoshi_script_cleanup(satoshi_script_t * scripts)
{
	if(NULL == scripts) return;
	
	satoshi_script_private_t * priv = scripts->priv;
	if(priv)
	{
		if(scripts->crypto == priv->crypto) 
		{
			scripts->crypto = NULL;
		}
		if(priv->crypto_init_flags) {
			crypto_context_cleanup(priv->crypto);
			priv->crypto_init_flags = 0;
		}
		free(priv);
		scripts->priv = NULL;
	}
	
	satoshi_script_reset(scripts);
	return;
}

#if defined(_TEST_SATOSHI_SCRIPT) && defined(_STAND_ALONE)

/*****************************************/


/**
 *  TEST DATA
 */
static const char * s_hex_txns[3] = {
// txns[0]: deposit to p2pkh address 
"0100000001fa19382fd7a4834f0d420b273888b223ed821996c0efbe2756e5dfe12b653b74000000006c49304602210091f4ad9e90bcb930e75b9cf0d48417f9d3966c15d40ef82f2a0fae1317368d94022100c8c6390eb304b52f2626a3de64bbeca1a6c2b1afcf65e5366d232c403d007d6b012103c58187d401a1a97a29caaba5f03d687b06d24e569816a471b3f3a872fcc31760ffffffff"
"02"	// txouts_count
	// txouts[0]:
	"40420f0000000000"
	"1976a91412a9abf5c32392f38bd8a1f57d81b1aeecc5699588ac"
	// txouts[1]
	"b0608b3b00000000"
	"1976a9141d30342095961d951d306845ef98ac08474b36a088ac"
"00000000",

// txns[1]: withdraw from p2phk and deposit to p2sh address
// # txid= LE"40eee3ae1760e3a8532263678cdf64569e6ad06abc133af64f735e52562bccc8"	
"01000000"
"01"
	"da75479f893cccfaa8e4558b28ec7cb4309954389f251f2212eabad7d7fda342"
	"00000000"		// txns[0].txouts[0]
	"6a"
		"47"
			"3044"
				"022048d1468895910edafe53d4ec4209192cc3a8f0f21e7b9811f83b5e419bfb57e0"
				"02203fef249b56682dbbb1528d4338969abb14583858488a3a766f609185efe68bca"
			"01"
		"21"
			"031a455dab5e1f614e574a2f4f12f22990717e93899695fb0d81e4ac2dcfd25d00"
	"ffffffff"
"01"
	"301b0f0000000000"
	"17a914e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a"
	"87"
"00000000",

// txns[2]: withdraw from p2sh address
//# txid = LE"7edb32d4ffd7a385b763c7a8e56b6358bcd729e747290624e18acdbe6209fc45"
"01000000"
"01"
	"c8cc2b56525e734ff63a13bc6ad06a9e5664df8c67632253a8e36017aee3ee40" // big-endian
	"00000000"		// txns[1].txouts[0]
	"90"
		"00"		// p2sh flag
		"48"
			"3045"
				"022100ad0851c69dd756b45190b5a8e97cb4ac3c2b0fa2f2aae23aed6ca97ab33bf883"	// 	r
				"02200b248593abc1259512793e7dea61036c601775ebb23640a0120b0dba2c34b790"		//	s
			"01"	// hash_type = satoshi_tx_sighash_all
		"45"
			"51"	// op_1: num signatures = 1
			"41" "042f90074d7a5bf30c72cf3a8dfd1381bdbd30407010e878f3a11269d5f74a58788505cdca22ea6eab7cfb40dc0e07aba200424ab0d79122a653ad0c7ec9896bdf"
			"51"	// op_1: num_pubkeys = 1
			"ae"	// satoshi_script_opcode_op_checkmultisig
	"feffffff"
"01"
	"20f40e0000000000" "1976a9141d30342095961d951d306845ef98ac08474b36a088ac"
"a7270400"
};

/********************************************************/

int verify_tx(satoshi_script_t * scripts, 
	satoshi_tx_t * tx, 
	satoshi_txout_t ** utxoes)
{
	int rc = 0;
	scripts->tx = tx;	// attach tx
	
	int64_t inputs_amount = 0;		// sum(utxoes[].value)
	int64_t outputs_amount = 0;		// sum(tx.txouts[].value)
	// verify tx
	for(ssize_t i = 0; i < tx->txin_count; ++i)
	{
		satoshi_txin_t * txin = &tx->txins[i];
		int utxo_index = txin->outpoint.index;
		satoshi_txout_t * utxo = utxoes[utxo_index]; 
		
		// init scripts' public data
		scripts->txin_index = i;
		scripts->utxo = utxo;
		
		ssize_t cb = -1;
		unsigned char * payload = varstr_getdata_ptr(txin->scripts);
		ssize_t cb_payload = varstr_length(txin->scripts);
		cb = scripts->parse(scripts, 
			satoshi_tx_script_type_txin, 
			payload, cb_payload);
		assert(cb == cb_payload);

		// parse utxo scripts
		payload = varstr_getdata_ptr(utxo->scripts);
		cb_payload = varstr_length(utxo->scripts);
		
		dump_line("parse txout: ", payload, cb_payload);
		cb = scripts->parse(scripts, 
			satoshi_tx_script_type_txout, 
			payload, cb_payload);
		assert(cb == cb_payload);
		
		// check scripts->stack
		rc = scripts->verify(scripts);
		assert(0 == rc);
		
		// sum inputs.amount
		assert(utxo->value >= 0);
		inputs_amount += utxo->value;
	}
	int64_t fees = 0;
	for(ssize_t i = 0; i < tx->txout_count; ++i)
	{
		outputs_amount += tx->txouts[i].value;
	}
#ifndef COIN
#define COIN (100000000)
#endif
	fees =  inputs_amount - outputs_amount;
	printf("inputs: %ld.%.8ld BTC, outputs: %ld.%.8ld BTC, fees: %ld.%.8ld BTC\n", 
		(long)(inputs_amount / COIN), (long)(inputs_amount % COIN),
		(long)(outputs_amount / COIN), (long)(outputs_amount % COIN),
		(long)(fees / COIN), (long)(fees % COIN));
	
	return 0;
}


int main(int argc, char **argv)
{
	unsigned char * txns_data[3] = {NULL};
	ssize_t cb_txns[3] = { 0 };
	
	cb_txns[0] = hex2bin(s_hex_txns[0], -1, (void **)&txns_data[0]);
	cb_txns[1] = hex2bin(s_hex_txns[1], -1, (void **)&txns_data[1]);
	cb_txns[2] = hex2bin(s_hex_txns[2], -1, (void **)&txns_data[2]);
	
	assert(cb_txns[0] > 0 && txns_data[0]);
	assert(cb_txns[1] > 0 && txns_data[1]);
	assert(cb_txns[2] > 0 && txns_data[2]);
	
	/*
	 * txns[0]: deposit to p2pkh;  
	 * txns[1]: withdraw from p2pkh and deposit to p2sh; 
	 * txns[2]: withdraw from p2sh
	*/ 
	satoshi_tx_t txns[3];
	memset(txns, 0, sizeof(txns));
	ssize_t cb = 0;
	
	cb = satoshi_tx_parse(&txns[0], cb_txns[0], txns_data[0]);
	assert(cb == cb_txns[0]);
	
	cb = satoshi_tx_parse(&txns[1], cb_txns[1], txns_data[1]);
	assert(cb == cb_txns[1]);
	assert(txns[1].txin_count > 0);
	
	cb = satoshi_tx_parse(&txns[2], cb_txns[2], txns_data[2]);
	assert(cb == cb_txns[2]);
	assert(txns[2].txin_count > 0);
	
	uint256_t prev_hash;
	memset(&prev_hash, 0, sizeof(prev_hash));
	hash256(txns_data[0], cb_txns[0], (unsigned char *)&prev_hash);
	dump_line("prev_hash: ", &prev_hash, 32);
	assert(0 == memcmp(&prev_hash, &txns[1].txins[0].outpoint.prev_hash, 32));	// verify test data
	
	int rc = 0;
	satoshi_script_t * scripts = satoshi_script_init(NULL, NULL, NULL);
	assert(scripts);
	
	// 1. verify p2pkh:  tx = &txns[1]
	satoshi_tx_t * tx = &txns[1];
	assert(tx->txin_count > 0);
	
	// init utxoes array[], 
	satoshi_txout_t ** utxoes = calloc(tx->txin_count, sizeof(*utxoes));
	utxoes[0] = &txns[0].txouts[0];	// todo: utxoes[i] = blockchain_db->get_utxo(tx->txins[i].outpoint);
	
	printf("==== verify p2pkh ...\n");
	rc = verify_tx(scripts, tx, utxoes);
	assert(0 == rc);
	free(utxoes);	// todo:  for each utxo in utxoes --> free(utxo);  free(utxoes);
	satoshi_script_cleanup(scripts);
	
	// 2. verify p2sh:  tx = &txns[2]
	
	satoshi_script_init(scripts, NULL, NULL);
	tx = &txns[2];
	assert(tx->txin_count > 0);
	
	// init utxoes array[], 
	utxoes = calloc(tx->txin_count, sizeof(*utxoes));
	utxoes[0] = &txns[1].txouts[0];	// todo: utxoes[i] = blockchain_db->get_utxo(tx->txins[i].outpoint);
	
	printf("==== verify p2sh ...\n");
	rc = verify_tx(scripts, tx, utxoes);
	assert(0 == rc);
	
	printf("num_items left on the stack: %ld\n", scripts->main_stack->count);
	
	
	// cleanup
	satoshi_script_cleanup(scripts);
	free(scripts);
	return 0;
}
#endif

