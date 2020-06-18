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

#include "satoshi-types.h"
#include "crypto.h"

enum satoshi_script_data_type
{
	satoshi_script_data_type_unknown = -1,
	satoshi_script_data_type_null = 0,
	satoshi_script_data_type_bool,
	satoshi_script_data_type_op_code,
	satoshi_script_data_type_varint,
	satoshi_script_data_type_uint8,
	satoshi_script_data_type_uint16,
	satoshi_script_data_type_uint32,
	satoshi_script_data_type_uint64,
	satoshi_script_data_type_hash256,	// 8
	satoshi_script_data_type_hash160,	// 9
	satoshi_script_data_type_varstr,	// 10
	satoshi_script_data_type_uchars,	// 11, array, no-free
	satoshi_script_data_type_pointer,	// 12, need free
};

enum satoshi_script_opcode
{
	// push value
	satoshi_script_opcode_op_0 = 0x00,
	satoshi_script_opcode_op_false = satoshi_script_opcode_op_0,
	satoshi_script_opcode_op_pushdata1 = 0x4c,
	satoshi_script_opcode_op_pushdata2 = 0x4d,
	satoshi_script_opcode_op_pushdata4 = 0x4e,
	satoshi_script_opcode_op_1negate = 0x4f,
	satoshi_script_opcode_op_reserved = 0x50,
	satoshi_script_opcode_op_1 = 0x51,
	satoshi_script_opcode_op_true = satoshi_script_opcode_op_1,
	satoshi_script_opcode_op_2 = 0x52,
	satoshi_script_opcode_op_3 = 0x53,
	satoshi_script_opcode_op_4 = 0x54,
	satoshi_script_opcode_op_5 = 0x55,
	satoshi_script_opcode_op_6 = 0x56,
	satoshi_script_opcode_op_7 = 0x57,
	satoshi_script_opcode_op_8 = 0x58,
	satoshi_script_opcode_op_9 = 0x59,
	satoshi_script_opcode_op_10 = 0x5a,
	satoshi_script_opcode_op_11 = 0x5b,
	satoshi_script_opcode_op_12 = 0x5c,
	satoshi_script_opcode_op_13 = 0x5d,
	satoshi_script_opcode_op_14 = 0x5e,
	satoshi_script_opcode_op_15 = 0x5f,
	satoshi_script_opcode_op_16 = 0x60,

	// control
	satoshi_script_opcode_op_nop = 0x61,
	satoshi_script_opcode_op_ver = 0x62,
	satoshi_script_opcode_op_if = 0x63,
	satoshi_script_opcode_op_notif = 0x64,
	satoshi_script_opcode_op_verif = 0x65,
	satoshi_script_opcode_op_vernotif = 0x66,
	satoshi_script_opcode_op_else = 0x67,
	satoshi_script_opcode_op_endif = 0x68,
	satoshi_script_opcode_op_verify = 0x69,
	satoshi_script_opcode_op_return = 0x6a,

	// stack ops
	satoshi_script_opcode_op_toaltstack = 0x6b,
	satoshi_script_opcode_op_fromaltstack = 0x6c,
	satoshi_script_opcode_op_2drop = 0x6d,
	satoshi_script_opcode_op_2dup = 0x6e,
	satoshi_script_opcode_op_3dup = 0x6f,
	satoshi_script_opcode_op_2over = 0x70,
	satoshi_script_opcode_op_2rot = 0x71,
	satoshi_script_opcode_op_2swap = 0x72,
	satoshi_script_opcode_op_ifdup = 0x73,
	satoshi_script_opcode_op_depth = 0x74,
	satoshi_script_opcode_op_drop = 0x75,
	satoshi_script_opcode_op_dup = 0x76,
	satoshi_script_opcode_op_nip = 0x77,
	satoshi_script_opcode_op_over = 0x78,
	satoshi_script_opcode_op_pick = 0x79,
	satoshi_script_opcode_op_roll = 0x7a,
	satoshi_script_opcode_op_rot = 0x7b,
	satoshi_script_opcode_op_swap = 0x7c,
	satoshi_script_opcode_op_tuck = 0x7d,

	// splice ops
	satoshi_script_opcode_op_cat = 0x7e,
	satoshi_script_opcode_op_substr = 0x7f,
	satoshi_script_opcode_op_left = 0x80,
	satoshi_script_opcode_op_right = 0x81,
	satoshi_script_opcode_op_size = 0x82,

	// bit logic
	satoshi_script_opcode_op_invert = 0x83,
	satoshi_script_opcode_op_and = 0x84,
	satoshi_script_opcode_op_or = 0x85,
	satoshi_script_opcode_op_xor = 0x86,
	satoshi_script_opcode_op_equal = 0x87,
	satoshi_script_opcode_op_equalverify = 0x88,
	satoshi_script_opcode_op_reserved1 = 0x89,
	satoshi_script_opcode_op_reserved2 = 0x8a,

	// numeric
	satoshi_script_opcode_op_1add = 0x8b,
	satoshi_script_opcode_op_1sub = 0x8c,
	satoshi_script_opcode_op_2mul = 0x8d,
	satoshi_script_opcode_op_2div = 0x8e,
	satoshi_script_opcode_op_negate = 0x8f,
	satoshi_script_opcode_op_abs = 0x90,
	satoshi_script_opcode_op_not = 0x91,
	satoshi_script_opcode_op_0notequal = 0x92,

	satoshi_script_opcode_op_add = 0x93,
	satoshi_script_opcode_op_sub = 0x94,
	satoshi_script_opcode_op_mul = 0x95,
	satoshi_script_opcode_op_div = 0x96,
	satoshi_script_opcode_op_mod = 0x97,
	satoshi_script_opcode_op_lshift = 0x98,
	satoshi_script_opcode_op_rshift = 0x99,

	satoshi_script_opcode_op_booland = 0x9a,
	satoshi_script_opcode_op_boolor = 0x9b,
	satoshi_script_opcode_op_numequal = 0x9c,
	satoshi_script_opcode_op_numequalverify = 0x9d,
	satoshi_script_opcode_op_numnotequal = 0x9e,
	satoshi_script_opcode_op_lessthan = 0x9f,
	satoshi_script_opcode_op_greaterthan = 0xa0,
	satoshi_script_opcode_op_lessthanorequal = 0xa1,
	satoshi_script_opcode_op_greaterthanorequal = 0xa2,
	satoshi_script_opcode_op_min = 0xa3,
	satoshi_script_opcode_op_max = 0xa4,

	satoshi_script_opcode_op_within = 0xa5,

	// crypto
	satoshi_script_opcode_op_ripemd160 = 0xa6,
	satoshi_script_opcode_op_sha1 = 0xa7,
	satoshi_script_opcode_op_sha256 = 0xa8,
	satoshi_script_opcode_op_hash160 = 0xa9,
	satoshi_script_opcode_op_hash256 = 0xaa,
	satoshi_script_opcode_op_codeseparator = 0xab,
	satoshi_script_opcode_op_checksig = 0xac,
	satoshi_script_opcode_op_checksigverify = 0xad,
	satoshi_script_opcode_op_checkmultisig = 0xae,
	satoshi_script_opcode_op_checkmultisigverify = 0xaf,

	// expansion
	satoshi_script_opcode_op_nop1 = 0xb0,
	satoshi_script_opcode_op_checklocktimeverify = 0xb1,
	satoshi_script_opcode_op_nop2 = satoshi_script_opcode_op_checklocktimeverify,
	satoshi_script_opcode_op_checksequenceverify = 0xb2,
	satoshi_script_opcode_op_nop3 = satoshi_script_opcode_op_checksequenceverify,
	satoshi_script_opcode_op_nop4 = 0xb3,
	satoshi_script_opcode_op_nop5 = 0xb4,
	satoshi_script_opcode_op_nop6 = 0xb5,
	satoshi_script_opcode_op_nop7 = 0xb6,
	satoshi_script_opcode_op_nop8 = 0xb7,
	satoshi_script_opcode_op_nop9 = 0xb8,
	satoshi_script_opcode_op_nop10 = 0xb9,

	satoshi_script_opcode_op_invalidopcode = 0xff,
};

typedef struct satoshi_script_data
{
	enum satoshi_script_data_type type;
	union
	{
		int8_t b;	// bool value
		uint64_t u64;
		unsigned char * data;
		unsigned char h256[32];
		unsigned char h160[20];
	};
	size_t size;	// data.size
}satoshi_script_data_t;
ssize_t satoshi_script_data_set(satoshi_script_data_t * sdata, enum satoshi_script_data_type type, const void * data, size_t size);
void satoshi_script_data_cleanup(satoshi_script_data_t * sdata);

satoshi_script_data_t * satoshi_script_data_new(enum satoshi_script_data_type type, const void * data, size_t size);
void satoshi_script_data_free(satoshi_script_data_t * sdata);

satoshi_script_data_t * satoshi_script_data_new_boolean(int value);
#define satoshi_script_data_new_ptr(ptr, size) satoshi_script_data_new(satoshi_script_data_type_pointer, ptr, size)


typedef struct satoshi_script_stack
{
	satoshi_script_data_t ** data;		// use array[] to impl.
	ssize_t max_size;				// max stack_array[] size
	ssize_t count;					// current items count
	void * user_data;
	
	int (* push)(struct satoshi_script_stack * stack, satoshi_script_data_t * sdata);
	satoshi_script_data_t * (*pop)(struct satoshi_script_stack * stack);
	
	//~ ssize_t (* pop_n)(struct satoshi_script_stack * script, int n, satoshi_script_data_t *** p_sdata);
}satoshi_script_stack_t;
satoshi_script_stack_t * satoshi_script_stack_init(satoshi_script_stack_t * stack, ssize_t size, void * user_data);
void satoshi_script_stack_cleanup(satoshi_script_stack_t * stack);


enum satoshi_tx_script_type
{
	satoshi_tx_script_type_unknown = 0,
	satoshi_tx_script_type_txin = 1,
	satoshi_tx_script_type_txout = 2,
};

typedef struct satoshi_script
{
	void * user_data;
	void * priv;

	satoshi_script_stack_t main_stack[1];
	satoshi_script_stack_t alt_stack[1];
	
	crypto_context_t * crypto;
	const uint256_t * digest;
	
	// should be called before parse tx
	int (* attach_tx)(struct satoshi_script * scripts, satoshi_tx_t * tx);
	int (* set_txin_info)(struct satoshi_script * scripts, ssize_t txin_index, const satoshi_txout_t * utxo);
	int (* detach_tx)(struct satoshi_script * scripts);
	
	// parse raw scripts_data 
	ssize_t (* parse)(struct satoshi_script * scripts, 
		enum satoshi_tx_script_type type, 
		const unsigned char * payload, 
		size_t length);
	
	int (* verify)(struct satoshi_script * scripts);
}satoshi_script_t;

satoshi_script_t * satoshi_script_init(satoshi_script_t * scripts, 
	crypto_context_t * crypto, 
	void * user_data);
void satoshi_script_reset(satoshi_script_t * scripts);
void satoshi_script_cleanup(satoshi_script_t * scripts);


/**
 *  utils
 */
ssize_t satoshi_script_pushdata_code_from_varstr(const varstr_t * vscripts, unsigned char ** p_script_code);

#ifdef __cplusplus
}
#endif
#endif
