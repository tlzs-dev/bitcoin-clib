/*
 * satoshi-tx.c
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

#include "satoshi-types.h"
#include "satoshi-tx.h"
#include "crypto.h"
#include "utils.h"

#include <stdint.h>
#include <inttypes.h>
#include "satoshi-script.h"


#ifndef debug_printf
#define debug_printf(fmt, ...) do { \
		fprintf(stderr, "\e[33m" "%s@%d::%s(): " fmt "\e[39m\n", 	\
			__FILE__, __LINE__, __FUNCTION__,						\
			##__VA_ARGS__);											\
	} while(0)
#endif

#define debug_dump(prefix, data, length) do {						\
		fprintf(stderr, "\e[33m" "%s: ",	prefix);				\
		dump2(stderr, data, length);								\
		fprintf(stderr, "\e[39m\n");							\
	} while(0)

/**
 * Segregated Witness: 
 * 	Transaction Signature Verification for Version 0 Witness Program
 * 	https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki

A new transaction digest algorithm is defined, but only applicable to sigops in version 0 witness program:

  Double SHA256 of the serialization of:
     1. nVersion of the transaction (4-byte little endian)
     2. hashPrevouts (32-byte hash)
     3. hashSequence (32-byte hash)
     4. outpoint (32-byte hash + 4-byte little endian) 
     5. scriptCode of the input (serialized as scripts inside CTxOuts)
     6. value of the output spent by this input (8-byte little endian)
     7. nSequence of the input (4-byte little endian)
     8. hashOutputs (32-byte hash)
     9. nLocktime of the transaction (4-byte little endian)
    10. sighash type of the signature (4-byte little endian)

**/

static ssize_t segwit_v0_generate_preimage(const satoshi_tx_t * tx, 
	int cur_index, 	// current txin index
	uint32_t hash_type,
	const satoshi_txout_t * utxo, // prevout
	unsigned char ** p_image)
{
	satoshi_txin_t * cur_txin = &tx->txins[cur_index];
	ssize_t cb_redeem_scripts = varstr_size(cur_txin->redeem_scripts);
	
	ssize_t cb_image = sizeof(uint32_t)		// 1. nVersion of the transaction (4-byte little endian)
		+ sizeof(uint256_t)	// 2. hashPrevouts (32-byte hash)
		+ sizeof(uint256_t)	// 3. hashSequence (32-byte hash)
		+ sizeof(satoshi_outpoint_t)	// 4. outpoint (32-byte hash + 4-byte little endian) 
		+ cb_redeem_scripts	//  5. scriptCode of the input (serialized as scripts inside CTxOuts)
		+ sizeof(int64_t) // 6. value of the output spent by this input (8-byte little endian)
		+ sizeof(uint32_t) // 7. nSequence of the input (4-byte little endian)
		+ sizeof(uint256_t) // 8. hashOutputs (32-byte hash)
		+ sizeof(uint32_t) // 9. nLocktime of the transaction (4-byte little endian)
		+ sizeof(uint32_t); // 10. sighash type of the signature (4-byte little endian)
	
	if(NULL == p_image) return cb_image;	// return buffer size
	
	unsigned char * preimage = *p_image;
	if(NULL == preimage)
	{
		preimage = malloc(cb_image);
		assert(preimage);
		*p_image = preimage;
	}
	assert(preimage);
	
	sha256_ctx_t sha[1];
	unsigned char hash[32];
	unsigned char * p = preimage;
	unsigned char * p_end = p + cb_image;
	// 1. nVersion of the transaction (4-byte little endian)
	*(uint32_t *)p = tx->version;
	debug_dump("version", p, 4);
	p += sizeof(uint32_t);
	
    // 2. hashPrevouts (32-byte hash)	( sha256(sha256(outpoints[])) )
    const satoshi_txin_t * txins = tx->txins;
    sha256_init(sha);
    for(ssize_t i = 0; i < tx->txin_count; ++i)
    {
		debug_dump("  --> hash outpoint: ", &txins[i].outpoint, sizeof(satoshi_outpoint_t));
		sha256_update(sha, (unsigned char *)&txins[i].outpoint, sizeof(satoshi_outpoint_t));
	}
	sha256_final(sha, hash);
	sha256_init(sha);
	sha256_update(sha, hash, 32);
	sha256_final(sha, p);	// write hash256() result 
	
	debug_dump("hashPrevouts", p, 32);
	p += sizeof(uint256_t);
    
    // 3. hashSequence (32-byte hash)
    sha256_init(sha);
    for(ssize_t i = 0; i < tx->txin_count; ++i)
    {
		sha256_update(sha, (unsigned char *)&txins[i].sequence, sizeof(uint32_t));
	}
	sha256_final(sha, hash);
	sha256_init(sha);
	sha256_update(sha, hash, 32);
	sha256_final(sha, p);	// write hash256() result 
	
	debug_dump("hashSequence", p, 32);
	p += sizeof(uint256_t);
	
   //  4. outpoint (32-byte hash + 4-byte little endian) 
   memcpy(p, &txins[cur_index].outpoint, sizeof(satoshi_outpoint_t));
   p += sizeof(satoshi_outpoint_t);
    
   //  5. scriptCode of the input (serialized as scripts inside CTxOuts)
   memcpy(p, cur_txin->redeem_scripts, cb_redeem_scripts);
   p += cb_redeem_scripts;
   
   //  6. value of the output spent by this input (8-byte little endian)
   *(int64_t *)p = utxo->value;
   debug_dump("value", p, 8);
   p += sizeof(int64_t);
   
   //  7. nSequence of the input (4-byte little endian)
   *(uint32_t *)p = txins[cur_index].sequence;
   debug_dump("sequence", p, 4);
   p += sizeof(uint32_t);

   //  8. hashOutputs (32-byte hash)
	const satoshi_txout_t * txouts = tx->txouts;
	sha256_init(sha);
	for(ssize_t i = 0; i < tx->txout_count; ++i)
	{
		sha256_update(sha, (unsigned char *)&txouts[i].value, sizeof(int64_t));
		ssize_t vstr_size = varstr_size(txouts[i].scripts);
		assert(vstr_size > 0);
		sha256_update(sha, (unsigned char *)txouts[i].scripts, vstr_size);
	}
	sha256_final(sha, hash);
	sha256_init(sha);
	sha256_update(sha, hash, 32);
	sha256_final(sha, p);	// write hash256() result 
	
	debug_dump("hashOutputs", p, 32);
	p += 32;
	
    // 9. nLocktime of the transaction (4-byte little endian)
    *(uint32_t *)p = tx->lock_time;
    debug_dump("lock_time", p, 4);
    p += sizeof(uint32_t);
    
    // 10. sighash type of the signature (4-byte little endian)
    
    assert( (hash_type & 0x7f) >= 1 // satoshi_tx_sighash_all
		&& (hash_type & 0x7f) <= 3	// satoshi_tx_sighash_single 
	);
	
#if defined(_DEBUG) && defined(_TEST_SATOSHI_TX)
	assert( hash_type == satoshi_tx_sighash_all); // test sighash_all only
#endif

	*(uint32_t *)p = hash_type;
	debug_dump("hash_type", p, 4);
	p += sizeof(uint32_t);
	
	assert(p == p_end);
	return cb_image;
}

int segwit_v0_tx_get_digest(const satoshi_tx_t * tx, 
	int cur_index, 		// txin index
	uint32_t hash_type,
	const satoshi_txout_t * utxo, // prevout
	uint256_t * hash
) ///< @deprecated
{
	unsigned char * preimage = NULL;
	ssize_t cb_image = segwit_v0_generate_preimage(tx, cur_index, hash_type, utxo, &preimage);
	assert(cb_image > 0 && preimage);
	
	debug_printf("preimage length: %ld", (long)cb_image);
	
	hash256(preimage, cb_image, (unsigned char *)hash);
	free(preimage);
	return 0;
}

int satoshi_tx_get_digest(
	satoshi_tx_t * tx, 
	int txin_index, 
	uint32_t hash_type,
	const satoshi_txout_t * utxo,
	uint256_t * hash)	///< @deprecated
{
	if(tx->has_flag && tx->flag[0] == 0 && tx->flag[1] == 1) // segwit_v0
	{
		return segwit_v0_tx_get_digest(tx, txin_index, hash_type, utxo, hash);
	}

	satoshi_txin_t * txins = (satoshi_txin_t *)tx->txins;
	assert(txins);
	
	varstr_t * scripts_backup = txins[txin_index].scripts;	// save the pointer of cur_txin.scripts 
	
	// replace current txin's scripts with redeem_scripts (p2sh) or utxo->pkscripts (p2phk)
	if(txins[txin_index].is_p2sh) { 
		txins[txin_index].scripts = txins->redeem_scripts; 
	}else { 
		txins[txin_index].scripts = utxo->scripts;
	}
	assert(txins[txin_index].scripts);
	
	for(ssize_t i = 0; i < tx->txin_count; ++i)
	{
		// set all txins's script length to zero except current txin
		if(i != txin_index) varint_set((varint_t *)txins[i].scripts, 0);
	}
	
	unsigned char * preimage = NULL;
	ssize_t cb_image = satoshi_tx_serialize(tx, NULL);	// get buffer size
	assert(cb_image > 0);
	preimage = malloc(cb_image + sizeof(uint32_t));	// preimage | hash_type
	assert(preimage);
	ssize_t cb = satoshi_tx_serialize(tx, &preimage);
	assert(cb == cb_image);
	
	*(uint32_t *)(preimage + cb_image) = hash_type;
	hash256(preimage, cb_image + sizeof(uint32_t), (unsigned char *)hash);
	free(preimage);

	// restore scripts of txins
	txins[txin_index].scripts = scripts_backup;
	
	for(ssize_t i = 0; i < tx->txin_count; ++i)
	{
		// restore all txins's script length 
		if(i != txin_index) varint_set((varint_t *)txins[i].scripts, txins[i].cb_scripts);
	}

	return 0;
}

satoshi_rawtx_t * satoshi_rawtx_attach_segwit_tx(satoshi_rawtx_t * rawtx, satoshi_tx_t * tx);
int segwit_utxo_get_digest(satoshi_rawtx_t * rawtx, 
	ssize_t cur_index,
	uint32_t hash_type,
	const satoshi_txout_t * utxo,
	uint256_t * digest);

int satoshi_utxo_get_digest(satoshi_rawtx_t * rawtx, 
	ssize_t cur_index, 
	uint32_t hash_type,
	const satoshi_txout_t * utxo,
	uint256_t * hash);
	
int satoshi_rawtx_get_digest(satoshi_rawtx_t * rawtx, 
		ssize_t cur_index, // current txin index
		uint32_t hash_type, 
		const satoshi_txout_t * utxo,
		uint256_t * digest)
{
	assert(utxo);
	
	int flags = utxo->flags & satoshi_txout_type_masks;
	int p2sh_segwit_flags = utxo->flags & satoshi_txout_type_p2sh_segwit_flags;
	
	if(p2sh_segwit_flags || flags == satoshi_txout_type_segwit) {
		return segwit_utxo_get_digest(rawtx, cur_index, hash_type, utxo, digest);
	}
	if(flags == satoshi_txout_type_legacy)
	{
		return satoshi_utxo_get_digest(rawtx, cur_index, hash_type, utxo, digest);
	}
	return -1;
}

satoshi_rawtx_t * satoshi_rawtx_attach(satoshi_rawtx_t * rawtx, satoshi_tx_t * tx)
{
	assert(tx && tx->txin_count > 0 && tx->txins);
	if(tx->has_flag) {
		satoshi_rawtx_attach_segwit_tx(rawtx, tx);	// add segwit-tx support
	}
	
	if(NULL == rawtx) rawtx = calloc(1, sizeof(*rawtx));
	assert(rawtx);
	
	rawtx->tx = tx;
	rawtx->get_digest = satoshi_rawtx_get_digest;
	
	sha256_ctx_t * sha = &rawtx->sha[0];
	sha256_init(sha);
	rawtx->last_hashed_txin_index = 0;
	
	// init raw_txins' script
	satoshi_txin_t * raw_txins = calloc(tx->txin_count, sizeof(*raw_txins));
	assert(raw_txins);
	rawtx->txins = raw_txins;
	
	// init raw txins for legacy tx
	for(ssize_t i = 0; i < tx->txin_count; ++i)
	{
		raw_txins[i].outpoint = tx->txins[i].outpoint;
		raw_txins[i].scripts = (varstr_t *)varstr_empty; 
		raw_txins[i].sequence = tx->txins[i].sequence;
	}
	
	// pre-hash tx->verison and tx->txin_count
	unsigned char vint[9] = { 0 };
	sha256_update(sha, (unsigned char *)&tx->version, sizeof(int32_t));
	
	varint_set((varint_t *)vint, tx->txin_count);
	sha256_update(sha, vint, varint_size((varint_t *)vint));
	
	// TODO: pre-hash outpoint of the first txin
	// sha256_update(rawtx->sha, (unsigned char *)&rawtx->txins[0].outpoint, sizeof(satoshi_outpoint_t));
	
	return rawtx;
}

void satoshi_rawtx_detach(satoshi_rawtx_t * rawtx)
{
	if(NULL == rawtx) return;
	
	// restore all txins' script_length
	if(rawtx->txins) {
		free(rawtx->txins);
		rawtx->txins = NULL;
	}
	
	rawtx->tx = NULL;
	rawtx->last_hashed_txin_index = -1;
	memset(rawtx->txouts_hash, 0, sizeof(rawtx->txouts_hash));
	
	sha256_init(&rawtx->sha[0]);
	sha256_init(&rawtx->sha[1]);
	return;
}

int satoshi_utxo_get_digest(satoshi_rawtx_t * rawtx, 
	ssize_t cur_index, 
	uint32_t hash_type,
	const satoshi_txout_t * utxo,
	uint256_t * hash)
{
	assert(rawtx && rawtx->tx);
	satoshi_tx_t * tx = rawtx->tx;
	
	assert(tx->txins && cur_index >= 0 && cur_index < tx->txin_count && hash);
	sha256_ctx_t sha[1];

	
	assert(tx->txins && cur_index >= 0 && cur_index < tx->txin_count);
	assert(rawtx->last_hashed_txin_index < tx->txin_count);
		
	uint32_t anyone_canpay = hash_type & satoshi_tx_sighash_anyone_can_pay;
	hash_type &= ~satoshi_tx_sighash_anyone_can_pay;
	
	
	satoshi_txin_t * raw_txins = rawtx->txins;
	satoshi_txin_t * cur_txin = &tx->txins[cur_index];
	unsigned char vint[9] = { 0 };
	

	if(rawtx->last_hashed_txin_index < 0) {
		rawtx->last_hashed_txin_index = 0;
	}
	assert(cur_index >= rawtx->last_hashed_txin_index);	// pre-hashed index, (from tx.begin() to the end of txins[cur_index].outpoint) 
	
	// set redeem_scripts code (pk_scripts)
	// discard data before last executed op_codeseperator
	varstr_t * redeem_scripts = satoshi_txin_get_redeem_scripts(cur_txin);
	raw_txins[cur_index].scripts = redeem_scripts; // unify all modes (p2pk, p2phk, p2sh, p2wphk, p2wsh ...)

	// pre-hash txins when needed
	if(anyone_canpay)	{ // sign only current txin, do not use the states of rawtx's sha_ctx
		sha256_init(sha);
		sha256_update(sha, (unsigned char *)&tx->version, sizeof(int32_t));
		
		// ??? hash txin_count ???
		//~ varint_set((varint_t *)vint, tx->txin_count);
		//~ sha256_update(sha, (unsigned char *)vint, varint_size((varint_t *)vint));
		sha256_update(sha, (unsigned char *)&raw_txins[cur_index].outpoint, sizeof(raw_txins[cur_index].outpoint));
		sha256_update(sha, (unsigned char *)raw_txins[cur_index].scripts, varstr_size(raw_txins[cur_index].scripts));
		sha256_update(sha, (unsigned char *)&raw_txins[cur_index].sequence, sizeof(uint32_t));
	}
	else{		
		ssize_t i = rawtx->last_hashed_txin_index;
		assert(i >= 0 && i < tx->txin_count);
		assert(raw_txins[i].scripts);	// tx should be attached by satoshi_rawtx_attach() function
		
		for(; i < cur_index; ++i)
		{
			sha256_update(rawtx->sha, (unsigned char *)&raw_txins[i].outpoint, sizeof(raw_txins[i].outpoint));
			sha256_update(rawtx->sha, (unsigned char *)raw_txins[i].scripts, varstr_size(raw_txins[i].scripts)); 
			sha256_update(rawtx->sha, (unsigned char *)&raw_txins[i].sequence, sizeof(uint32_t));
		}
		assert(i == cur_index);
		rawtx->last_hashed_txin_index = cur_index - 1;

		// copy pre-hashed sha context 
		memcpy(sha, rawtx->sha, sizeof(sha));
		

		// hash the rest txins 
		for(; i < tx->txin_count; ++i)
		{
			sha256_update(sha, (unsigned char *)&raw_txins[i].outpoint, sizeof(raw_txins[i].outpoint));
			sha256_update(sha, (unsigned char *)raw_txins[i].scripts, varstr_size(raw_txins[i].scripts));
			sha256_update(sha, (unsigned char *)&raw_txins[i].sequence, sizeof(uint32_t));
			
			dump_line("raw_txin->scripts: ", raw_txins[i].scripts, varstr_size(raw_txins[i].scripts));
		}
	}
	// restore raw_txin's scripts
	raw_txins[cur_index].scripts = (varstr_t *)varstr_empty;
	varstr_free(redeem_scripts);
	
	
	// hash txouts
	if(hash_type == satoshi_tx_sighash_all)
	{
		varint_set((varint_t *)vint, tx->txout_count);
		sha256_update(sha, vint, varint_size((varint_t *)vint));
		
		satoshi_txout_t * txouts = tx->txouts;
		assert(txouts);
		for(ssize_t i = 0; i < tx->txout_count; ++i)
		{
			sha256_update(sha, (unsigned char *)&txouts[i].value, sizeof(txouts[i].value));
			sha256_update(sha, (unsigned char *)txouts[i].scripts, varstr_size(txouts[i].scripts));
		}
	}else if(hash_type == satoshi_tx_sighash_single)
	{
		if(cur_index >= tx->txout_count) return -1;
		assert(cur_index < tx->txout_count);
		
		satoshi_txout_t * cur_txout = &tx->txouts[cur_index];
		sha256_update(sha, (unsigned char *)&cur_txout->value, sizeof(cur_txout->value));
		sha256_update(sha, (unsigned char *)cur_txout->scripts, varstr_size(cur_txout->scripts));
	}
		
	// hash 'lock_time'
	sha256_update(sha, (unsigned char *)&tx->lock_time, sizeof(tx->lock_time));
	
	// hash 'sighash_type'
	hash_type |= anyone_canpay;
	sha256_update(sha, (unsigned char *)&hash_type, sizeof(uint32_t));

	sha256_final(sha, (unsigned char *)hash);
	
	// double hash
	sha256_init(sha);
	sha256_update(sha, (unsigned char *)hash, 32);
	sha256_final(sha, (unsigned char *)hash);
	
	return 0;
}

void satoshi_tx_dump(const satoshi_tx_t * tx)
{
	assert(tx && tx->txin_count && tx->txins && tx->txout_count && tx->txouts);
	
	printf("================= dump tx: %p ======================\n", tx);
	printf("version: %u\n", tx->version);
	if(tx->has_flag) 
	{
		printf("witness_flags: %.2x%.2x\n", tx->flag[0], tx->flag[1]);
	}
	
	printf("== txins_count: %Zd ==\n", tx->txin_count);
	for(ssize_t i = 0; i < tx->txin_count; ++i)
	{
		const satoshi_txin_t * txin = &tx->txins[i];
		printf("\t== txins[%d] ==\n", (int)i);
		printf("\t" "outpoint: "); dump(&txin->outpoint.prev_hash, 32); printf(" %.8d\n", (int)txin->outpoint.index);
		printf("\t" "sig_scripts: (cb=%d)", (int)txin->cb_scripts); 
			dump(varstr_getdata_ptr(txin->scripts), txin->cb_scripts); printf("\n");
		
		if(txin->signatures)
		{
			printf("\t" "-- num_signatures: %Zd\n", txin->num_signatures);
			for(ssize_t i = 0; i < txin->num_signatures; ++i)
			{
				printf("\t\tsig[%d]: ", (int)i); 
				dump(txin->signatures[i], varstr_size(txin->signatures[i]));
				printf("\n");
			}
		}
		
		if(txin->redeem_scripts)
		{
			ssize_t cb_scripts = varstr_length(txin->redeem_scripts);
			printf("\t-- redeem_scripts: (cb=%d): ", (int)cb_scripts);
			dump(varstr_getdata_ptr(txin->redeem_scripts), cb_scripts); 
		}
		
		
		printf("\t" "sequence: "); dump(&txin->sequence, 4); printf("\n");
	}
	printf("== txouts_count: %Zd ==\n", tx->txout_count);
	for(ssize_t i = 0; i < tx->txout_count; ++i)
	{
		const satoshi_txout_t * txout = &tx->txouts[i];
		printf("\t== txouts[%d] ==\n", (int)i);
		printf("\t" "value: %" PRIi64 "(", txout->value); dump(&txout->value, 8); printf(")\n");
		ssize_t cb_scripts = varstr_length(txout->scripts);
		printf("\t" "pk_scripts: (cb=%d)", (int)cb_scripts); dump(varstr_getdata_ptr(txout->scripts), cb_scripts); printf("\n");
	}
	
	if(tx->has_flag && tx->witnesses)
	{
		printf("witnesses: count = %Zd, bytes = %Zd\n", tx->txin_count, tx->cb_witnesses);
		bitcoin_tx_witness_t * witnesses = tx->witnesses;
		assert(witnesses);
		
		for(ssize_t i = 0; i < tx->txin_count; ++i)
		{
			printf("\t== witnesses[%Zd] ==\n", i);
			ssize_t num_items = witnesses[i].num_items;
			printf("\t" "num_items: %Zd\n", num_items);
			if(num_items > 0)
			{
				varstr_t ** items = witnesses[i].items;
				assert(items);
				
				for(ssize_t ii = 0; ii < num_items; ++ii)
				{
					printf("\t  ->"); dump(items[ii], varstr_size(items[ii])); printf("\n");
				}
			}
		}
	}
	printf("locktime: "); dump(&tx->lock_time, 4); printf("\n");
}


/**
 * set p2pk or p2phk or p2wphk txin's redeem scripts
 * 
 * @deprecated
 */
static inline varstr_t * get_p2wpkh_redeem_scripts(const satoshi_txout_t * utxo)
{
	static const unsigned char redeem_scripts_template[] = {
		[0] = 0x19,
		[1] = satoshi_script_opcode_op_dup,
		[2] = satoshi_script_opcode_op_hash160,
		[3] = 20,	// h160 size
		// [4] .. [23]: hash160 result
		[24] = satoshi_script_opcode_op_equalverify,
		[25] = satoshi_script_opcode_op_checksig
	};
	
	const unsigned char * scripts_data = varstr_getdata_ptr(utxo->scripts);
	assert(scripts_data);
	// check_version
	uint8_t segwit_version = *scripts_data++;
	assert(segwit_version == 0);	// only support segwit_v0
	
	uint8_t data_size = *scripts_data++;
	assert(data_size == 20);
	assert(varstr_length(utxo->scripts) == 0x16);
	
	
	unsigned char * redeem_scripts = calloc(1, sizeof(redeem_scripts_template));
	assert(redeem_scripts);
	memcpy(redeem_scripts, redeem_scripts_template, sizeof(redeem_scripts_template));
	
	memcpy(&redeem_scripts[4], scripts_data, 20); // copy h160 data
	return (varstr_t *)redeem_scripts;
}

/**************************************************************************************
 * TEST Module
**************************************************************************************/
#if defined(_TEST_SATOSHI_TX) && defined(_STAND_ALONE)

int test_copy_sha_ctx();
int test_p2wpkh();
int test_p2sh();
int verify_p2sh();

int test_segwit_v0();

int main(int argc, char ** argv)
{
//	test_copy_sha_ctx(argc, argv);
//	test_p2wpkh(argc, argv);
	
//	test_p2sh(argc, argv);
	
	//~ verify_p2sh(argc, argv);
	
	test_segwit_v0(argc, argv);
	return 0;
}

/*************************************************
 * test_rawtx
*************************************************/


int satoshi_tx_add_inputs(satoshi_tx_t * tx,
	ssize_t count,
	const satoshi_outpoint_t outpoints[],
	uint32_t sequences[]
)
{
	assert(tx && count > 0 && outpoints);
	
	satoshi_txin_t * txins = realloc(tx->txins, (tx->txin_count + count) * sizeof(*txins));
	assert(txins);
	memset(txins + tx->txin_count, 0, count * sizeof(*txins));
	tx->txins = txins;
	
	tx->txin_count += count;
	txins += count;	// move to new item's start_pos
	for(ssize_t i = 0; i < count; ++i)
	{
		txins[i].outpoint = outpoints[i];
		txins[i].sequence = sequences?sequences[i]:0xffffffff;
	}
	
	return 0;
}

int satoshi_tx_add_outputs(satoshi_tx_t * tx, 
	ssize_t count,
	const int64_t values[],
	varstr_t * scripts[]
)
{
	assert(tx && count > 0 && values && scripts);
	
	satoshi_txout_t * txouts = realloc(tx->txouts, (tx->txout_count + count) * sizeof(*txouts));
	assert(txouts);
	memset(txouts + tx->txout_count, 0, count * sizeof(*txouts));
	tx->txouts = txouts;

	tx->txout_count += count;
	txouts += count;	// move to new item's start_pos
	for(ssize_t i = 0; i < count; ++i)
	{
		txouts[i].value = values[i];
		txouts[i].scripts = varstr_clone(scripts[i]);
	}
	return 0;
}

static inline crypto_privkey_t * import_privkey_from_string(crypto_context_t * crypto, const char * secdata_hex)
{
	assert(crypto && secdata_hex);
	
	int cb_hex = strlen(secdata_hex);
	if(cb_hex != 64) return NULL;
	
	unsigned char buffer[32] = { 0 };
	void * secdata = buffer;
	ssize_t cb = hex2bin(secdata_hex, cb_hex, &secdata);
	assert(cb == 32 && secdata == buffer);
	
	crypto_privkey_t * privkey = crypto_privkey_import(crypto, secdata, cb);
	assert(privkey);
	
	// clear sensitive data
	memset(buffer, 0, 32);
	return privkey;
}

// verify p2sh 
int test_p2sh(int argc, char ** argv)	
{
	static const char * tx_hex[2] = { 
	// txid = LE"a0f1aaa2fb4582c89e0511df0374a5a2833bf95f7314f4a51b55b7b71e90ce0f"
	"01000000"
	"01"
		"4ce7153d92e3b24d9eea31f8cf391c3fb4c39f7742b341b2d36c6367e754647400000000"
		"6c"
			"49"
				"3046"
					"022100c554360535b2ad3b1cb1b966a87807f7a7e45fa485348d662a1e7413dced8471"
					"022100d6bcfc4385b7ac41ca3968a73c4a28e38879192c3db1286b36e59ec9fce52bbd"
				"01"
			"21"
				"03c96e3a9e63986801269d5f278246ed7cdc2d392595d0a25b102e04598f4b4fa9"
		"ffffffff"
	"02"
		"cb871a0000000000" "1976a914c02ebae82202119f23f330781ff26b303edb7dbd88ac"
		"8096980000000000" "17a914748284390f9e263a4b766a75d0633c50426eb87587"
	"00000000",
	
	// txid = LE"4d8eabfc8e6c266fb0ccd815d37dd69246da634df0effd5a5c922e4ec37880f6"
	"01000000"
	"03"
		"a5ee1a0fd80dfbc3142df136ab56e082b799c13aa977c048bdf8f61bd158652c" "00000000"
		"6b"
			"48"
				"3045"
					"02203b0160de302cded63589a88214fe499a25aa1d86a2ea09129945cd632476a12c"
					"022100c77727daf0718307e184d55df620510cf96d4b5814ae3258519c0482c1ca82fa"
				"01"
			"21"
				"024f4102c1f1cf662bf99f2b034eb03edd4e6c96793cb9445ff519aab580649120"
		"ffffffff"
		"0fce901eb7b7551ba5f414735ff93b83a2a57403df11059ec88245fba2aaf1a0" "00000000"  // tx[0].txouts[0]
		"6a"
			"47"
				"3044"
					"02204089adb8a1de1a9e22aa43b94d54f1e54dc9bea745d57df1a633e03dd9ede3c2"
					"022037d1e53e911ed7212186028f2e085f70524930e22eb6184af090ba4ab779a5b9"
				"01"
			"21"
				"030644cb394bf381dbec91680bdf1be1986ad93cfb35603697353199fb285a119e"
		"ffffffff"
		"0fce901eb7b7551ba5f414735ff93b83a2a57403df11059ec88245fba2aaf1a0" "01000000" // tx[0].txouts[1]
		"93"
			"00"	// p2sh flag
			"49"
				"3046"
					"022100a07b2821f96658c938fa9c68950af0e69f3b2ce5f8258b3a6ad254d4bc73e11e"
					"022100e82fab8df3f7e7a28e91b3609f91e8ebf663af3a4dc2fd2abd954301a5da67e7"
				"01"
			"47"
				"51"	// OP_1, need at least 1 signature
				"21022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e"		// pubkey 1
				"2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c0"		// pubkey 2
				"52"	// 2 pubkeys
				"ae"	// OP_CHECKMULTISIG
		"ffffffff"
	"02"
		"a3b81b0000000000" "1976a914ea00917f128f569cbdf79da5efcd9001671ab52c88ac"
		"8096980000000000" "1976a9143dec0ead289be1afa8da127a7dbdd425a05e25f688ac"
	"00000000"
	};
	
	unsigned char * tx_data[2] = { NULL };
	ssize_t tx_sizes[2] = { 0 };
	
	satoshi_tx_t tx[2];
	memset(tx, 0, sizeof(tx));
	
	for(int i = 0; i < 2; ++i)
	{
		tx_sizes[i] = hex2bin(tx_hex[i], -1, (void **)&tx_data[i]);
		assert(tx_sizes[i] > 0);
		
		ssize_t cb = satoshi_tx_parse(&tx[i], tx_sizes[i], tx_data[i]);
		assert(cb == tx_sizes[i]);
		
		printf("tx[%d]: ", i);
		satoshi_tx_dump(&tx[i]);
	}
	
	assert(tx[0].txout_count == 2);
	assert(tx[1].txin_count == 3);
	
	satoshi_txin_t * txins = tx[1].txins;
	
	crypto_context_t * crypto = crypto_context_init(NULL, crypto_backend_libsecp256, NULL);
	satoshi_script_t * scripts = satoshi_script_init(NULL, crypto, NULL);
	assert(crypto && scripts);
	
	scripts->attach_tx(scripts, &tx[1]);
	
	/**
	 *  tests:
	 * 	 1. p2pkh:  tx[0].txouts[0]  -->  tx[1].txins[1]
	 *   2. p2sh:   tx[0].txouts[1]  -->  tx[1].txins[2]
	 */
	// 1. test p2pkh:  utxo = tx[0].txouts[0],  txin = tx[1].txins[1]
	ssize_t txin_index = 1;
	satoshi_txout_t * utxo = &tx[0].txouts[0];
	scripts->set_txin_info(scripts, txin_index, &tx[0].txouts[0]);
	ssize_t cb_scripts = varstr_length(txins[txin_index].scripts);
	
	ssize_t cb = scripts->parse(scripts, 
		satoshi_tx_script_type_txin,	// parse txin
		varstr_getdata_ptr(txins[txin_index].scripts), 
		cb_scripts);
	assert(cb == cb_scripts);
	
	cb_scripts = varstr_length(utxo->scripts);
	cb = scripts->parse(scripts,
		satoshi_tx_script_type_txout, // parse txout
		varstr_getdata_ptr(utxo->scripts),
		cb_scripts);
	assert(cb == cb_scripts);
	
	
	// 2. test p2sh:
	utxo = &tx[0].txouts[1];
	txin_index = 2;
	scripts->set_txin_info(scripts, txin_index, utxo);
	
	cb_scripts = varstr_length(txins[txin_index].scripts);
	cb = scripts->parse(scripts, 
		satoshi_tx_script_type_txin,	// parse txin
		varstr_getdata_ptr(txins[txin_index].scripts), cb_scripts);
	assert(cb == cb_scripts);
	
	cb_scripts = varstr_length(utxo->scripts);
	cb = scripts->parse(scripts,
		satoshi_tx_script_type_txout, // parse txout
		varstr_getdata_ptr(utxo->scripts),
		cb_scripts);
	assert(cb == cb_scripts);
	
	
	
	// cleanup
	for(int i = 0; i < 2; ++i) {
		satoshi_tx_cleanup(&tx[i]);
		free(tx_data[i]);
	}
	
	satoshi_script_cleanup(scripts);
	free(scripts);
	
	crypto_context_cleanup(crypto);
	free(crypto);

	return 0;
}

int verify_p2sh(int argc, char ** argv)
{
	/*
	 *  https://en.bitcoin.it/wiki/Pay_to_script_hash
	 * Example
	 * 	tx[0] : txid = (LE)40eee3ae1760e3a8532263678cdf64569e6ad06abc133af64f735e52562bccc8 
	 *		paid to P2SH address 3P14159f73E4gFr7JterCCQh9QjiTjiZrG. 
	 * 
	 * 	tx[1]: txid = (LE)7edb32d4ffd7a385b763c7a8e56b6358bcd729e747290624e18acdbe6209fc45 
	 * 		which spends that output
	*/
	
	static const char * tx_data_hex[2] = {
		[0] = "01000000"
		"01"
			"da75479f893cccfaa8e4558b28ec7cb4309954389f251f2212eabad7d7fda34200000000"
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
			"301b0f0000000000" "17a914e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a87"
		"00000000",
		
		[1] = "01000000"
		"01"
			"c8cc2b56525e734ff63a13bc6ad06a9e5664df8c67632253a8e36017aee3ee4000000000"
			"90"
				"00"
				"48"
					"3045"
						"022100ad0851c69dd756b45190b5a8e97cb4ac3c2b0fa2f2aae23aed6ca97ab33bf883"
						"02200b248593abc1259512793e7dea61036c601775ebb23640a0120b0dba2c34b790"
					"01"
				"45"
					"51"
					"41" "042f90074d7a5bf30c72cf3a8dfd1381bdbd30407010e878f3a11269d5f74a58788505cdca22ea6eab7cfb40dc0e07aba200424ab0d79122a653ad0c7ec9896bdf"
					"51"
					"ae"
			"feffffff"
		"01"
			"20f40e0000000000" "1976a9141d30342095961d951d306845ef98ac08474b36a088ac"
		"a7270400"
	};
	
	unsigned char * tx_data[2] = { NULL };
	ssize_t tx_sizes[2] = { 0 };
	satoshi_tx_t tx[2];
	memset(tx, 0, sizeof(tx));
	
	for(int i = 0; i < 2; ++i)
	{
		tx_sizes[i] = hex2bin(tx_data_hex[i], -1, (void **)&tx_data[i]);
		assert(tx_sizes[i] > 0);
	
		ssize_t cb = satoshi_tx_parse(&tx[i], tx_sizes[i], tx_data[i]);
		assert(cb == tx_sizes[i]);
		
		satoshi_tx_dump(&tx[i]);
	}
	
	crypto_context_t * crypto = crypto_context_init(NULL, crypto_backend_libsecp256, NULL);
	assert(crypto);
	
	uint256_t digest;
	//~ unsigned char * preimage = NULL;
	//~ ssize_t cb_preimage = hex2bin("01000000"
		//~ "01"
			//~ "c8cc2b56525e734ff63a13bc6ad06a9e5664df8c67632253a8e36017aee3ee4000000000"
			//~ "45"
				//~ "51"
				//~ "41" "042f90074d7a5bf30c72cf3a8dfd1381bdbd30407010e878f3a11269d5f74a58788505cdca22ea6eab7cfb40dc0e07aba200424ab0d79122a653ad0c7ec9896bdf"
				//~ "51"
				//~ "ae"
			//~ "feffffff"
		//~ "01"
			//~ "20f40e0000000000" "1976a9141d30342095961d951d306845ef98ac08474b36a088ac"
		//~ "a7270400"
		//~ "01000000",
		//~ -1,
		//~ (void ** )&preimage);
	//~ assert(preimage && cb_preimage > 0);
	//~ hash256(preimage, cb_preimage, (unsigned char *)&digest);
	//~ dump_line("digest: ", &digest, 32);
	
	satoshi_txout_t * utxo = &tx[0].txouts[0];
	/**
	 * manual set txins[0].redeem_scripts for testing 
	 * ( satoshi_script->parse() is not introduced here)
	 */
	tx[1].txins[0].is_p2sh = 1;
	hex2bin(
		"45"
		"51"
		"41" "042f90074d7a5bf30c72cf3a8dfd1381bdbd30407010e878f3a11269d5f74a58788505cdca22ea6eab7cfb40dc0e07aba200424ab0d79122a653ad0c7ec9896bdf"
		"51"
		"ae",
		-1,
		(void **)&tx[1].txins[0].redeem_scripts);
		
	uint256_t hash[1];
	satoshi_tx_get_digest(&tx[1], 0, 1, utxo, hash);
	dump_line("satoshi_tx_get_digest: ", hash, 32);
	
	satoshi_rawtx_t rawtx[1];
	memset(rawtx, 0, sizeof(rawtx));
	satoshi_rawtx_attach(rawtx, &tx[1]);
	
	uint32_t hash_type = 1;
	
	rawtx->get_digest(rawtx, 0, hash_type, utxo, &digest);
	dump_line("digest: ", &digest, 32);
	satoshi_rawtx_detach(rawtx);
	satoshi_txout_cleanup(utxo);
	
	int rc = 0;
	
	crypto_pubkey_t * pubkey = crypto_pubkey_import_from_string(crypto, 
		"042f90074d7a5bf30c72cf3a8dfd1381bdbd30407010e878f3a11269d5f74a58788505cdca22ea6eab7cfb40dc0e07aba200424ab0d79122a653ad0c7ec9896bdf");
	
	unsigned char * sig_der = NULL;
	ssize_t cb_sig_der = hex2bin("3045"
		"022100ad0851c69dd756b45190b5a8e97cb4ac3c2b0fa2f2aae23aed6ca97ab33bf883"
		"02200b248593abc1259512793e7dea61036c601775ebb23640a0120b0dba2c34b790",
		-1,
		(void **)&sig_der);
	assert(sig_der && cb_sig_der > 0);
	
	rc = crypto->verify(crypto, (unsigned char *)&digest, 32, 
		pubkey,
		sig_der, cb_sig_der);
	
	printf("[%s]\n", (0 == rc)?"OK":"NG");	
	assert(0 == rc);
	
	crypto_context_cleanup(crypto);
	free(crypto);
	
	return 0;
}


/*************************************************
 * test_copy_sha_ctx
*************************************************/
int test_copy_sha_ctx(int argc, char **argv)
{
	unsigned char data[100] = {1, 2, 3, 4, 5, 6, 7, 8};
	
	// test: SHA states copy
	sha256_ctx_t sha[1];
	sha256_ctx_t temp_sha[1];
	
	unsigned char hash[32];
	
	sha256_init(temp_sha);
	sha256_update(temp_sha, data, 4);
	
	
	memcpy(sha, temp_sha, sizeof(sha));
	sha256_update(sha, data + 4, 4);
	sha256_final(sha, hash);
	
	dump_line("hash1: ", hash, 32);
	
	
	memset(hash, 0, 32);
	sha256_init(sha);
	sha256_update(sha, data, 8);
	sha256_final(sha, hash);
	dump_line("hash2: ", hash, 32);
	
	
	memcpy(sha, temp_sha, sizeof(sha));
	sha256_update(sha, data + 4, 4);
	sha256_final(sha, hash);
	dump_line("hash3: ", hash, 32);
	return 0;
}
#endif
