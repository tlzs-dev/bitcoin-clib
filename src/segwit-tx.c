/*
 * segwit-tx.c
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

/***************************************************************************
  BIP: 143
  Layer: Consensus (soft fork)
  Title: Transaction Signature Verification for Version 0 Witness Program
  Author: Johnson Lau <jl2012@xbt.hk>
          Pieter Wuille <pieter.wuille@gmail.com>
  Comments-Summary: No comments yet.
  Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-0143
  Status: Final
  Type: Standards Track
  Created: 2016-01-03
  License: PD
***************************************************************************/

/***************************************************************************
Specification
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
Semantics of the original sighash types remain unchanged, except the followings:

The way of serialization is changed;
	All sighash types commit to the amount being spent by the signed input;
	FindAndDelete of the signature is not applied to the scriptCode;
	OP_CODESEPARATOR(s) after the last executed OP_CODESEPARATOR are not removed from the scriptCode 
(the last executed OP_CODESEPARATOR and any script before it are always removed);
	SINGLE does not commit to the input index. When ANYONECANPAY is not set, 
the semantics are unchanged since hashPrevouts and outpoint together implictly commit to the input index. 
	When SINGLE is used with ANYONECANPAY, omission of the index commitment allows permutation of the input-output pairs, 
as long as each pair is located at an equivalent index.
	The items 1, 4, 7, 9, 10 have the same meaning as the original algorithm. [1]
The item 5:
	For P2WPKH witness program, the scriptCode is 0x1976a914{20-byte-pubkey-hash}88ac.
	For P2WSH witness program,
		if the witnessScript does not contain any OP_CODESEPARATOR, 
		the scriptCode is the witnessScript serialized as scripts inside CTxOut.
		if the witnessScript contains any OP_CODESEPARATOR, 
		the scriptCode is the witnessScript but removing everything up to and including the last executed OP_CODESEPARATOR 
		before the signature checking opcode being executed, serialized as scripts inside CTxOut. 
		(The exact semantics is demonstrated in the examples below)
The item 6 is a 8-byte value of the amount of bitcoin spent in this input.

hashPrevouts:
If the ANYONECANPAY flag is not set, hashPrevouts is the double SHA256 of the serialization of all input outpoints;
Otherwise, hashPrevouts is a uint256 of 0x0000......0000.

hashSequence:
	If none of the ANYONECANPAY, SINGLE, NONE sighash type is set, 
hashSequence is the double SHA256 of the serialization of nSequence of all inputs;
	Otherwise, hashSequence is a uint256 of 0x0000......0000.

hashOutputs:
	If the sighash type is neither SINGLE nor NONE, hashOutputs is the double SHA256 of the serialization of 
	all output amount (8-byte little endian) with scriptPubKey (serialized as scripts inside CTxOuts);
	If sighash type is SINGLE and the input index is smaller than the number of outputs, 
	hashOutputs is the double SHA256 of the output amount with scriptPubKey of the same index as the input;
	Otherwise, hashOutputs is a uint256 of 0x0000......0000.[7]

The hashPrevouts, hashSequence, and hashOutputs calculated in an earlier verification may be reused 
in other inputs of the same transaction, so that the time complexity of the whole hashing process 
reduces from O(n2) to O(n).
***************************************************************************/

#include "crypto.h"
#include "satoshi-types.h"
#include "satoshi-tx.h"
#include "satoshi-script.h"

#include "utils.h"

// step 2.
static inline void prehash_prevouts(sha256_ctx_t * sha, ssize_t txin_count, const satoshi_txin_t * txins)
{
	if(txin_count == 0) sha256_update(sha, (unsigned char *)uint256_zero, 32);	// sighash_anyone_can_pay
	else {
		sha256_ctx_t temp_sha[1];
		unsigned char hash[32];
		sha256_init(temp_sha);
		for(ssize_t i = 0; i < txin_count; ++i)
		{
			sha256_update(temp_sha, (unsigned char *)&txins[i].outpoint, sizeof(txins[i].outpoint));
		}
		sha256_final(temp_sha, hash);
		// double hash
		sha256_init(temp_sha);
		sha256_update(temp_sha, hash, 32);
		sha256_final(temp_sha, hash);
		
		// update rawtx->sha states
		sha256_update(sha, hash, 32);
	}
	return;
}

// step 3.
static inline void prehash_sequences(sha256_ctx_t * sha, ssize_t txin_count, const satoshi_txin_t * txins)
{
	if(txin_count == 0) {
		// sighash_anyone_canpay or sighash_none or sighash_single
		sha256_update(sha, (unsigned char *)uint256_zero, 32);
	}
	else {
		sha256_ctx_t temp_sha[1];
		unsigned char hash[32];
		sha256_init(temp_sha);
		for(ssize_t i = 0; i < txin_count; ++i)
		{
			sha256_update(temp_sha, (unsigned char *)&txins[i].sequence, sizeof(txins[i].sequence));
		}
		sha256_final(temp_sha, hash);
		// double hash
		sha256_init(temp_sha);
		sha256_update(temp_sha, hash, 32);
		sha256_final(temp_sha, hash);
		
		// update rawtx->sha states
		sha256_update(sha, hash, 32);
	}
	return;
}

// step 8.
static inline void prehash_outputs(sha256_ctx_t * sha, 
	ssize_t txout_count, 
	ssize_t txin_index,	// -1(, < 0): sighash_all;  >=0: sighash_single, hash the txout with the same index of txin
	const satoshi_txout_t * txouts, 
	uint256_t * txouts_hash 	// if is_null --> update sha; else --> save current result   
)
{
	if(txout_count == 0) {
		sha256_update(sha, (unsigned char *)uint256_zero, 32);	// sighash_none
	}
	else {
		sha256_ctx_t temp_sha[1];
		unsigned char hash[32];
		sha256_init(temp_sha);
		if(txin_index < 0)	// sighash_all
		{
			for(ssize_t i = 0; i < txout_count; ++i)
			{
				sha256_update(temp_sha, (unsigned char *)&txouts[i].value, sizeof(txouts[i].value));
				sha256_update(temp_sha, (unsigned char *)txouts[i].scripts, varstr_size(txouts[i].scripts));
			}
		}else
		{
			// sighash_single
			assert(txin_index < txout_count);
			sha256_update(temp_sha, (unsigned char *)&txouts[txin_index].value, sizeof(txouts[txin_index].value));
			sha256_update(temp_sha, (unsigned char *)txouts[txin_index].scripts, varstr_size(txouts[txin_index].scripts));
		}
		sha256_final(temp_sha, hash);
		
		// double hash
		sha256_init(temp_sha);
		sha256_update(temp_sha, hash, 32);
		sha256_final(temp_sha, hash);
		
		if(txouts_hash) {	// save result for later use
			memcpy(txouts_hash, hash, 32);
		}
		else { // update sha
			sha256_update(sha, hash, 32);
		}
	}
	return;
}

int segwit_utxo_get_digest(satoshi_rawtx_t * rawtx, 
	ssize_t cur_index,
	uint32_t hash_type,
	const satoshi_txout_t * utxo, 
	uint256_t * digest)
{
	
	assert(rawtx && rawtx->tx && utxo);
	debug_printf("utxo->flag=%d, hash_type=0x%.2x", utxo->flags, hash_type);
	satoshi_tx_t * tx = rawtx->tx;
	assert(tx->txins && cur_index >= 0 && cur_index < tx->txin_count);

	sha256_ctx_t sha[1];
	unsigned char hash[32];
	
	uint32_t anyone_canpay = (hash_type & 0x80);
	hash_type &= satoshi_tx_sighash_masks;

	if(!anyone_canpay)
	{
		if(hash_type == satoshi_tx_sighash_all)	// hash_type = 0x01
		{
			// copy pre-hashed states
			memcpy(sha, &rawtx->sha[1], sizeof(sha));	// copy internal state ( common data pre-hashed )
		}else
		{
			sha256_init(sha);
			// step 1
			sha256_update(sha, (unsigned char *)&tx->version, sizeof(tx->version));
			
			// step 2
			prehash_prevouts(sha, tx->txin_count, tx->txins);
			
			// step 3
			if(hash_type == satoshi_tx_sighash_none || hash_type == satoshi_tx_sighash_single)
			{
				sha256_update(sha, (unsigned char *)uint256_zero, 32);
			}else
			{
				prehash_sequences(sha, tx->txin_count, tx->txins);
			}
		}
	}else // anyone_canpay
	{
		// there's no convenient way to simplify operation, just hash from the very begining
		sha256_init(sha);
		// step 1
		sha256_update(sha, (unsigned char *)&tx->version, sizeof(tx->version));
		
		// step 2
		sha256_update(sha, (unsigned char *)uint256_zero, 32);
		
		// step 3
		sha256_update(sha, (unsigned char *)uint256_zero, 32);
	}
	
	ssize_t cb_image = 4 + 32 + 32;	// skip pre-hashed data
	satoshi_txin_t * txins = tx->txins;
	
	// hash different parts (start from step 4)
	//  4. outpoint (32-byte hash + 4-byte little endian) 
	sha256_update(sha, (unsigned char *)&txins[cur_index].outpoint, sizeof(satoshi_outpoint_t));
	cb_image += sizeof(satoshi_outpoint_t);
	
	//  5. scriptCode of the input (serialized as scripts inside CTxOuts)
	varstr_t * redeem_scripts = satoshi_txin_get_redeem_scripts(&txins[cur_index]);
	assert(redeem_scripts);
	
	ssize_t cb_redeem_scripts = varstr_size(redeem_scripts);
	sha256_update(sha, (unsigned char *)redeem_scripts, cb_redeem_scripts);	
	cb_image += cb_redeem_scripts;
	varstr_free(redeem_scripts);
	
	//  6. value of the output spent by this input (8-byte little endian)
	sha256_update(sha, (unsigned char *)&utxo->value, sizeof(int64_t));
	cb_image += 8;
	
	//  7. nSequence of the input (4-byte little endian)
	sha256_update(sha, (unsigned char *)&txins[cur_index].sequence, sizeof(uint32_t));
	cb_image += 4;

	//  8. hashOutputs (32-byte hash)
	switch(hash_type)
	{
	case satoshi_tx_sighash_all:
		// use saved result
		sha256_update(sha, (unsigned char *)rawtx->txouts_hash, 32);
		break;
	case satoshi_tx_sighash_none:
		prehash_outputs(sha, 0, -1, NULL, NULL);
		break;
	case satoshi_tx_sighash_single:
		if(cur_index >= tx->txout_count) sha256_update(sha, (unsigned char *)uint256_zero, 32);
		else prehash_outputs(sha, tx->txout_count, cur_index, tx->txouts, NULL);
		break;
	default:
		fprintf(stderr, "[ERROR]: %s@%d::%s(): unknown hash_type %u(0x%.8x).\n",
			__FILE__, __LINE__, __FUNCTION__,
			hash_type, hash_type);
		abort();
	}
	cb_image += 32;
	
	// 9. nLocktime of the transaction (4-byte little endian)
	sha256_update(sha, (unsigned char *)&tx->lock_time, sizeof(uint32_t));
	cb_image += 4;
	
	// 10. sighash type of the signature (4-byte little endian)
	hash_type |= anyone_canpay;
	sha256_update(sha, (unsigned char *)&hash_type, sizeof(uint32_t));
	cb_image += 4;
	
	sha256_final(sha, hash);
	
	// double hash
	sha256_init(sha);
	sha256_update(sha, hash, 32);
	
	// write result
	sha256_final(sha, (unsigned char *)digest);	

	debug_dump_line("\t--> digest: ", digest, 32);
	return 0;
}

satoshi_rawtx_t * satoshi_rawtx_attach_segwit_tx(satoshi_rawtx_t * rawtx, satoshi_tx_t * tx)
{
	assert(tx->has_flag);
	assert(tx->flag[0] == 0 && tx->flag[1] == 1);	// segwit_v0 only
	assert(tx->txin_count > 0 && tx->txins);
	assert(tx->txout_count > 0 && tx->txouts);
	
	if(NULL == rawtx) rawtx = calloc(1, sizeof(*rawtx));
	assert(rawtx);
	
	rawtx->tx = tx;
	
	sha256_ctx_t * sha = &rawtx->sha[1];	
	sha256_init(sha);
	
// pre-hash step1, step2, step3
	// step 1. nVersion of the transaction (4-byte little endian)
	sha256_update(sha, (unsigned char *)&tx->version, sizeof(int32_t));
	
	// step 2. hashPrevouts (32-byte hash)	// for sighash_type_all
	prehash_prevouts(sha, tx->txin_count, tx->txins);
	
	// step 3. hashSequence (32-byte hash)
	prehash_sequences(sha, tx->txin_count, tx->txins);

	// step 8. hashOutputs (32-byte hash)
	prehash_outputs(sha, tx->txout_count, 
		-1, // sighash_all
		tx->txouts, 
		rawtx->txouts_hash	// save the result of step8 for later use
	);
	
	return rawtx;
}


/****************************************************************
 * TEST Module
 ***************************************************************/
#if defined(_TEST_SEGWIT_TX) || defined(_TEST_SATOSHI_TX)

#define test_(name) do {												\
		int rc = test_##name(argc, argv);								\
		printf("==> TEST %s: [%s]\n" 									\
			"----------------------------------------\n",				\
			#name, 														\
			(0==rc)?"\e[32mPASSED\e[39m":"\e[31mFAILED\e[39m");			\
		assert(0 == rc);												\
	} while(0)

#define AUTO_FREE_PTR __attribute__((cleanup(auto_free_ptr)))
void auto_free_ptr(void * ptr)
{
	void * p = *(void **)ptr;
	if(p)
	{
		free(p);
		*(void **)ptr = NULL;
	}
	return;
}

#define AUTO_FREE_(type) __attribute__((cleanup(auto_free_##type))) type
void auto_free_satoshi_script_t(void * ptr)
{
	satoshi_script_t * scripts = *(satoshi_script_t **)ptr;
	if(scripts)
	{
		satoshi_script_cleanup(scripts);
		free(scripts);
		*(void **)ptr = NULL;
	}
	return;
}

void auto_free_crypto_context_t(void * ptr)
{
	crypto_context_t * crypto = *(crypto_context_t **)ptr;
	if(crypto)
	{
		crypto_context_cleanup(crypto);
		free(crypto);
		*(void **)ptr = NULL;
	}
	return;
}

#define AUTO_CLEANUP_ARRAY1_(type) __attribute__((cleanup(auto_cleanup_array1_##type))) type
#define AUTO_CLEANUP_ARRAY2_(type) __attribute__((cleanup(auto_cleanup_array2_##type))) type
void auto_cleanup_array1_satoshi_tx_t(void * ptr)
{
	satoshi_tx_t * tx = ptr;
	if(tx)
	{
		satoshi_tx_cleanup(tx);
	}
	return;
}

void auto_cleanup_array1_satoshi_txout_t(void * ptr)
{
	satoshi_txout_t * txouts = ptr;
	if(txouts)
	{
		satoshi_txout_cleanup(&txouts[0]);
	}
	return;
}

void auto_cleanup_array2_satoshi_txout_t(void * ptr)
{
	satoshi_txout_t * txouts = ptr;
	if(txouts)
	{
		satoshi_txout_cleanup(&txouts[0]);
		satoshi_txout_cleanup(&txouts[1]);
	}
	return;
}


static int verify_tx(satoshi_tx_t * tx, satoshi_txout_t * utxoes)
{
	AUTO_FREE_(crypto_context_t) * crypto = crypto_context_init(NULL, crypto_backend_libsecp256, NULL);
	assert(crypto);
	AUTO_FREE_(satoshi_script_t) * scripts = satoshi_script_init(NULL, crypto, NULL);
	assert(scripts);
	
	scripts->attach_tx(scripts, tx);
	
	satoshi_txin_t * txins = tx->txins;
	int rc = 0;
	for(ssize_t i = 0; i < tx->txin_count; ++i)
	{
		varstr_t * vscripts = txins[i].scripts;
		ssize_t cb_scripts = varstr_length(vscripts);
		satoshi_txout_t * utxo = &utxoes[i];
		ssize_t cb = 0;
		
		scripts->set_txin_info(scripts, i, utxo);
		// parse txin
		if(cb_scripts > 0)	// legacy tx
		{
			cb = scripts->parse(scripts, 
				satoshi_tx_script_type_txin, 
				varstr_getdata_ptr(vscripts), cb_scripts);
			assert(cb == cb_scripts);
		}else
		{
			if(!tx->has_flag || NULL == tx->witnesses) {
				/*
				 * legacy-tx with no witnesses data, 
				 * ignore this verification for compatibility with future unknown versions
				 */
				continue;
			}
		}
		
		satoshi_script_stack_t * stack = scripts->main_stack;
		printf("\e[35m-- " "txin[%d].scripts parsed. stack status: count = %Zd" "\e[39m\n", (int)i, stack->count);
		for(ssize_t ii = 0; ii < stack->count; ++ii)
		{
			satoshi_script_data_t * sdata = stack->data[stack->count - 1 - ii];
			if(sdata->type >= satoshi_script_data_type_varstr){
				dump_line("\t data: ", sdata->data, sdata->size);
			}else 
			{
				printf("\tdata_type=%d, ", sdata->type);
				dump_line("value=(hex)", sdata->h256, sdata->size);
			}
		}
		
		// parse utxo
		
		cb_scripts = varstr_length(utxo->scripts);
		printf("\e[35m-- " "parse utxo of txins[%Zd], flags = %d, cb=%Zd ..." "\e[39m\n", i, utxo->flags, cb_scripts);
		dump_line("\t utxo: ", utxo->scripts, varstr_size(utxo->scripts));
		if(cb_scripts > 0)
		{
			cb = scripts->parse(scripts, 
				satoshi_tx_script_type_txout,
				varstr_getdata_ptr(utxo->scripts), cb_scripts);
			assert(cb == cb_scripts);
		} 
		
		printf("utxo of txin[%d] parsed. stack status: count = %Zd\n", (int)i, stack->count);
		for(ssize_t ii = 0; ii < stack->count; ++ii)
		{
			satoshi_script_data_t * sdata = stack->data[stack->count - 1 - ii];
			if(sdata->type >= satoshi_script_data_type_varstr){
				dump_line("\t data: ", sdata->data, sdata->size);
			}else 
			{
				printf("\tdata_type=%d, ", sdata->type);
				dump_line("value=(hex)", sdata->h256, sdata->size);
			}
		}
		
		rc = scripts->verify(scripts);
		assert(0 == rc);
		if(rc) break;
	}
	return rc;
}



/*
 * Segwit v0 TEST data: 
 *  https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
*/

/*
1. Native P2WPKH
The following is an unsigned transaction:
    0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000
    
    nVersion:  01000000
    txin:      02 fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f 00000000 00 eeffffff
                  ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a 01000000 00 ffffffff
    txout:     02 202cb20600000000 1976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac
                  9093510d00000000 1976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac
    nLockTime: 11000000
  
  The first input comes from an ordinary P2PK:
    scriptPubKey : 2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac value: 6.25
    private key  : bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866
    
  The second input comes from a P2WPKH witness program:
    scriptPubKey : 00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1, value: 6
    private key  : 619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9
    public key   : 025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357
    
  To sign it with a nHashType of 1 (SIGHASH_ALL):
  
  hashPrevouts:
    dSHA256(fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000)
  = 96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37
  
  hashSequence:
    dSHA256(eeffffffffffffff)
  = 52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b
  
  hashOutputs:
    dSHA256(202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac)
  = 863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5
  
  hash preimage: 0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd3752b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3bef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000001976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffff863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e51100000001000000
  
    nVersion:     01000000
    hashPrevouts: 96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37
    hashSequence: 52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b
    outpoint:     ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000
    scriptCode:   1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac
    amount:       0046c32300000000
    nSequence:    ffffffff
    hashOutputs:  863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5
    nLockTime:    11000000
    nHashType:    01000000
    
  sigHash:      c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670
  signature:    304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee
    
  The serialized signed transaction is: 01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000
  
    nVersion:  01000000
    marker:    00
    flag:      01
    txin:      02 fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f 00000000 494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01 eeffffff
                  ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a 01000000 00 ffffffff
    txout:     02 202cb20600000000 1976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac
                  9093510d00000000 1976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac
    witness    00
               02 47304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01 21025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357
    nLockTime: 11000000
*/

int test_native_p2wpkh(int argc, char ** argv)
{
// 1. Native P2WPKH
	static const int TEST_CASE = 1;
	printf("\n======== TEST %d. %s() ========\n", TEST_CASE, __FUNCTION__);
	AUTO_CLEANUP_ARRAY2_(satoshi_txout_t) utxoes[2] = {
		[0] = { .value = 625000000, .flags = 1},
		[1] = { .value = 600000000, .flags = 2}
	};
	hex2bin("23" // vstr.length 
		"2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac",
		-1, (void **)&utxoes[0].scripts);
	hex2bin("16" // vstr.length 
		"00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1",
		-1, (void **)&utxoes[1].scripts);
	
	
	// step 0. load tx
	AUTO_CLEANUP_ARRAY1_(satoshi_tx_t) tx[1] = { 0 };
	ssize_t cb = 0;
	AUTO_FREE_PTR unsigned char * tx_data = NULL;	// serialized tx data
	ssize_t cb_data = hex2bin("01000000"
		"0001"	// segwit flag
		"02"	// 2 txins
			"fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f" "00000000"
			"49"
				"48"
					"3045"	
						"0221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be"
						"022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed"
					"01"
			"eeffffff"
			"ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a" "01000000"
			"00"
			"ffffffff"
		"02"
			"202cb20600000000" "1976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac"
			"9093510d00000000" "1976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac"
		
		// witness data
		"00"	// for first txin
		"02"	// for second txin
			"47"
				"3044"
					"02203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a"
					"0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee"
				"01"
			"21"
				"025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
		"11000000", 
		-1, 
		(void **)&tx_data);
	assert(cb_data > 0 && tx_data);
	
	cb = satoshi_tx_parse(tx, cb_data, tx_data);
	assert(cb == cb_data);
	satoshi_tx_dump(tx);
	
	return verify_tx(tx, utxoes);
}

/*
2. P2SH-P2WPKH
  The following is an unsigned transaction: 0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000
  
    nVersion:  01000000
    txin:      01 db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477 01000000 00 feffffff
    txout:     02 b8b4eb0b00000000 1976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac
                  0008af2f00000000 1976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac
    nLockTime: 92040000
  
  The input comes from a P2SH-P2WPKH witness program:
    scriptPubKey : a9144733f37cf4db86fbc2efed2500b4f4e49f31202387, value: 10
    redeemScript : 001479091972186c449eb1ded22b78e40d009bdf0089
    private key  : eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf
    public key   : 03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873
  
  To sign it with a nHashType of 1 (SIGHASH_ALL):
  
  hashPrevouts:
    dSHA256(db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a547701000000)
  = b0287b4a252ac05af83d2dcef00ba313af78a3e9c329afa216eb3aa2a7b4613a
  
  hashSequence:
    dSHA256(feffffff)
  = 18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198
  
  hashOutputs:
    dSHA256(b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac)
  = de984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c83
  
  hash preimage: 01000000b0287b4a252ac05af83d2dcef00ba313af78a3e9c329afa216eb3aa2a7b4613a18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001976a91479091972186c449eb1ded22b78e40d009bdf008988ac00ca9a3b00000000feffffffde984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c839204000001000000
  
    nVersion:     01000000
    hashPrevouts: b0287b4a252ac05af83d2dcef00ba313af78a3e9c329afa216eb3aa2a7b4613a
    hashSequence: 18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198
    outpoint:     db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a547701000000
    scriptCode:   1976a91479091972186c449eb1ded22b78e40d009bdf008988ac
    amount:       00ca9a3b00000000
    nSequence:    feffffff
    hashOutputs:  de984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c83
    nLockTime:    92040000
    nHashType:    01000000
  
  sigHash:      64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6
  signature:    3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01
  
  The serialized signed transaction is: 01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000
    nVersion:  01000000
    marker:    00
    flag:      01
    txin:      01 db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477 01000000 1716001479091972186c449eb1ded22b78e40d009bdf0089 feffffff
    txout:     02 b8b4eb0b00000000 1976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac
                  0008af2f00000000 1976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac
    witness    02 473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01 2103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873
    nLockTime: 92040000
*/
int test_p2sh_p2wpkh(int argc, char ** argv)
{
	static const int TEST_CASE = 2;
	printf("\n======== TEST %d. %s() ========\n", TEST_CASE, __FUNCTION__);
	
	// 2. P2SH-P2WPKH
	AUTO_CLEANUP_ARRAY1_(satoshi_txout_t) utxoes[1] = {
		[0] = { .value = 1000000000, .flags = 1},
	};
	hex2bin("17" // vstr.length 
		"a9144733f37cf4db86fbc2efed2500b4f4e49f31202387",
		-1, (void **)&utxoes[0].scripts);
	
	ssize_t cb = 0;
	AUTO_FREE_PTR unsigned char * tx_data = NULL;	// serialized tx data
	ssize_t cb_data = hex2bin(
		"01000000"
		"0001"
		"01"
			"db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a547701000000"
			"1716001479091972186c449eb1ded22b78e40d009bdf0089"
			"feffffff"
		"02"
			"b8b4eb0b00000000" "1976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac"
			"0008af2f00000000" "1976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac"
		"02"
			"47"
				"3044"
					"022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f"
					"0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb"
				"01"
			"21"
				"03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"
		"92040000",
		-1,
		(void **)&tx_data);
	assert(tx_data && cb_data > 0);
	
	AUTO_CLEANUP_ARRAY1_(satoshi_tx_t) tx[1] = { 0 };
	cb = satoshi_tx_parse(tx, cb_data, tx_data);
	assert(cb == cb_data);
	satoshi_tx_dump(tx);
	
	return verify_tx(tx, utxoes);
}


/*
3. Native P2WSH
This example shows how OP_CODESEPARATOR and out-of-range SIGHASH_SINGLE are processed:

  The following is an unsigned transaction:
    0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000
  
    nVersion:  01000000
    txin:      02 fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e 00000000 00 ffffffff
                  0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f8 00000000 00 ffffffff
    txout:     01 00f2052a01000000 1976a914a30741f8145e5acadf23f751864167f32e0963f788ac
    nLockTime: 00000000
  
  The first input comes from an ordinary P2PK:
    scriptPubKey: 21036d5c20fa14fb2f635474c1dc4ef5909d4568e5569b79fc94d3448486e14685f8ac value: 1.5625
    private key:  b8f28a772fccbf9b4f58a4f027e07dc2e35e7cd80529975e292ea34f84c4580c
    signature:    304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201 (SIGHASH_ALL)
  
  The second input comes from a native P2WSH witness program:
    scriptPubKey : 00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0, value: 49
    witnessScript: 21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac
                   <026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae> CHECKSIGVERIFY CODESEPARATOR <0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465> CHECKSIG
  
  To sign it with a nHashType of 3 (SIGHASH_SINGLE):
  
  hashPrevouts:
    dSHA256(fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e000000000815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f800000000)
  = ef546acf4a020de3898d1b8956176bb507e6211b5ed3619cd08b6ea7e2a09d41
  
    nVersion:     01000000
    hashPrevouts: ef546acf4a020de3898d1b8956176bb507e6211b5ed3619cd08b6ea7e2a09d41
    hashSequence: 0000000000000000000000000000000000000000000000000000000000000000
    outpoint:     0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f800000000
    scriptCode:   (see below)
    amount:       0011102401000000
    nSequence:    ffffffff
    hashOutputs:  0000000000000000000000000000000000000000000000000000000000000000 (this is the second input but there is only one output)
    nLockTime:    00000000
    nHashType:    03000000
  
  scriptCode:  4721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac
                                                                                       ^^
               (please note that the not-yet-executed OP_CODESEPARATOR is not removed from the scriptCode)
  preimage:    01000000ef546acf4a020de3898d1b8956176bb507e6211b5ed3619cd08b6ea7e2a09d4100000000000000000000000000000000000000000000000000000000000000000815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f8000000004721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac0011102401000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000003000000
  sigHash:     82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391
  public key:  026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae
  private key: 8e02b539b1500aa7c81cf3fed177448a546f19d2be416c0c61ff28e577d8d0cd
  signature:   3044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e2703
  
  scriptCode:  23210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac
               (everything up to the last executed OP_CODESEPARATOR, including that OP_CODESEPARATOR, are removed)
  preimage:    01000000ef546acf4a020de3898d1b8956176bb507e6211b5ed3619cd08b6ea7e2a09d4100000000000000000000000000000000000000000000000000000000000000000815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000023210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac0011102401000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000003000000
  sigHash:     fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47
  public key:  0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465
  private key: 86bf2ed75935a0cbef03b89d72034bb4c189d381037a5ac121a70016db8896ec
  signature:   304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503
  
  The serialized signed transaction is: 01000000000102fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e000000004847304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac000347304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503473044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e27034721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac00000000
 
*/

int test_native_p2wsh(int argc, char ** argv)
{
	static const int TEST_CASE = 3;
	printf("\n======== TEST %d. %s() ========\n", TEST_CASE, __FUNCTION__);
	
	// 3. Native P2WSH
	AUTO_CLEANUP_ARRAY2_(satoshi_txout_t) utxoes[2] = {
		[0] = { .value = 156250000LL, .flags = satoshi_txout_type_legacy},
		[1] = { .value = 4900000000LL, .flags = satoshi_txout_type_segwit},
	};
	hex2bin("23" // vstr.length 
		"21036d5c20fa14fb2f635474c1dc4ef5909d4568e5569b79fc94d3448486e14685f8ac",
		-1, (void **)&utxoes[0].scripts);
	hex2bin("22" // vstr.length 
		"00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0",
		-1, (void **)&utxoes[1].scripts);
	
	ssize_t cb = 0;
	AUTO_FREE_PTR unsigned char * tx_data = NULL;	// serialized tx data
	ssize_t cb_data = hex2bin(
		"01000000"
		"0001"
		"02"
			"fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e" "00000000"
			"48"
				"47"
					"3044"
						"02200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e99"
						"02204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da2"
					"01"
			"ffffffff"
			"0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f8" "00000000"
			"00"
			"ffffffff"
		"01"
			"00f2052a01000000" "1976a914a30741f8145e5acadf23f751864167f32e0963f788ac"
		// witnesses data
		"00"
		"03"
			"47"
				"3044"
					"02200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac"
					"0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e5"
				"03"	// sighash_single
			"47"
				"3044"
					"022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c0"
					"02201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e27"
				"03"
			"47"
				"21" "026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae"
				"ad"	// op_checksigverify
				"ab"	// op_codeseparator
				"21" "0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465"
				"ac" // op_checksig
		"00000000",
		-1,
		(void **)&tx_data);
	assert(tx_data && cb_data > 0);
	
	AUTO_CLEANUP_ARRAY1_(satoshi_tx_t) tx[1] = { 0 };
	cb = satoshi_tx_parse(tx, cb_data, tx_data);
	assert(cb == cb_data);
	satoshi_tx_dump(tx);
	
	return verify_tx(tx, utxoes);
}




/*
P2SH-P2WSH
This example is a P2SH-P2WSH 6-of-6 multisig witness program signed with 6 different SIGHASH types.

  The following is an unsigned transaction: 010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000
  
    nVersion:  01000000
    txin:      01 36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e 01000000 00 ffffffff
    txout:     02 00e9a43500000000 1976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688ac
                  c0832f0500000000 1976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac
    nLockTime: 00000000
  
  The input comes from a P2SH-P2WSH 6-of-6 multisig witness program:
    scriptPubKey : a9149993a429037b5d912407a71c252019287b8d27a587, value: 9.87654321
    redeemScript : 0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54
    witnessScript: 56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae
  
  hashPrevouts:
    dSHA256(36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000)
  = 74afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0
  
  hashSequence:
    dSHA256(ffffffff)
  = 3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044
  
  hashOutputs for ALL:
    dSHA256(00e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac)
  = bc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc
  
  hashOutputs for SINGLE:
    dSHA256(00e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688ac)
  = 9efe0c13a6b16c14a41b04ebe6a63f419bdacb2f8705b494a43063ca3cd4f708
  
  hash preimage for ALL: 0100000074afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa03bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e7066504436641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffffbc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc0000000001000000
    nVersion:     01000000
    hashPrevouts: 74afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0
    hashSequence: 3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044
    outpoint:     36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000
    scriptCode:   cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae
    amount:       b168de3a00000000
    nSequence:    ffffffff
    hashOutputs:  bc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc
    nLockTime:    00000000
    nHashType:    01000000
  sigHash:      185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c
  public key:   0307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3
  private key:  730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6
  signature:    304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01
  
  hash preimage for NONE: 0100000074afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000002000000
    nVersion:     01000000
    hashPrevouts: 74afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0
    hashSequence: 0000000000000000000000000000000000000000000000000000000000000000
    outpoint:     36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000
    scriptCode:   cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae
    amount:       b168de3a00000000
    nSequence:    ffffffff
    hashOutputs:  0000000000000000000000000000000000000000000000000000000000000000
    nLockTime:    00000000
    nHashType:    02000000
  sigHash:        e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36
  public key:     03b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b
  private key:    11fa3d25a17cbc22b29c44a484ba552b5a53149d106d3d853e22fdd05a2d8bb3
  signature:      3044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502
  
  hash preimage for SINGLE: 0100000074afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffff9efe0c13a6b16c14a41b04ebe6a63f419bdacb2f8705b494a43063ca3cd4f7080000000003000000
    nVersion:     01000000
    hashPrevouts: 74afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0
    hashSequence: 0000000000000000000000000000000000000000000000000000000000000000
    outpoint:     36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000
    scriptCode:   cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae
    amount:       b168de3a00000000
    nSequence:    ffffffff
    hashOutputs:  9efe0c13a6b16c14a41b04ebe6a63f419bdacb2f8705b494a43063ca3cd4f708
    nLockTime:    00000000
    nHashType:    03000000
  sigHash:        1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea
  public key:     034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a
  private key:    77bf4141a87d55bdd7f3cd0bdccf6e9e642935fec45f2f30047be7b799120661
  signature:      3044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403
  
  hash preimage for ALL|ANYONECANPAY: 010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffffbc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc0000000081000000
    nVersion:     01000000
    hashPrevouts: 0000000000000000000000000000000000000000000000000000000000000000
    hashSequence: 0000000000000000000000000000000000000000000000000000000000000000
    outpoint:     36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000
    scriptCode:   cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae
    amount:       b168de3a00000000
    nSequence:    ffffffff
    hashOutputs:  bc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc
    nLockTime:    00000000
    nHashType:    81000000
  sigHash:        2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e
  public key:     033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f4
  private key:    14af36970f5025ea3e8b5542c0f8ebe7763e674838d08808896b63c3351ffe49
  signature:      3045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381
  
  hash preimage for NONE|ANYONECANPAY: 010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000082000000
    nVersion:     01000000
    hashPrevouts: 0000000000000000000000000000000000000000000000000000000000000000
    hashSequence: 0000000000000000000000000000000000000000000000000000000000000000
    outpoint:     36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000
    scriptCode:   cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae
    amount:       b168de3a00000000
    nSequence:    ffffffff
    hashOutputs:  0000000000000000000000000000000000000000000000000000000000000000
    nLockTime:    00000000
    nHashType:    82000000
  sigHash:        781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a
  public key:     03a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac16
  private key:    fe9a95c19eef81dde2b95c1284ef39be497d128e2aa46916fb02d552485e0323
  signature:      3045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a0882
  
  hash preimage for SINGLE|ANYONECANPAY: 010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffff9efe0c13a6b16c14a41b04ebe6a63f419bdacb2f8705b494a43063ca3cd4f7080000000083000000
    nVersion:     01000000
    hashPrevouts: 0000000000000000000000000000000000000000000000000000000000000000
    hashSequence: 0000000000000000000000000000000000000000000000000000000000000000
    outpoint:     36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000
    scriptCode:   cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae
    amount:       b168de3a00000000
    nSequence:    ffffffff
    hashOutputs:  9efe0c13a6b16c14a41b04ebe6a63f419bdacb2f8705b494a43063ca3cd4f708
    nLockTime:    00000000
    nHashType:    83000000
  sigHash:        511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b
  public key:     02d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b
  private key:    428a7aee9f0c2af0cd19af3cf1c78149951ea528726989b2e83e4778d2c3f890
  signature:      30440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783
  
  The serialized signed transaction is: 0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac080047304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08824730440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000
*/

int test_p2sh_p2wsh(int argc, char ** argv)
{
	static const int TEST_CASE = 4;
	printf("\n======== TEST %d. %s() ========\n", TEST_CASE, __FUNCTION__);
	
	// 4. P2SH-P2WSH
	// utxo[0]: scriptPubKey : a9149993a429037b5d912407a71c252019287b8d27a587, value: 9.87654321
	AUTO_CLEANUP_ARRAY1_(satoshi_txout_t) utxoes[1] = {
		[0] = { .value = 987654321, .flags = satoshi_txout_type_legacy }, 
	};
	hex2bin("17" // vstr.length 
		"a9149993a429037b5d912407a71c252019287b8d27a587",
		-1, (void **)&utxoes[0].scripts);
		
	ssize_t cb = 0;
	AUTO_FREE_PTR unsigned char * tx_data = NULL;	// serialized tx data
	ssize_t cb_data = hex2bin(
		"01000000"
		"0001"
		"01"
			"36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000"
			"23" "220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54"
			"ffffffff"
		"02"
			"00e9a43500000000" "1976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688ac"
			"c0832f0500000000" "1976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac"
	// witnesses data
		"08"
			"00"
			"47"
				"3044"
					"02206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b"
					"0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce"
				"01"
			"47"
				"3044"
					"022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d90"
					"02205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce2715"
				"02"
			"47"
				"3044"
					"022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e"
					"022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c767954"
				"03"
			"48"
				"3045"
					"022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e"
					"02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d163"
				"81"
			"48"
				"3045"
					"022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407"
					"022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08"
				"82"
			"47"
				"3044"
					"0220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c"
					"022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b47"
				"83"
			"cf"
				"56"	// need 6 signatures
					"21" "0307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3"
					"21" "03b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b"
					"21" "034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a"
					"21" "033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f4"
					"21" "03a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac16"
					"21" "02d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b"
				"56" 	// 6 pubkeys
				"ae"	// op_checkmultisig
		"00000000",	// localtime 
		-1,
		(void **)&tx_data);
	
	assert(tx_data && cb_data > 0);
	
	AUTO_CLEANUP_ARRAY1_(satoshi_tx_t) tx[1] = { 0 };
	cb = satoshi_tx_parse(tx, cb_data, tx_data);
	assert(cb == cb_data);
	satoshi_tx_dump(tx);
	
	return verify_tx(tx, utxoes);
}






int test_segwit_v0(int argc, char ** argv)
{
	test_(native_p2wpkh);
	test_(p2sh_p2wpkh);
	
	test_(native_p2wsh);
	test_(p2sh_p2wsh);
	return 0;
}
#endif



#if defined(_TEST_SEGWIT_TX) && defined(_STAND_ALONE)


int main(int argc, char **argv)
{
	
	return 0;
}
#endif
