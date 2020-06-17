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

static const uint256_t uint256_zero[1];

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
	if(txout_count == 0) sha256_update(sha, (unsigned char *)uint256_zero, 32);	// sighash_none
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

static inline int segwit_v0_get_digest(satoshi_rawtx_t * rawtx, 
	ssize_t cur_index,
	uint32_t hash_type,
	const satoshi_txout_t * utxo,
	uint256_t * digest)
{
	assert(rawtx && rawtx->tx);
	satoshi_tx_t * tx = rawtx->tx;
	assert(tx->txins && cur_index >= 0 && cur_index < tx->txin_count);

	sha256_ctx_t sha[1];
	unsigned char hash[32];
	
	uint32_t anyone_canpay = (hash_type & 0x80);
	hash_type &= satoshi_tx_sighash_masks;

	if(!anyone_canpay && hash_type == satoshi_tx_sighash_all)
	{
		// copy pre-hashed states
		memcpy(sha, rawtx->sha, sizeof(sha));	// copy internal state ( common data pre-hashed )
	}else // with anyone_canpay flag,  or is sighash_single,  or is sighash_none
	{
		// there's no convenient way to simplify operation, just hash from the very begining
		sha256_init(sha);
		// step 1
		sha256_update(sha, (unsigned char *)&tx->version, sizeof(tx->version));
		
		// step 2
		if(!anyone_canpay) prehash_prevouts(sha, tx->txin_count, tx->txins);
		else prehash_prevouts(sha, 0, NULL);
		
		// step 3
		if(hash_type == satoshi_tx_sighash_all) {	// ( anyone_canpay && (type!=sighash_single) && (type!=sighash_none) )
			prehash_sequences(sha, tx->txin_count, tx->txins);
		}
		else {
			prehash_sequences(sha, 0, NULL);
		}
	}
	
	ssize_t cb_image = 4 + 32 + 32;	// skip pre-hashed data
	satoshi_txin_t * txins = tx->txins;
	
	// hash different parts (start from step 4)
	//  4. outpoint (32-byte hash + 4-byte little endian) 
	sha256_update(sha, (unsigned char *)&txins[cur_index].outpoint, sizeof(satoshi_outpoint_t));
	cb_image += sizeof(satoshi_outpoint_t);
	
	//  5. scriptCode of the input (serialized as scripts inside CTxOuts)
	assert(txins[cur_index].redeem_scripts);
	ssize_t cb_redeem_scripts = varstr_size(txins[cur_index].redeem_scripts);
	sha256_update(sha, (unsigned char *)txins[cur_index].redeem_scripts, cb_redeem_scripts);	
	cb_image += cb_redeem_scripts;
	
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
		prehash_outputs(sha, tx->txout_count, cur_index, tx->txouts, NULL);
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
	
	debug_printf("hash_type: %u", hash_type);
	debug_printf("preimage length: %ld", cb_image);
	
	sha256_final(sha, hash);
	
	// double hash
	sha256_init(sha);
	sha256_update(sha, hash, 32);
	
	// write result
	sha256_final(sha, (unsigned char *)digest);	
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
	rawtx->get_digest = segwit_v0_get_digest;
	
	sha256_ctx_t * sha = rawtx->sha;
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
	debug_printf("TEST: 1. Native P2WPKH ...");
	satoshi_txout_t utxoes[2] = {
		[0] = { .value = 625000000, },
		[1] = { .value = 600000000, }
	};
	hex2bin("23" // vstr.length 
		"2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac",
		-1, (void **)&utxoes[0].scripts);
	hex2bin("16" // vstr.length 
		"00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1",
		-1, (void **)&utxoes[1].scripts);
	
	
	// step 0. load tx
	satoshi_tx_t tx[1] = { 0 };
	ssize_t cb = 0;
	unsigned char * tx_data = NULL;	// serialized tx data
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
	
	// step 1. parse tx
	crypto_context_t * crypto = crypto_context_init(NULL, crypto_backend_libsecp256, NULL);
	assert(crypto);
	satoshi_script_t * scripts = satoshi_script_init(NULL, crypto, NULL);
	assert(scripts);
	scripts->attach_tx(scripts, tx);
	
	satoshi_txin_t * txins = tx->txins;
	for(ssize_t i = 0; i < tx->txin_count; ++i)
	{
		ssize_t cb_scripts = varstr_length(txins[i].scripts);
		unsigned char * scripts_data = varstr_getdata_ptr(txins[i].scripts);
		scripts->set_txin_info(scripts, i, &utxoes[i]);
		
		if(tx->has_flag && cb_scripts == 0)	 // todo: load from tx->witness_data
		{
		}else
		{
			cb = scripts->parse(scripts, 
				satoshi_tx_script_type_txin, scripts_data, cb_scripts);
			assert(cb == cb_scripts);
		}
	}

	return 0;
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



int test_segwit_v0(int argc, char ** argv)
{
	test_native_p2wpkh(argc, argv);
	return 0;
}
#endif



#if defined(_TEST_SEGWIT_TX) && defined(_STAND_ALONE)


int main(int argc, char **argv)
{
	
	return 0;
}
#endif
