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
	memcpy(sha, rawtx->sha, sizeof(sha));	// copy internal state ( common data pre-hashed )
		
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
	sha256_update(sha, rawtx->txouts_hash, 32);
	cb_image += 32;
	
	// 9. nLocktime of the transaction (4-byte little endian)
	sha256_update(sha, (unsigned char *)&tx->lock_time, sizeof(uint32_t));
	cb_image += 4;
	
	// 10. sighash type of the signature (4-byte little endian)
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
	sha256_ctx_t temp_sha[1];
	unsigned char hash[32];
	sha256_init(sha);
	
// pre-hash step1, step2, step3
	// step 1. nVersion of the transaction (4-byte little endian)
	sha256_update(sha, (unsigned char *)&tx->version, sizeof(int32_t));
	
	// step 2. hashPrevouts (32-byte hash)	// for sighash_type_all
	satoshi_txin_t * txins = tx->txins;
	sha256_init(temp_sha);
	for(ssize_t i = 0; i < tx->txin_count; ++i)
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
	 
	// step 3. hashSequence (32-byte hash)
	sha256_init(temp_sha);
	for(ssize_t i = 0; i < tx->txin_count; ++i)
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


	// step 8. hashOutputs (32-byte hash)
	satoshi_txout_t * txouts = tx->txouts;
	sha256_init(temp_sha);
	for(ssize_t i = 0; i < tx->txout_count; ++i)
	{
		sha256_update(temp_sha, (unsigned char *)&txouts[i].value, sizeof(txouts[i].value));
		sha256_update(temp_sha, (unsigned char *)txouts[i].scripts, varstr_size(txouts[i].scripts));
	}
	
	sha256_final(temp_sha, hash);
	// double hash
	sha256_init(temp_sha);
	sha256_update(temp_sha, hash, 32);
	
	// save the result of step8 for later use
	sha256_final(temp_sha, rawtx->txouts_hash);
	
	return rawtx;
}


/****************************************************************
 * TEST Module
 ***************************************************************/
#if defined(_TEST_SEGWIT_TX) || defined(_TEST_SATOSHI_TX)
/*
 * Segwit v0 TEST data: from https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
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
*/


int test_segwit_v0(int argc, char ** argv)
{
// 1. Native P2WPKH
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
	
	satoshi_tx_t tx[1] = { 0 };
	tx->version = 1;
	
	// set segwit flag
	tx->has_flag = 1;
	tx->flag[0] = 0; tx->flag[1] = 1;
	
	tx->txin_count = 2;
	satoshi_txin_t * txins = calloc(tx->txin_count, sizeof(*txins));
	assert(txins);
	tx->txins = txins;
	
	// set txins[0]
	void * p_outpoint = &txins[0].outpoint;
	hex2bin("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f" "00000000",
			-1, 
			(void **)&p_outpoint);
	txins[0].scripts = (varstr_t *)varstr_empty;
	txins[0].sequence = 0xffffffee;		// "eeffffff"
	
	// set txins[1]
	p_outpoint = &txins[1].outpoint;
	hex2bin("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a" "01000000",
			-1, 
			(void **)&p_outpoint);
	txins[1].scripts = (varstr_t *)varstr_empty;	// "00"
	txins[1].sequence = 0xffffffff;		// "ffffffff"
	
	tx->txout_count = 2;
	satoshi_txout_t * txouts = calloc(tx->txout_count, sizeof(*txouts));
	assert(txouts);
	tx->txouts = txouts;
	
	// set txouts[0]
	void * p_value = &txouts[0].value;
	hex2bin("202cb20600000000", -1, (void **)&p_value);
	hex2bin("1976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac", -1, (void **)&txouts[0].scripts);
	
	// set txouts[1]
	p_value = &txouts[1].value;
	hex2bin("9093510d00000000", -1, (void **)&p_value);
	hex2bin("1976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac", -1, (void **)&txouts[1].scripts);
	
	// set locktime
	tx->lock_time = 0x00000011;	// "11000000"
	
	satoshi_tx_dump(tx);
	
/*
 * set redeem_scripts manually 
 * ( this field should be set by scripts->parse() automatically )
 */
	if(NULL == txins[0].redeem_scripts) 
		txins[0].redeem_scripts = varstr_clone(utxoes[0].scripts);	// The first input comes from an ordinary P2PK:
	
	if(NULL == txins[1].redeem_scripts)
		txins[1].redeem_scripts = satoshi_txin_get_redeem_scripts(1, &utxoes[1]); //The second input comes from a P2WPKH witness program:
	
	dump_line("txins[1].script: ", txins[1].redeem_scripts, varstr_size(txins[1].redeem_scripts));
	
	crypto_context_t * crypto = crypto_context_init(NULL, crypto_backend_libsecp256, NULL);
	crypto_privkey_t * privkeys[2] = { NULL };
	crypto_pubkey_t * pubkeys[2] = { NULL };
	
	// private key of the first input:
	privkeys[0] = crypto_privkey_import_from_string(crypto, 
		"bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
	
	// private key of the second input:
	privkeys[1] = crypto_privkey_import_from_string(crypto,
		"619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
	assert(privkeys[0] && privkeys[1]);
	
	// calc pubkeys
	pubkeys[0] = (crypto_pubkey_t *)crypto_privkey_get_pubkey(privkeys[0]);
	pubkeys[1] = (crypto_pubkey_t *)crypto_privkey_get_pubkey(privkeys[1]);
	
// verify keys
	unsigned char hash[32];
	unsigned char pubkey_buffer[65] = { 0 };
	unsigned char * pubkey_data = pubkey_buffer;
	
	int compressed_flag = 1;
	ssize_t cb_pubkey = crypto_pubkey_export(crypto, pubkeys[0], compressed_flag, &pubkey_data);
	assert(cb_pubkey == 33);
	// verify pubkey of the first input
	assert(0 == memcmp(pubkey_data, varstr_getdata_ptr(utxoes[0].scripts) + 1, cb_pubkey));
	
	// verify pubkey of the second input
	cb_pubkey = crypto_pubkey_export(crypto, pubkeys[1], compressed_flag, &pubkey_data);
	assert(cb_pubkey == 33);
	
	char * pubkey_hex = NULL;
	dump_line("pubkey: ", pubkey_data, cb_pubkey);
	hash160(pubkey_data, cb_pubkey, hash);
	
	dump_line("hash160(pubkey): ", hash, 20);
	dump_line("utxo: ", varstr_getdata_ptr(utxoes[1].scripts) + 2, 20);
	assert(0 == memcmp(hash, varstr_getdata_ptr(utxoes[1].scripts) + 2, 20));
	
	ssize_t cb = bin2hex(pubkey_data, cb_pubkey, &pubkey_hex);
	assert(cb == 66);
	assert(0 == strcasecmp(pubkey_hex, "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"));
	free(pubkey_hex);
	pubkey_hex = NULL;
	
// import signatures
	crypto_signature_t * sigs[2] = { NULL };
	sigs[0] = crypto_signature_import_from_string(crypto, 
		"3045"
			"0221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be"
			"022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed");
	
	sigs[1] = crypto_signature_import_from_string(crypto, 
		"3044"
			"02203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a"
			"0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee");
	
	assert(sigs[0] && sigs[1]);
	
	uint256_t digests[2];
	int rc = 0;
	unsigned char * preimage = NULL;
	rc = segwit_v0_tx_get_digest(tx, 1, 1, &utxoes[1], &digests[1]);
	assert(0 == rc);
	
	//c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670
	printf("digest(truth): %s\n", "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");
	dump_line("--> digest[1]: ", &digests[1], 32);
	free(preimage); preimage = NULL;
	
	satoshi_rawtx_t rawtx[1];
	memset(rawtx, 0, sizeof(rawtx));
	satoshi_rawtx_attach(rawtx, tx);
	uint256_t digest;
	rawtx->get_digest(rawtx, 1, 1, &utxoes[1], &digest);
	dump_line("rawtx_get_digest: ", &digest, 32);
	assert(0 == memcmp(&digest, &digests[1], 32));
	
	return 0;
}

#endif



#if defined(_TEST_SEGWIT_TX) && defined(_STAND_ALONE)


int main(int argc, char **argv)
{
	
	return 0;
}
#endif
