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
	const satoshi_txout_t * utxo, // prevout
	unsigned char ** p_image)
{
	ssize_t cb_image = sizeof(uint32_t)		// 1. nVersion of the transaction (4-byte little endian)
		+ sizeof(uint256_t)	// 2. hashPrevouts (32-byte hash)
		+ sizeof(uint256_t)	// 3. hashSequence (32-byte hash)
		+ sizeof(satoshi_outpoint_t)	// 4. outpoint (32-byte hash + 4-byte little endian) 
		+ varint_calc_size(utxo->cb_script) + utxo->cb_script	//  5. scriptCode of the input (serialized as scripts inside CTxOuts)
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
	p += sizeof(uint32_t);
	
    // 2. hashPrevouts (32-byte hash)	( sha256(sha256(outpoints[])) )
    const satoshi_txin_t * txins = tx->txins;
    sha256_init(sha);
    for(ssize_t i = 0; i < tx->txin_count; ++i)
    {
		sha256_update(sha, (unsigned char *)&txins[i].outpoint, sizeof(satoshi_outpoint_t));
	}
	sha256_final(sha, hash);
	sha256_init(sha);
	sha256_update(sha, hash, 32);
	sha256_final(sha, p);	// write hash256() result 
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
	p += sizeof(uint256_t);
	
   //  4. outpoint (32-byte hash + 4-byte little endian) 
   memcpy(p, &txins[cur_index].outpoint, sizeof(satoshi_outpoint_t));
   p += sizeof(satoshi_outpoint_t);
    
   //  5. scriptCode of the input (serialized as scripts inside CTxOuts)
   varstr_set((varstr_t *)p, utxo->scripts, utxo->cb_script);
   p += varstr_size((varstr_t *)p);
   
   //  6. value of the output spent by this input (8-byte little endian)
   *(int64_t *)p = utxo->value;
   p += sizeof(int64_t);
   
   //  7. nSequence of the input (4-byte little endian)
   *(uint32_t *)p = txins[cur_index].sequence;
   p += sizeof(uint32_t);

   //  8. hashOutputs (32-byte hash)
	const satoshi_txout_t * txouts = tx->txouts;
	sha256_init(sha);
	for(ssize_t i = 0; i < tx->txout_count; ++i)
	{
		unsigned char vlength[8];	// varint_t 
		varint_set((varint_t *)vlength, txouts[i].cb_script);
		sha256_update(sha, (unsigned char *)&txouts[i].value, sizeof(int64_t));
		sha256_update(sha, vlength, varint_size((varint_t *)vlength));
		sha256_update(sha, txouts[i].scripts, txouts[i].cb_script);
	}
	sha256_final(sha, hash);
	sha256_init(sha);
	sha256_update(sha, hash, 32);
	sha256_final(sha, p);	// write hash256() result 
	
    // 9. nLocktime of the transaction (4-byte little endian)
    *(uint32_t *)p = tx->lock_time;
    p += sizeof(uint32_t);
    
    // 10. sighash type of the signature (4-byte little endian)
	*(uint32_t *)p = txins[cur_index].hash_type;
	p += sizeof(uint32_t);
	
	assert(p == p_end);
	return cb_image;
}



int segwit_v0_tx_get_digest(const satoshi_tx_t * tx, 
	int cur_index, 		// txin index
	const satoshi_txout_t * utxo, // prevout
	uint256_t * hash
)
{
	unsigned char * preimage = NULL;
	ssize_t cb_image = segwit_v0_generate_preimage(tx, cur_index, utxo, &preimage);
	assert(cb_image > 0 && preimage);
	
	hash256(preimage, cb_image, (unsigned char *)hash);
	free(preimage);
	return 0;
}

struct scripts_data
{
	unsigned char * scripts;
	ssize_t cb_scripts;
};

int satoshi_tx_get_digest(const satoshi_tx_t * tx,
	int cur_index,
	const satoshi_txout_t * utxo, 
	uint256_t * hash)
{
	if(tx->has_flag && tx->flag[0] == 0 && tx->flag[1] == 1) // segwit_v0
	{
		return segwit_v0_tx_get_digest(tx, cur_index, utxo, hash);
	}
	
	struct scripts_data * backup = NULL;
	backup = calloc(tx->txin_count, sizeof(struct scripts_data));
	assert(backup);
	
	satoshi_txin_t * txins = (satoshi_txin_t *)tx->txins;
	for(ssize_t i = 0; i < tx->txin_count; ++i)
	{
		backup[i].scripts = txins[i].scripts;
		backup[i].cb_scripts = txins[i].cb_scripts;
		
		if(i == cur_index)
		{
			txins[i].scripts = utxo->scripts;
			txins[i].cb_scripts = utxo->cb_script;
		}else
		{
			txins[i].scripts = NULL;
			txins[i].cb_scripts = 0;
		}
	}
	
	unsigned char * preimage = NULL;
	ssize_t cb_image = satoshi_tx_serialize(tx, NULL);	// get buffer size
	assert(cb_image > 0);
	preimage = malloc(cb_image + sizeof(uint32_t));	// preimage | sequence
	assert(preimage);
	ssize_t cb = satoshi_tx_serialize(tx, &preimage);	
	assert(cb == cb_image);
	
	*(uint32_t *)(preimage + cb_image) = txins[cur_index].sequence;
	hash256(preimage, cb_image + sizeof(uint32_t), (unsigned char *)hash);
	free(preimage);

	for(ssize_t i = 0; i < tx->txin_count; ++i)
	{
		txins[i].scripts = backup[i].scripts;
		txins[i].cb_scripts = backup[i].cb_scripts;
	}
	free(backup);
	return 0;
}



//~ typedef struct satoshi_rawtx 
//~ {
	//~ satoshi_tx_t * tx;
	//~ // backup
	//~ unsigned char ** scripts;
	//~ ssize_t * cb_scripts;
	
	//~ // internal states
	//~ sha256_ctx_t sha[1];
	//~ unsigned char hash[32];
//~ }satoshi_rawtx_t;
satoshi_rawtx_t * satoshi_rawtx_prepare(satoshi_rawtx_t * rawtx, satoshi_tx_t * tx)
{
	assert(tx && tx->txin_count > 0 && tx->txins);
	
	if(NULL == rawtx) rawtx = calloc(1, sizeof(*rawtx));
	assert(rawtx);
	rawtx->tx = tx;
	
	sha256_ctx_t temp_sha[1];
	unsigned char hash[32];
	sha256_init(rawtx->sha);
	
	if(tx->has_flag)
	{
		assert(tx->flag[0] == 0 && tx->flag[1] == 1);	// support segwit_v0 only
		// pre-hash common data to internal SHA context (step 1, 2, 3, 8)

		// 1. nVersion of the transaction (4-byte little endian)
		sha256_update(rawtx->sha, (unsigned char *)&tx->version, sizeof(uint32_t));
		
		// 2. hashPrevouts (32-byte hash)	( sha256(sha256(outpoints[])) )
		const satoshi_txin_t * txins = tx->txins;
		sha256_init(temp_sha);
		for(ssize_t i = 0; i < tx->txin_count; ++i)
		{
			sha256_update(temp_sha, (unsigned char *)&txins[i].outpoint, sizeof(satoshi_outpoint_t));
		}
		sha256_final(temp_sha, hash);
		sha256_init(temp_sha);
		sha256_update(temp_sha, hash, 32);
		sha256_final(temp_sha, hash);	// calc hash256() result 
		
		sha256_update(rawtx->sha, (unsigned char *)hash, 32);
		
		
		// 3. hashSequence (32-byte hash)
		sha256_init(temp_sha);
		for(ssize_t i = 0; i < tx->txin_count; ++i)
		{
			sha256_update(temp_sha, (unsigned char *)&txins[i].sequence, sizeof(uint32_t));
		}
		sha256_final(temp_sha, hash);
		sha256_init(temp_sha);
		sha256_update(temp_sha, hash, 32);
		sha256_final(temp_sha, hash);	// write hash256() result 
		
		sha256_update(rawtx->sha, (unsigned char *)hash, 32);
		
		//  8. hashOutputs (32-byte hash)
		const satoshi_txout_t * txouts = tx->txouts;
		for(ssize_t i = 0; i < tx->txout_count; ++i)
		{
			unsigned char vlength[8];	// varint_t 
			varint_set((varint_t *)vlength, txouts[i].cb_script);
			sha256_update(temp_sha, (unsigned char *)&txouts[i].value, sizeof(int64_t));
			sha256_update(temp_sha, vlength, varint_size((varint_t *)vlength));
			sha256_update(temp_sha, txouts[i].scripts, txouts[i].cb_script);
		}
		sha256_final(temp_sha, hash);
		sha256_init(temp_sha);
		sha256_update(temp_sha, hash, 32);
		sha256_final(temp_sha, rawtx->txouts_hash);	// write hash256() result 
		
	}else // legacy tx
	{
		// backup scripts
		rawtx->backup = calloc(tx->txin_count, sizeof(*rawtx->backup));
		assert(rawtx->backup);
		
		satoshi_txin_t * txins = tx->txins;
		for(ssize_t i = 0; i < tx->txin_count; ++i)
		{
			rawtx->backup[i].scripts = txins[i].scripts;
			rawtx->backup[i].cb_scripts = txins[i].cb_scripts;
			
			txins[i].scripts = NULL;
			txins[i].cb_scripts = 0;
		}
	}
	return rawtx;
}

void satoshi_rawtx_reset(satoshi_rawtx_t * rawtx)
{
	if(NULL == rawtx || NULL == rawtx->backup) return;
	
	satoshi_tx_t * tx = rawtx->tx;
	assert(tx);
	
	if(tx->has_flag == 0) // legacy tx
	{
		
		if(tx)
		{
			satoshi_txin_t * txins = tx->txins;
			for(ssize_t i = 0; i < tx->txin_count; ++i)
			{
				txins[i].scripts = rawtx->backup[i].scripts;
				txins[i].cb_scripts = rawtx->backup[i].cb_scripts;
			}
		}
		free(rawtx->backup);
		rawtx->backup = NULL;
	}
	
	rawtx->tx = NULL;
	sha256_init(rawtx->sha);
	return;
}

int satoshi_rawtx_get_digest(satoshi_rawtx_t * rawtx, 
	int cur_index, 
	const satoshi_txout_t * utxo,
	uint256_t * hash)
{
	assert(rawtx && rawtx->tx);
	satoshi_tx_t * tx = rawtx->tx;
	
	assert(tx->txins && cur_index >= 0 && cur_index < tx->txin_count && utxo && hash);
	sha256_ctx_t sha[1];
	memcpy(sha, rawtx->sha, sizeof(sha));	// copy internal state ( common data pre-hashed )
	
	unsigned char vlength[8] = {0};	// hold enough buffer size, can be processed as varint_t * 
	
	if(tx->has_flag)
	{
		assert(tx->flag[0] == 0 && tx->flag[1] == 1);
		
		satoshi_txin_t * txins = tx->txins;
		
		// hash different parts (start from step 4)
		//  4. outpoint (32-byte hash + 4-byte little endian) 
		sha256_update(sha, (unsigned char *)&txins[cur_index].outpoint, sizeof(satoshi_outpoint_t));
		
		//  5. scriptCode of the input (serialized as scripts inside CTxOuts)
		varint_set((varint_t *)vlength, utxo->cb_script);
		sha256_update(sha, vlength, varint_size((varint_t *)vlength));
		
		//  6. value of the output spent by this input (8-byte little endian)
		sha256_update(sha, (unsigned char *)utxo->value, sizeof(int64_t));
		
		//  7. nSequence of the input (4-byte little endian)
		sha256_update(sha, (unsigned char *)&txins[cur_index].sequence, sizeof(uint32_t));

		//  8. hashOutputs (32-byte hash)
		sha256_update(sha, rawtx->txouts_hash, 32);
		
		// 9. nLocktime of the transaction (4-byte little endian)
		sha256_update(sha, (unsigned char *)&tx->lock_time, sizeof(uint32_t));
		
		// 10. sighash type of the signature (4-byte little endian)
		sha256_update(sha, (unsigned char *)&txins[cur_index].hash_type, sizeof(uint32_t));
	}else
	{
		satoshi_txin_t * txins = tx->txins;
		for(ssize_t i = 0; i < tx->txin_count; ++i)
		{
			if(i == cur_index)
			{
				txins[i].scripts = utxo->scripts;
				txins[i].cb_scripts = utxo->cb_script;
			}else
			{
				txins[i].scripts = NULL;
				txins[i].cb_scripts = 0;
			}
		}
		
		unsigned char * preimage = NULL;
		ssize_t cb_image = satoshi_tx_serialize(tx, &preimage);
		assert(preimage && cb_image > 0);
		
		sha256_update(sha, preimage, cb_image);
		sha256_update(sha, (unsigned char *)&txins[cur_index].hash_type, sizeof(uint32_t));
	}
	
	sha256_final(sha, (unsigned char *)hash);
	
	// double hash
	sha256_init(sha);
	sha256_update(sha, (unsigned char *)hash, 32);
	sha256_final(sha, (unsigned char *)hash);		
	
	return 0;
}

#if defined(_TEST_SATOSHI_TX) && defined(_STAND_ALONE)
#define dump_line(prefix, data, length) do {							\
		printf(prefix); dump(data, length); printf("\e[39m\n");	\
	} while(0)



int test_copy_sha_ctx();
int test_p2wpkh();

int main(int argc, char ** argv)
{
//	test_copy_sha_ctx(argc, argv);
	test_p2wpkh(argc, argv);
	return 0;
}

/*************************************************
 * test_rawtx
*************************************************/

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
		txouts[i].cb_script = varstr_get(scripts[i], &txouts[i].scripts, 0);
	}
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
		printf("\t" "sig_scripts: (cb=%d)", (int)txin->cb_scripts); dump(txin->scripts, txin->cb_scripts); printf("\n");
		printf("\t" "sequence: "); dump(&txin->sequence, 4); printf("\n");
	}
	printf("== txouts_count: %Zd ==\n", tx->txout_count);
	for(ssize_t i = 0; i < tx->txout_count; ++i)
	{
		const satoshi_txout_t * txout = &tx->txouts[i];
		printf("\t== txouts[%d] ==\n", (int)i);
		printf("\t" "value: %" PRIi64 "(", txout->value); dump(&txout->value, 8); printf(")\n");
		printf("\t" "pk_scripts: (cb=%d)", (int)txout->cb_script); dump(txout->scripts, txout->cb_script); printf("\n");
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

int test_p2wpkh(int argc, char **argv)
{
	static const char * rawtx_hex = "01000000"
	"02"
		"fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f" "00000000"
		"00"
		"eeffffff"
		"ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a" "01000000"
		"00"
		"ffffffff"
	"02"
		"202cb20600000000"
		"1976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac"
		"9093510d00000000"
		"1976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac"
	"11000000";
	
	static const char * signed_tx_hex = "01000000"
		"0001"
		"02"
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
		"00" "02"
			"47"
				"3044"
					"02203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a"
					"0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee"
				"01"
			"21"
				"025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
		"11000000";
	
	unsigned char * rawtx_data = NULL;
	unsigned char * signed_tx_data = NULL;
	
	ssize_t cb = 0;
	ssize_t cb_rawtx = hex2bin(rawtx_hex, -1, (void **)&rawtx_data);
	ssize_t cb_signed_tx = hex2bin(signed_tx_hex, -1, (void **)&signed_tx_data);
	
	assert(cb_rawtx > 0 && rawtx_data);
	assert(cb_signed_tx > 0 && signed_tx_data);
	
	satoshi_tx_t tx[2]; 
	memset(tx, 0, sizeof(tx));
	cb = satoshi_tx_parse(&tx[0], cb_rawtx, rawtx_data);
	assert(cb == cb_rawtx);
	
	cb = satoshi_tx_parse(&tx[1], cb_signed_tx, signed_tx_data);
	assert(cb == cb_signed_tx);
	
	satoshi_tx_dump(&tx[0]);
	satoshi_tx_dump(&tx[1]);
	
	
	satoshi_tx_cleanup(&tx[0]);
	satoshi_tx_cleanup(&tx[1]);
	
	free(rawtx_data);
	free(signed_tx_data);
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
