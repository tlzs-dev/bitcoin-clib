/*
 * utxoes_db.c
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

#include "db_engine.h"
#include "utxoes_db.h"

typedef struct utxoes_db_private
{
	utxoes_db_t * db;
	db_engine_t * engine;
	
	db_handle_t * utxoes;
	db_handle_t * block_hashes_db;
	db_handle_t * witness_flag_db;
	
	char db_name[PATH_MAX];
	char block_hashes_db_name[PATH_MAX];
	char witness_flag_db_name[PATH_MAX];
	
}utxoes_db_private_t;

static ssize_t associate_block_hashes(db_handle_t * db, 
	const db_record_data_t * key, 
	const db_record_data_t * value, 
	db_record_data_t ** p_result)
{
	static const int num_results = 1;	
	if(NULL == p_result) return num_results;	// returns the required array size for custom memory allocator
	
	db_record_data_t * results = * p_result;
	if(NULL == results) {
		results = calloc(num_results, sizeof(*results));
		*p_result = results;
	}
	
	db_record_utxo_t * utxo = (db_record_utxo_t *)value->data;
	assert(sizeof(*utxo) == value->size);
	
	results[0].data = &utxo->block_hash;
	results[0].size = sizeof(utxo->block_hash);
	
	return num_results;
}

static ssize_t associate_witness_flag(db_handle_t * db, 
	const db_record_data_t * key, 
	const db_record_data_t * value, 
	db_record_data_t ** p_result)
{
	static const int num_results = 1;	
	if(NULL == p_result) return num_results;	// returns the required array size for custom memory allocator
	
	db_record_data_t * results = * p_result;
	if(NULL == results) {
		results = calloc(num_results, sizeof(*results));
		*p_result = results;
	}
	
	db_record_utxo_t * utxo = (db_record_utxo_t *)value->data;
	assert(sizeof(*utxo) == value->size);
	
	results[0].data = &utxo->is_witness;
	results[0].size = sizeof(utxo->is_witness) + sizeof(utxo->p2sh_flags);
	
	return num_results;
}

utxoes_db_private_t * utxoes_db_private_new(utxoes_db_t * db, db_engine_t * engine, const char * db_name)
{
#define BLOCK_HASHES_DB_SUFFIX "_block_hashes.db"
#define WITNESS_FLAG_DB_SUFFIX "_witness_flag.db"
	int rc = -1;
	assert(db && engine);
	if(NULL == db_name) db_name = "utxoes.db";
	
	utxoes_db_private_t * priv = calloc(1, sizeof(*priv));
	assert(priv);
	
	priv->engine = engine;
	priv->db = db;
	db->priv = priv;
	
	strncpy(priv->db_name, db_name, sizeof(priv->db_name));
	strncpy(priv->block_hashes_db_name, db_name, sizeof(priv->block_hashes_db_name) - sizeof(BLOCK_HASHES_DB_SUFFIX));
	strncpy(priv->witness_flag_db_name, db_name, sizeof(priv->witness_flag_db_name) - sizeof(WITNESS_FLAG_DB_SUFFIX));
	
	
	char * p_ext = strstr(priv->block_hashes_db_name, ".db");
	if(NULL == p_ext) p_ext = priv->block_hashes_db_name + strlen(priv->block_hashes_db_name);
	strcpy(p_ext, BLOCK_HASHES_DB_SUFFIX);
	
	p_ext = strstr(priv->witness_flag_db_name, ".db");
	if(NULL == p_ext) p_ext = priv->witness_flag_db_name + strlen(priv->witness_flag_db_name);
	strcpy(p_ext, WITNESS_FLAG_DB_SUFFIX);
	
	
	// open block_hashes.db
	priv->block_hashes_db = engine->open_db(engine, priv->block_hashes_db_name, db_format_type_btree, db_flags_dup_sort);
	assert(priv->block_hashes_db);
	
	// open witness_flags.db
	priv->witness_flag_db = engine->open_db(engine, priv->witness_flag_db_name, db_format_type_btree, db_flags_dup_sort);
	assert(priv->witness_flag_db);
	
	/**
	 * open utxoes.db, 
	 * We chose to use hashtable because disk I/O operations are inevitable,
	 * and there is no direct correlation between keys, 
	 * so we don't want to use extra memory space to store meta-data for btree.
	 */
	priv->utxoes = engine->open_db(engine, db_name, db_format_type_hash, 0); 
	assert(priv->utxoes);

	// sorted by 'block_hash'
	rc = priv->utxoes->associate(priv->utxoes, NULL, priv->block_hashes_db, associate_block_hashes);
	assert(0 == rc);
	
	// sorted by 'witness_flags'
	rc = priv->utxoes->associate(priv->utxoes, NULL, priv->witness_flag_db, associate_witness_flag);
	assert(0 == rc);

	return priv;
#undef BLOCK_HASHES_DB_SUFFIX
#undef WITNESS_FLAG_DB_SUFFIX
}

#define db_private_close_db(_db) do {				\
		db_handle_t * db = priv->_db;				\
		if(db) {									\
			engine->list_remove(engine, db);		\
			db->close(db);							\
			db_handle_cleanup(db);					\
			free(db);								\
			priv->_db = NULL;						\
		}											\
	}while(0)

void utxoes_db_private_free(utxoes_db_private_t * priv)
{
	if(NULL == priv) return;
	db_engine_t * engine = priv->engine;
	if(engine) {
		db_private_close_db(block_hashes_db);
		db_private_close_db(witness_flag_db);
		db_private_close_db(utxoes);
	}
	free(priv);
	return;
}
	
static int utxoes_db_add(struct utxoes_db * db, db_engine_txn_t * txn, 
	const satoshi_outpoint_t * outpoint,
	const satoshi_txout_t * txout,
	const uint256_t * block_hash
)
{
	assert(db && db->priv && outpoint && txout && block_hash);
	utxoes_db_private_t * priv = db->priv;
	db_handle_t * utxoes = priv->utxoes;
	assert(utxoes);
	
	db_record_utxo_t utxo[1];
	memset(utxo, 0, sizeof(utxo));
	
	ssize_t script_size = varstr_size(txout->scripts);
	unsigned char * script_data = varstr_getdata_ptr(txout->scripts);
	
	if(script_size <= 0 || script_size > UTXOES_DB_MAX_SCRIPT_LENGTH) return -1;
	
	utxo->value = txout->value;
	memcpy(utxo->scripts, txout->scripts, script_size);
	
	utxo->block_hash = *block_hash;
	utxo->is_witness = (script_data[0] <= 16);	// bip141
	
	return utxoes->insert(utxoes, txn, 
		&(db_record_data_t){.data = (void *)outpoint, .size = sizeof(*outpoint)},
		&(db_record_data_t){.data = (void *)utxo, .size = sizeof(utxo)}); 
}

static int utxoes_db_remove(struct utxoes_db * db, db_engine_txn_t * txn, const satoshi_outpoint_t * outpoint)
{
	return 0;
}
static int utxoes_db_remove_block(struct utxoes_db * db, db_engine_txn_t * txn, const uint256_t * block_hash)
{
	return 0;
}

static ssize_t utxoes_db_find(struct utxoes_db * db, db_engine_txn_t * txn, 
	const satoshi_outpoint_t * outpoint,
	db_record_utxo_t ** p_utxo)
{
	return 0;
}
	
static ssize_t utxoes_db_find_in_block(struct utxoes_db * db, db_engine_txn_t * txn, 
	const uint256_t * block_hash, 
	satoshi_outpoint_t ** p_outpoints,
	db_record_utxo_t ** p_utxoes)
{
	return 0;
}
	
static ssize_t utxoes_db_find_in_tx(struct utxoes_db * db, db_engine_txn_t * txn, 
	const uint256_t * tx_hash, 
	int32_t ** p_indexes,
	db_record_utxo_t ** p_utxoes)
{
	return 0;
}

utxoes_db_t * utxoes_db_init(utxoes_db_t * db, db_engine_t * engine, const char * db_name, void * user_data)
{
	if(NULL == db) db = calloc(1, sizeof(*db));
	assert(db);
	
	db->user_data = user_data;
	
	db->add = utxoes_db_add;
	db->remove = utxoes_db_remove;
	db->remove_block = utxoes_db_remove_block;
	db->find = utxoes_db_find;
	db->find_in_block = utxoes_db_find_in_block;
	db->find_in_tx = utxoes_db_find_in_tx;
	
	utxoes_db_private_t * priv = utxoes_db_private_new(db, engine, db_name);
	assert(priv && db->priv == priv);
	
	return db;
}
void utxoes_db_cleanup(utxoes_db_t * db)
{
	if(NULL == db) return;
	utxoes_db_private_free(db->priv);
	db->priv = NULL;
	return;
}


#if defined(_TEST_UTXOES_DB) && defined(_STAND_ALONE)
int main(int argc, char **argv)
{
	
	return 0;
}
#endif
