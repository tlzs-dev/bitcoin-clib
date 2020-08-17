/*
 * transactions_db.c
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


#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include <db.h>
#include <endian.h>


#include "transactions_db.h"
#include "satoshi-types.h"
#include "utils.h"

typedef struct transactions_db_private
{
	transactions_db_t * db;
	db_engine_t * engine;
	
	db_handle_t * txes_db;
	db_handle_t * wtxid_db;		// sorted by wtxid
	db_handle_t * block_hashes_db;	// sorted by block_hash

	char db_name[PATH_MAX];
	char wtxid_db_name[PATH_MAX];
	char block_hashes_db_name[PATH_MAX];
}transactions_db_private_t;


static ssize_t associate_wtxid(db_handle_t * db, 
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
	
	db_record_tx_t * tx = value->data;
	assert(sizeof(*tx) == value->size);
	
	results[0].data = &tx->wtxid;
	results[0].size = sizeof(tx->wtxid);
	
	return num_results;
}


static ssize_t associate_block_hash(db_handle_t * db, 
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
	
	db_record_tx_t * tx = value->data;
	assert(sizeof(*tx) == value->size);
	
	results[0].data = &tx->block_hash;
	results[0].size = sizeof(tx->block_hash);
	return num_results;
}


transactions_db_private_t * transactions_db_private_new(transactions_db_t * db, db_engine_t * engine, const char * db_name)
{
#define WTXID_DB_SUFFIX "_wtxid.db"
#define BLOCK_HASHES_DB_SUFFIX "_in_block.db"
	assert(db && engine);
	int rc = -1;
	if(NULL == db_name) db_name = "transctions.db";

	transactions_db_private_t * priv = calloc(1, sizeof(*priv));
	assert(priv);
	
	priv->engine = engine;
	priv->db = db;
	db->priv = priv;
	
	strncpy(priv->db_name, db_name, sizeof(priv->db_name));
	strncpy(priv->wtxid_db_name, db_name, sizeof(priv->wtxid_db_name) - sizeof(WTXID_DB_SUFFIX));
	strncpy(priv->block_hashes_db_name, db_name, sizeof(priv->block_hashes_db_name) - sizeof(BLOCK_HASHES_DB_SUFFIX));
	
	char * p_ext = strstr(priv->wtxid_db_name, ".db");
	if(NULL == p_ext) p_ext = priv->wtxid_db_name + strlen(priv->wtxid_db_name);
	strcpy(p_ext, WTXID_DB_SUFFIX);
	
	p_ext = strstr(priv->block_hashes_db_name, ".db");
	if(NULL == p_ext) p_ext = priv->block_hashes_db_name + strlen(priv->block_hashes_db_name);
	strcpy(p_ext, BLOCK_HASHES_DB_SUFFIX);
	
	// open wtxid db and block_hashes db
	priv->wtxid_db = engine->open_db(engine, priv->wtxid_db_name, db_format_type_hash, db_flags_dup_sort);
	assert(priv->wtxid_db);
	
	priv->block_hashes_db = engine->open_db(engine, priv->block_hashes_db_name, db_format_type_btree, db_flags_dup_sort);
	assert(priv->block_hashes_db);
	
	// open transactions.db
	priv->txes_db = engine->open_db(engine, db_name, db_format_type_hash, 0);
	assert(priv->txes_db);

	// sorted by 'wtxid' and 'block_hash' fields
	rc = priv->txes_db->associate(priv->txes_db, NULL, priv->wtxid_db, associate_wtxid);
	assert(0 == rc);

	rc = priv->txes_db->associate(priv->txes_db, NULL, priv->block_hashes_db, associate_block_hash);
	assert(0 == rc);

	return priv;
#undef BLOCK_HASHES_DB_SUFFIX
#undef WTXID_DB_SUFFIX
}

static void transactions_db_private_free(transactions_db_private_t * priv)
{
	if(NULL == priv) return;
	db_engine_t * engine = priv->engine;
	if(engine) {
		db_private_close_db(wtxid_db);
		db_private_close_db(block_hashes_db);
		db_private_close_db(txes_db);
	}
	free(priv);
	return;
}

/************************************************************
 * member functions
************************************************************/
static int transactions_db_add(
	struct transactions_db * db, db_engine_txn_t * txn, 
	const uint256_t * txid, 	// key
	const uint256_t * wtxid, const uint256_t * block_hash, int32_t tx_index, uint32_t flags)
{
	int rc = -1;
	assert(db && db->priv && txid);
	
	transactions_db_private_t * priv = db->priv;
	db_handle_t * txes_db = priv->txes_db;
	assert(txes_db);
	
	db_record_tx_t tx[1];
	memset(tx, 0, sizeof(tx));
	
	if(wtxid) tx->wtxid = *wtxid;
	if(block_hash) tx->block_hash = *block_hash;
	tx->tx_index = tx_index;
	tx->flags = flags;
	
	rc = txes_db->insert(txes_db, txn, 
		&(db_record_data_t){.data = (void *)txid, .size = sizeof(*txid)},
		&(db_record_data_t){.data = (void *)tx, .size = sizeof(tx)}); 
	return rc;
}

static int transactions_db_remove(struct transactions_db * db, db_engine_txn_t * txn, const uint256_t * txid, const uint256_t * wtxid)
{
	int rc = -1;
	assert(db && db->priv);
	assert(txid || wtxid);
	
	transactions_db_private_t * priv = db->priv;
	assert(priv->txes_db && priv->wtxid_db);
	
	if(txid)
	{
		rc = priv->txes_db->del(priv->txes_db, txn, 
			&(db_record_data_t){.data = (void *)txid, .size = sizeof(*txid)});
	}else {
		rc = priv->wtxid_db->del(priv->wtxid_db, txn, 
			&(db_record_data_t){.data = (void *)wtxid, .size = sizeof(*wtxid)});
	}
	return rc;
}

static int transactions_db_remove_block(struct transactions_db * db, db_engine_txn_t * txn, const uint256_t * block_hash)
{
	int rc = -1;
	assert(db && db->priv);
	assert(block_hash);
	
	transactions_db_private_t * priv = db->priv;
	db_handle_t * block_hashes_db = priv->block_hashes_db;
	assert(block_hashes_db);
	
	rc = block_hashes_db->del(block_hashes_db, txn, 
		&(db_record_data_t){.data = (void *)block_hash, .size = sizeof(*block_hash)});

	return rc;
}

ssize_t transactions_db_find(struct transactions_db * db, db_engine_txn_t * txn, const uint256_t * txid, db_record_tx_t ** p_txes)
{
	assert(db && db->priv);
	assert(txid);
	
	ssize_t count = -1;
	transactions_db_private_t * priv = db->priv;
	db_record_data_t * value = NULL;
	
	count = priv->txes_db->find(priv->txes_db, txn, 
		&(db_record_data_t){.data = (void *)txid, .size = sizeof(*txid)},
		&value); 
	if(count <= 0) goto label_cleanup;
	
	assert(count == 1);
	
	db_record_tx_t * txes = *p_txes;
	if(NULL == txes) {
		txes = calloc(count, sizeof(*txes));
		assert(txes);
		*p_txes = txes;
	}
	
	memcpy(txes, value->data, value->size);
	
label_cleanup:
	db_record_data_cleanup(value);
	free(value);
	return count;
}

ssize_t transactions_db_find_by_wtxid(struct transactions_db * db, db_engine_txn_t * txn, const uint256_t * wtxid, uint256_t ** p_txids, db_record_tx_t ** p_txes)
{
	assert(db && db->priv);
	assert(wtxid);
	
	ssize_t count = -1;
	transactions_db_private_t * priv = db->priv;
	db_record_data_t * keys = NULL;
	db_record_data_t * values = NULL;
	
	count = priv->wtxid_db->find_secondary(priv->wtxid_db, txn, 
		&(db_record_data_t){.data = (void *)wtxid, .size = sizeof(*wtxid)},
		&keys,
		&values); 

	if(count <= 0) goto label_cleanup;
	db_record_tx_t * txes = NULL;
	uint256_t * txids = NULL;
	
	if(p_txids) {
		txids = *p_txids;
		if(NULL == txids) {
			txids = calloc(count, sizeof(*txids));
			assert(txids);
			
		}
	}

	if(p_txes) {
		txes = *p_txes;
		if(NULL == txes) {
			txes = calloc(count, sizeof(*txes));
			assert(txes);
		}
	}
	
	for(ssize_t i = 0; i < count; ++i) {
		if(txids) memcpy(&txids[i], keys[i].data, keys[i].size);
		if(txes) memcpy(&txes[i], values[i].data, values[i].size);
		
		db_record_data_cleanup(&keys[i]);
		db_record_data_cleanup(&values[i]);
	}

	if(p_txids) *p_txids = txids;
	if(p_txes) * p_txes = txes;
	
label_cleanup:
	if(keys) {
		free(keys);
		keys = NULL;
	}
	if(values) {
		free(values);
		values = NULL;
	}
	return count;
}


ssize_t transactions_db_find_in_block(
	struct transactions_db * db, db_engine_txn_t * txn, 
	const uint256_t * block_hash, 
	uint256_t ** p_txids, db_record_tx_t ** p_txes)
{
	assert(db && db->priv);
	assert(block_hash);
	
	ssize_t count = -1;
	transactions_db_private_t * priv = db->priv;
	db_record_data_t * keys = NULL;
	db_record_data_t * values = NULL;
	
	
	count = priv->block_hashes_db->find_secondary(priv->block_hashes_db, txn, 
		&(db_record_data_t){.data = (void *)block_hash, .size = sizeof(*block_hash)},
		&keys,
		&values); 

	if(count <= 0) goto label_cleanup;
	db_record_tx_t * txes = NULL;
	uint256_t * txids = NULL;
	
	if(p_txids) {
		txids = *p_txids;
		if(NULL == txids) {
			txids = calloc(count, sizeof(*txids));
			assert(txids);
			
		}
	}
	
	if(p_txes) {
		txes = *p_txes;
		if(NULL == txes) {
			txes = calloc(count, sizeof(*txes));
			assert(txes);
		}
	}
	
	for(ssize_t i = 0; i < count; ++i) {
		if(txids) memcpy(&txids[i], keys[i].data, keys[i].size);
		if(txes) memcpy(&txes[i], values[i].data, values[i].size);
		
		db_record_data_cleanup(&keys[i]);
		db_record_data_cleanup(&values[i]);
	}

	if(p_txids) *p_txids = txids;
	if(p_txes) * p_txes = txes;
	
label_cleanup:
	if(keys) {
		free(keys);
		keys = NULL;
	}
	if(values) {
		free(values);
		values = NULL;
	}
	return count;
}


/************************************************************
 * constructor / destructor
************************************************************/
transactions_db_t * transactions_db_init(transactions_db_t * db, db_engine_t * engine, const char * db_name, void * user_data)
{
	if(NULL == db) db = calloc(1, sizeof(*db));
	assert(db);
	
	db->user_data = user_data;
	
	db->add = transactions_db_add;
	db->remove = transactions_db_remove;
	db->remove_block = transactions_db_remove_block;
	db->find = transactions_db_find;
	db->find_by_wtxid = transactions_db_find_by_wtxid;
	db->find_in_block = transactions_db_find_in_block;
	
	transactions_db_private_t * priv = transactions_db_private_new(db, engine, db_name);
	assert(priv && db->priv == priv);
	return db;
}

void transactions_db_cleanup(transactions_db_t * db)
{
	if(NULL == db) return;
	transactions_db_private_free(db->priv);
	db->priv = NULL;
	return;
}


#if defined(_TEST_TRANSACTIONS_DB) && defined(_STAND_ALONE)

static unsigned int uint256_rand_seed = 0;
static void uint256_rand(uint256_t * dst)
{
	if(0 == uint256_rand_seed) {
		uint256_rand_seed = 0x123456;
		srand(uint256_rand_seed);
	}
	
	uint16_t * data = (uint16_t *)dst;
	for(int i = 0; i < 16; ++i) {
		data[i] = rand() % RAND_MAX;
	}
	return;
}

static void dump_record(const uint256_t * txid, const db_record_tx_t * tx_data)
{
	dump_line("txid: ", txid, sizeof(*txid));
	dump_line("\t" "wtxid: ", &tx_data->wtxid, sizeof(tx_data->wtxid));
	dump_line("\t" "block_hash: ", &tx_data->block_hash, sizeof(tx_data->block_hash));
}

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h> 
#include <limits.h>
static int check_path(const char * path)
{
	assert(path && path[0]);
	int rc = 0;
	struct stat st[1];
	memset(st, 0, sizeof(st));
	rc = stat(path, st);
	if(0 == rc) {
		switch((st->st_mode & S_IFMT)) 
		{
		case S_IFDIR: return 0;
		default: return -1;
		}
	}
	
	char command[PATH_MAX + 100] = "";
	int cb = snprintf(command, sizeof(command), "mkdir -p \"%s\"", path);
	assert(cb > 0 && cb < (int)sizeof(command));
	
	rc = system(command);
	assert(0 == rc);
	return rc;
}


int main(int argc, char ** argv)
{
	const char * db_home = "data/test_txdb";
	if(argc > 1) db_home = argv[1];
	
	check_path(db_home);
	db_engine_t * engine = db_engine_init(NULL, db_home, NULL);
	
	transactions_db_t * txes_db = transactions_db_init(NULL, engine, NULL, NULL);
	assert(txes_db);
	
	uint256_t txid;
	uint256_t wtxid;
	uint256_t block_hash;
	int rc = -1;
	for(int i = 0; i < 10; ++i)
	{
		uint256_rand(&txid);
		uint256_rand(&wtxid);
		uint256_rand(&block_hash);
		
		printf("\n==== add %d ...\n", i);
		dump_line("txid: ", &txid, sizeof(txid));
		dump_line("\t" "wtxid: ", &wtxid, sizeof(wtxid));
		dump_line("\t" "block_hash: ", &block_hash, sizeof(block_hash));
		rc = txes_db->add(txes_db, NULL, &txid, &wtxid, &block_hash, i, 0);
		printf("\t --> ret_code = %d\n", rc);
	}
	
	db_cursor_t cursor[1];
	memset(cursor, 0, sizeof(cursor));
	
	transactions_db_private_t * priv = txes_db->priv;
	
	db_cursor_t * p_cursor = db_cursor_init(cursor, priv->txes_db, NULL, 0);
	assert(p_cursor && p_cursor == cursor);
	
	memset(&txid, 0, sizeof(txid));
	db_record_tx_t tx_data[1];
	memset(tx_data, 0, sizeof(tx_data));
	
	cursor->key->data = &txid;
	cursor->key->size = sizeof(txid);
	cursor->value->data = tx_data;
	cursor->value->size = sizeof(tx_data);
	
	while(0 == (rc = cursor->next(cursor))) {
		dump_record(&txid, tx_data);
	}
	
	transactions_db_cleanup(txes_db);
	free(txes_db);

	return 0;
}
#endif
