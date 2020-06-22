/*
 * blockchain.c
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

#include <stdint.h>
#include <inttypes.h>

#include <json-c/json.h>

#include "bitcoin-consensus.h"
#include "satoshi-types.h"
#include "utils.h"

#include "blockchain.h"

#include <search.h>
#include <db.h>

#define BLOCKCHAIN_ALLOC_SIZE			(65536)

/***************************************
 * Utils
 **************************************/
static void db_error(const DB_ENV * env, 
	const char * errpfx, const char * msg)
{
	fprintf(stderr, "\e[33m" "%s: %s" "\e[39m" "\n", errpfx, msg);
	return;
}

static int check_path(const char * path)
{
	assert(path);
	char command[100 + PATH_MAX] = "";
	snprintf(command, sizeof(command), "mkdir -p \"%s\"", path); 
	int rc = system(command);
	assert(0 == rc);
	return rc;
}

static pthread_once_t s_once_key = PTHREAD_ONCE_INIT;
static DB_ENV * s_db_env;
static const char s_db_home[PATH_MAX] = "data";

static DB_ENV * init_db_env(const char * db_home)
{
	DB_ENV * env = NULL;
	int ret = db_env_create(&env, 0);
	if(ret)
	{
		fprintf(stderr, "[ERROR]::%s() failed: %s\n", 
			__FUNCTION__,
			db_strerror(ret));
		exit(1);
	}
	
	if(NULL == db_home) db_home = s_db_home;
	
	u_int32_t flags = DB_CREATE 
		| DB_INIT_MPOOL 
		| DB_INIT_LOG
		| DB_INIT_LOCK
		| DB_INIT_TXN
		| DB_RECOVER
		| DB_REGISTER
		| DB_THREAD
		| 0;
	int mode = 0666;
	ret = env->open(env, db_home, flags, mode);
	if(ret)
	{
		fprintf(stderr, "[DB::ERROR]: %s\n", db_strerror(ret));
		env->close(env, 0);
		return NULL;
	}
	
	env->set_errpfx(env, "[DB::ERROR]");
	env->set_errcall(env, db_error);

	return env;
}

static void init_db_env_default(void)
{
	s_db_env = init_db_env(s_db_home);
	assert(s_db_env);
	return;
}

static void close_db(DB_ENV * env, DB * dbp, DB * sdbp)
{
	assert(env);
	int rc = 0;
	if(sdbp) // close secondary db before primary
	{
		rc = sdbp->close(sdbp, 0);
		if(rc)
		{
			env->err(env, rc, NULL);
		//	exit(1);
		}
	}
	
	if(dbp)
	{
		rc = dbp->close(dbp, 0);
		if(rc)
		{
			env->err(env, rc, NULL);
		//	exit(1);
		}
	}
	return;
}

static int open_db(DB_ENV ** p_env, const char * db_name, 
	DBTYPE type, u_int32_t flags,
	DB ** p_dbp /* [OUT] */
)
{
	static const u_int32_t default_flags = DB_CREATE 
		| DB_READ_UNCOMMITTED
		| DB_AUTO_COMMIT;
	
	assert(db_name && p_dbp);
	DB_ENV * env = NULL;
	if(p_env) env = *p_env;
	
	if(NULL == env)
	{
		pthread_once(&s_once_key, init_db_env_default);
		env = s_db_env;
		assert(env);
		
		if(p_env) * p_env = env;
	}
	
	if(0 == flags) flags = default_flags;
	
	int rc = 0;
	DB * dbp = NULL;
	rc = db_create(&dbp, env, 0);
	if(rc)
	{
		env->err(env, rc, NULL);
		exit(1);
	}
	
	rc = dbp->open(dbp, NULL, db_name, NULL, 
		type, flags, 0666);
	if(rc)
	{
		env->err(env, rc, NULL);
		exit(1);
	}
	
	int txn_mode = dbp->get_transactional(dbp);
	assert(txn_mode != 0);	// db MUST support DB transaction operation
	
	*p_dbp = dbp;
	return rc;
}
	

/******************************************
 * db_record_utxo
 *****************************************/
struct db_record_utxo * db_record_utxo_new(
	const uint256_t * block_hash, 
	const satoshi_outpoint_t *outpoint, 
	const satoshi_txout_t * txout)
{
	assert(txout);
	uint32_t cb_scripts = varstr_length(txout->scripts);
	
	
	struct db_record_utxo * utxo = calloc(
		sizeof(*utxo) + cb_scripts, // allocate additional size for scripts data
		1); 
	assert(utxo);

	utxo->cb_scripts = cb_scripts;
	utxo->value = txout->value;
	
	if(cb_scripts > 0)
	{
		memcpy(utxo->scripts, varstr_getdata_ptr(txout->scripts), cb_scripts);
	}

	if(outpoint)
	{
		memcpy(&utxo->outpoint, outpoint, sizeof(*outpoint));
	}
	
	if(block_hash)
	{
		memcpy(&utxo->block_hash, block_hash, sizeof(*block_hash));
	}
	
	return utxo;
}

void db_record_utxo_free(struct db_record_utxo * utxo)
{
	free(utxo);
}

/******************************************
 * utxo_db_private
 *****************************************/
typedef struct utxo_db_private
{
	bitcoin_utxo_db_t * db;
	// priv
	char db_name[200];
	DB_ENV * env;
	DB * dbp;	// primary db, indexed by outpoint
	DB * sdbp;	// secondary db,  indexed by block_hash
	ssize_t count;
	
	DB_TXN * txn;	// if txn == NULL, transactions would be auto commited.
}utxo_db_private_t;

typedef struct block_db_private
{
	bitcoin_blocks_db_t * db;
	char db_name[200];
	DB_ENV * env;
	DB * dbp;
	ssize_t count;
}block_db_private_t;



static int utxo_record_get_block_hash(DB *sdbp,
    const DBT *key, const DBT *value, DBT *result)
{
	memset(result, 0, sizeof(*result));
	result->data = (void *)value->data;
	
	result->size = sizeof(uint256_t);
	return 0;
}


static utxo_db_private_t * utxo_db_private_new(bitcoin_utxo_db_t * db, DB_ENV * env, const char * db_name)
{
	static const u_int32_t flags = DB_CREATE 
		| DB_READ_UNCOMMITTED
		| DB_AUTO_COMMIT;
	int rc;
	if(NULL == db_name) db_name = "utxo.db";
	char sdb_name[PATH_MAX] = "";
	int cb = snprintf(sdb_name, sizeof(sdb_name), "blocks-%s", db_name);
	assert(cb >= 0 && cb < PATH_MAX);
	
	utxo_db_private_t * priv = calloc(1, sizeof(*priv));
	assert(priv);
	
	priv->db = db;
	db->priv = priv;
	
	DB * dbp = NULL;		// primary db
	DB * sdbp = NULL;		// secondary db
	
	rc = open_db(&env, db_name, DB_HASH, flags, &dbp);
	assert(0 == rc);
	
	rc = open_db(&env, sdb_name, DB_HASH, flags, &sdbp);
	assert(0 == rc);
	
	rc = dbp->associate(dbp, NULL, sdbp, 
		utxo_record_get_block_hash, 
		0
	//	| DB_IMMUTABLE_KEY	/9/ assume that the block hash associated with the UTXO will never be changed. if need reorg, remove all orphaned block's UTXOes first.
	);
	if(rc)
	{
		env->err(env, rc, NULL);
		exit(1);
	}
	
	priv->env = env;
	priv->dbp = dbp;
	priv->sdbp = sdbp;
	strncpy(priv->db_name, db_name, sizeof(priv->db_name));
	return priv;
}

void utxo_db_private_free(utxo_db_private_t * priv)
{
	if(NULL == priv) return;
	close_db(priv->env, priv->dbp, priv->sdbp);
	free(priv);
}

static void utxo_db_set_txn(struct bitcoin_utxo_db * db, void * txn)
{
	utxo_db_private_t * priv = db->priv;
	assert(priv && priv->db == db);
	priv->txn = txn;
	return;
}

static int utxo_db_add(struct bitcoin_utxo_db * db, 
	const uint256_t * block_hash, 
	const satoshi_outpoint_t *outpoint, 
	const satoshi_txout_t * txout)
{
	DBT key, value;
	memset(&key, 0, sizeof(key));
	memset(&value, 0, sizeof(value));

	db_record_utxo_t * utxo = db_record_utxo_new(block_hash, outpoint, txout);
	assert(utxo);
	ssize_t utxo_size = db_record_utxo_size(utxo);
	assert(utxo_size > sizeof(struct satoshi_outpoint));
	
	key.data = &utxo->outpoint;
	key.size = sizeof(*outpoint);
	
	value.data = &utxo->block_hash;
	value.size = utxo_size - sizeof(struct satoshi_outpoint); // skip utxo->outpoint, start from utxo->block_hash
	
	utxo_db_private_t * priv = db->priv;
	assert(priv && priv->db == db);
	
	int ret = 0;
	DB * dbp = priv->dbp;
	ret = dbp->put(dbp, priv->txn, &key, &value, 0);
	if(ret)
	{
		dbp->err(dbp, ret, "dbp->put(): value_size=%d", (int)value.size);
		
	}
	
	assert(ret == 0);
	db_record_utxo_free(utxo);
	return ret;
}

int utxo_db_remove(struct bitcoin_utxo_db * db, const struct satoshi_outpoint * outpoint)
{
	utxo_db_private_t * priv = db->priv;
	assert(priv && priv->db == db && priv->dbp);
	
	DB * dbp = priv->dbp;
	int ret = 0;
	DBT key;
	memset(&key, 0, sizeof(key));
	key.data = (void *)outpoint;
	key.size = sizeof(*outpoint);
	ret = dbp->del(dbp, priv->txn, &key, 0);
	
	if(ret != 0)
	{
		if(ret == DB_NOTFOUND) return 1;
		dbp->err(dbp, ret, "delete key(%p) failed", outpoint);
		return -1;	// error
	}
	return 0;
}

int utxo_db_find(struct bitcoin_utxo_db * db, const satoshi_outpoint_t * outpoint, satoshi_txout_t * txout, uint256_t * block_hash)
{
	utxo_db_private_t * priv = db->priv;
	assert(priv && priv->db == db && priv->dbp);
	
	DB * dbp = priv->dbp;
	int ret = 0;
	DBT key, value;
	memset(&key, 0, sizeof(key));
	memset(&value, 0, sizeof(value));
	
	key.data = (void *)outpoint;
	key.size = sizeof(*outpoint);
	
	value.flags = DB_DBT_MALLOC;
	ret = dbp->get(dbp, priv->txn, &key, &value, 0);
	
	
	if(ret != 0)
	{
		if(ret != DB_NOTFOUND) {
			dbp->err(dbp, ret, "delete key(%p) failed", outpoint);
		}
		return -1;
	}
	
	struct db_record_utxo_data * utxo = value.data;
	uint32_t data_size = value.size;
	assert(data_size == (sizeof(*utxo) + utxo->cb_scripts));
	
	if(block_hash)
	{
		memcpy(block_hash, &utxo->block_hash, sizeof(*block_hash));
	}
	
	if(txout)
	{
		txout->value = utxo->value;
		txout->scripts = varstr_new(utxo->scripts, utxo->cb_scripts);
	}
	
	free(utxo);
	return 0;
}

bitcoin_utxo_db_t * bitcoin_utxo_db_init(bitcoin_utxo_db_t * db, void * user_data)
{
	if(NULL == db) db = calloc(1, sizeof(*db));
	assert(db);
	
	db->add = utxo_db_add;
	db->remove = utxo_db_remove;
	db->find = utxo_db_find;
	
	db->set_txn = utxo_db_set_txn;
	
	bitcoin_blockchain_t * chain = user_data;
	DB_ENV * env = chain->get_db_env(chain);
	
	const char * db_name = NULL;	///< @todo load from settings
	utxo_db_private_t * priv = utxo_db_private_new(db, env, db_name);
	assert((db->priv == priv)); 
	
	return db;
}
void bitcoin_utxo_db_cleanup(bitcoin_utxo_db_t * db)
{
	if(NULL == db) return;
	utxo_db_private_free(db->priv);
	return;
}

/*******************************************************
 * BLOCKs
 ******************************************************/ 
typedef struct blocks_db_private
{
	bitcoin_blocks_db_t * db;
 // priv
	char db_name[200];
	DB_ENV * env;
	DB * dbp;	// primary db, indexed by outpoint
	DB * sdbp;	// secondary db,  indexed by block_hash
	ssize_t count;

	DB_TXN * txn;	// if txn == NULL, transactions would be auto commited.
}blocks_db_private_t;

static int blocks_record_get_height(DB *sdbp,
    const DBT *key, const DBT *value, DBT *result)
{
	memset(result, 0, sizeof(*result));
	const struct db_record_block_data * block = value->data;
	
	result->data = (void *)&block->height;
	result->size = sizeof(block->height);
	return 0;
}

blocks_db_private_t * blocks_db_private_new(
	bitcoin_blocks_db_t * db, 
	DB_ENV * env, 
	const char * db_name)
{
	static const u_int32_t flags = DB_CREATE 
		| DB_READ_UNCOMMITTED
		| DB_AUTO_COMMIT;
		
	if(NULL == db_name) db_name = "blocks.db";
	char sdb_name[PATH_MAX] = "";
	snprintf(sdb_name, sizeof(sdb_name), "heights-%s", db_name);
	
	int rc = 0;
	blocks_db_private_t * priv = calloc(1, sizeof(*priv));
	assert(priv);
	priv->db = db;
	db->priv = priv;

	DB * dbp = NULL;		// primary db
	DB * sdbp = NULL;		// secondary db
	
	rc = open_db(&env, db_name, DB_HASH, flags, &dbp);
	assert(0 == rc);
	
	rc = open_db(&env, sdb_name, DB_BTREE, flags, &sdbp);
	assert(0 == rc);
	
	rc = dbp->associate(dbp, NULL, sdbp, 
		blocks_record_get_height, 
		0
	//	| DB_IMMUTABLE_KEY	/9/ assume that the block hash associated with the UTXO will never be changed. if need reorg, remove all orphaned block's UTXOes first.
	);
	if(rc)
	{
		env->err(env, rc, NULL);
		exit(1);
	}
	
	priv->env = env;
	priv->dbp = dbp;
	priv->sdbp = sdbp;
	strncpy(priv->db_name, db_name, sizeof(priv->db_name));
	
	return priv;
}

static void blocks_db_private_free(blocks_db_private_t * priv)
{
	if(NULL == priv) return;
	close_db(priv->env, priv->dbp, priv->sdbp);
	free(priv);
	return;
}

static int blocks_db_add(struct bitcoin_blocks_db * db, 
	const uint256_t * block_hash,
	int height,
	const struct satoshi_block_header * hdr,
	int file_index, 
	int64_t start_pos, 
	uint32_t magic, uint32_t block_size)
{
	int rc = 0;
	blocks_db_private_t * priv = db->priv;
	assert(priv);
	
	struct db_record_block_data block[1];
	memset(block, 0, sizeof(block));
	block->height = height;
	if(hdr) block->hdr = *hdr;
	block->file_index = file_index;
	block->start_pos = start_pos;
	block->magic = magic;
	block->block_size = block_size;
	
	DB_ENV * env = priv->env;
	DB * dbp = priv->dbp;
	assert(env && dbp);
	
	DBT key, value;
	memset(&key, 0, sizeof(key));
	memset(&value, 0, sizeof(value));
	
	key.data = (void *)block_hash;
	key.size = sizeof(*block_hash);
	
	value.data = block;
	value.size = sizeof(block);
	
	rc = dbp->put(dbp, priv->txn, &key, &value, 0);
	if(rc)
	{
		env->err(env, rc, NULL);
	}
	return rc;
}

static int blocks_db_remove(struct bitcoin_blocks_db * db, const uint256_t * block_hash)
{
	assert(db && block_hash);
	
	int rc = 0;
	blocks_db_private_t * priv = db->priv;
	assert(priv);
	DB_ENV * env = priv->env;
	DB * dbp = priv->dbp;
	assert(env && dbp);
	
	DBT key;
	memset(&key, 0, sizeof(key));
	
	key.data = (void *)block_hash;
	key.size = sizeof(*block_hash);
	
	rc = dbp->del(dbp, priv->txn, &key, 0);
	if(rc)
	{
		env->err(env, rc, NULL);
	}
	return rc;
}

static int blocks_db_find(struct bitcoin_blocks_db * db, 
	const uint256_t * block_hash, 
	db_record_block_t ** p_record)
{
	assert(db && block_hash);
	
	int rc = 0;
	blocks_db_private_t * priv = db->priv;
	assert(priv);
	DB_ENV * env = priv->env;
	DB * dbp = priv->dbp;
	assert(env && dbp);
	
	DBT key, value;
	memset(&key, 0, sizeof(key));
	memset(&value, 0, sizeof(value));
	
	key.data = (void *)block_hash;
	key.size = sizeof(*block_hash);
	
	value.flags = DB_DBT_MALLOC;
	rc = dbp->get(dbp, priv->txn, &key, &value, 0);
	if(0 == rc) {
		struct db_record_block_data * block_data = value.data;
		assert(value.size == sizeof(*block_data));
		if(p_record)
		{
			db_record_block_t * block = *p_record;
			if(NULL == block)
			{
				block = calloc(1, sizeof(*block));
			}
			assert(block);
			block->hash = *block_hash;
			block->data = *block_data;
			
			*p_record = block;
		}
	}else if(rc != DB_NOTFOUND) {
			env->err(env, rc, NULL);
	}
	
	if(value.data) free(value.data);
	return rc;
}

void blocks_db_set_txn(struct bitcoin_blocks_db * db, void * txn)
{
	blocks_db_private_t * priv = db->priv;
	assert(priv);
	priv->txn = txn;
	return;
}



bitcoin_blocks_db_t * bitcoin_blocks_db_init(bitcoin_blocks_db_t * db, void * user_data)
{
	if(NULL == db) db = calloc(1, sizeof(*db));
	assert(db);
	db->user_data = user_data;
	db->add = blocks_db_add;
	db->remove = blocks_db_remove;
	db->find = blocks_db_find;
	db->set_txn = blocks_db_set_txn;
	
	bitcoin_blockchain_t * chain = user_data;
	DB_ENV * env = NULL;
	const char * db_name = NULL;	///< @todo load from settings
	if(chain) {
		env = chain->get_db_env(chain);
	}
	blocks_db_private_t * priv = blocks_db_private_new(db, env, db_name);
	assert(priv && (db->priv == priv));
	
	return db;
}

void bitcoin_blocks_db_cleanup(bitcoin_blocks_db_t * db)
{
	if(NULL == db) return;
	blocks_db_private_free(db->priv);
	db->priv = NULL;
	return;
}

/***********************************************************************
 * blockchain
 **********************************************************************/
typedef struct blockchain_private 
{
	bitcoin_blockchain_t * chain;
	char db_home[PATH_MAX];
	char blocks_dir[PATH_MAX];
	
	DB_ENV * env;
}blockchain_private_t;

blockchain_private_t * blockchain_private_new(bitcoin_blockchain_t * chain,
	const char * db_home, 
	const char *blocks_dir)
{
	blockchain_private_t * priv = calloc(1, sizeof(*priv));
	assert(priv);
	
	priv->chain = chain;
	chain->priv = priv;
	
	if(NULL == db_home) db_home = "data";
	if(NULL == blocks_dir) blocks_dir = "blocks";
	strncpy(priv->db_home, db_home, sizeof(priv->db_home));
	strncpy(priv->blocks_dir, blocks_dir, sizeof(priv->blocks_dir));
	
	int rc = 0;
	rc = check_path(db_home);		assert(0 == rc);
	rc = check_path(blocks_dir);	assert(0 == rc);
	return priv;
}

void blockchain_private_free(blockchain_private_t * priv)
{
	if(NULL == priv) return;
	free(priv);
	return;
}

static int blockchain_add(struct bitcoin_blockchain blockchain, const satoshi_block_t * block)
{
	return 0;
}

static int blockchain_remove(struct bitcoin_blockchain blockchain, const uint256_t * hash)
{
	return 0;
}

static void * get_db_env(bitcoin_blockchain_t * chain)
{
	assert(chain && chain->priv);
	blockchain_private_t * priv = chain->priv;
	return priv->env;
}

static blockchain_db_txn_t * open_db_txn(bitcoin_blockchain_t * chain, blockchain_db_txn_t * parent_txn, int flags)
{
	assert(chain && chain->priv);
	blockchain_private_t * priv = chain->priv;
	
	DB_ENV * env = priv->env;
	assert(env);
	
	if(-1 == flags) {	// use default settings
		flags = DB_READ_COMMITTED | DB_TXN_SYNC;
	}
	
	DB_TXN * db_txn = NULL;
	int rc = env->txn_begin(env, parent_txn, &db_txn, flags);
	if(rc) {
		env->err(env, rc, "%s() failed", __FUNCTION__);
		return NULL;
	}
	return db_txn;
}

static int commit_db_txn(bitcoin_blockchain_t * chain, blockchain_db_txn_t * txn)
{
	int rc = -1;
	assert(chain && chain->priv);
	blockchain_private_t * priv = chain->priv;
	
	DB_ENV * env = priv->env;
	assert(env);
	
	DB_TXN * db_txn = txn;
	if(db_txn)
	{
		rc = db_txn->commit(db_txn, 0);
		if(rc) {
			env->err(env, rc, "%s() failed", __FUNCTION__);
		}
	}
	return rc;
}

static int abort_db_txn(bitcoin_blockchain_t * chain, blockchain_db_txn_t * txn)
{
	int rc = -1;
	assert(chain && chain->priv);
	blockchain_private_t * priv = chain->priv;
	
	DB_ENV * env = priv->env;
	assert(env);
	
	DB_TXN * db_txn = txn;
	if(db_txn)
	{
		rc = db_txn->abort(db_txn);
		if(rc) {
			env->err(env, rc, "%s() failed", __FUNCTION__);
		}
	}
	return rc;
}

bitcoin_blockchain_t * bitcoin_blockchain_init(
	bitcoin_blockchain_t * chain, 
	uint32_t magic,
	const char * db_home,		// database home_dir
	const char * blocks_dir,	// to store block_nnnnn.dat files 
	ssize_t mempool_size,		
	void * user_data)
{
	if(NULL == chain) chain = calloc(1, sizeof(*chain));
	assert(chain);

	chain->add = blockchain_add;
	chain->remove = blockchain_remove;
	
	chain->get_db_env = get_db_env;
	chain->open_db_txn = open_db_txn;
	chain->commit_db_txn = commit_db_txn;
	chain->abort_db_txn = abort_db_txn;
	
	chain->magic = magic;
	chain->user_data = user_data;

	blockchain_private_t * priv = blockchain_private_new(chain, db_home, blocks_dir);
	assert(priv && (chain->priv == priv));
	
	if(NULL == db_home) db_home = priv->db_home;
	if(NULL == blocks_dir) blocks_dir = priv->blocks_dir;

	DB_ENV * env = init_db_env(db_home);
	assert(env);
	priv->env = env;

	bitcoin_utxo_db_t * utxo_db = bitcoin_utxo_db_init(chain->utxo_db, chain);
	bitcoin_blocks_db_t * blocks_db = bitcoin_blocks_db_init(chain->blocks_db, chain);
	assert(utxo_db && utxo_db == chain->utxo_db);
	assert(blocks_db && blocks_db == chain->blocks_db);

	return chain;
}

void bitcoin_blockchain_cleanup(bitcoin_blockchain_t * chain)
{
	if(NULL == chain) return;
	if(chain->utxo_db) 
	{
		bitcoin_utxo_db_cleanup(chain->utxo_db);
	}
	return;
}

#if defined(_TEST_BITCOIN_BLOCKCHAIN) && defined(_STAND_ALONE)

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <libgen.h>
int set_working_dir(const char * path)
{
	int rc = 0;
	char path_name[PATH_MAX] = "";
	if(NULL == path)
	{
		ssize_t cb = readlink("/proc/self/exe", path_name, sizeof(path_name));
		assert(cb > 0);
		
		path = dirname(path_name);
	}
	assert(path);
	
	rc = chdir(path);
	return rc;
}

void test_utxoes();
void test_blocks();
void test_blockchain();

int main(int argc, char ** argv)
{
	int rc = set_working_dir(NULL);
	assert(0 == rc);
	
	char db_home[PATH_MAX] = "data";
	check_path(db_home);
	
	//~ test_utxoes(NULL, db_home);
	//~ test_blocks(NULL, db_home);
	test_blockchain(db_home);
	
	if(s_db_env)
	{
		s_db_env->close(s_db_env, 0);
		s_db_env = NULL;
	}
	return 0;
}

void test_utxoes(bitcoin_utxo_db_t * utxo_db, const char * db_home)
{
	bitcoin_utxo_db_t * db = utxo_db;
	if(NULL == db) db = bitcoin_utxo_db_init(NULL, NULL);
	assert(db);
	
	utxo_db_private_t * priv = db->priv;
	assert(priv && db->priv == priv);
	
	int rc = 0;
	// prepare data
	uint256_t block_hashes[2];
	memset(block_hashes, 0, sizeof(block_hashes));
	//~ hash256("block1", 7, (unsigned char *)&block_hashes[0]);
	//~ hash256("block2", 7, (unsigned char *)&block_hashes[1]);
	strcpy((char *)&block_hashes[0], "block1");
	strcpy((char *)&block_hashes[1], "block2");
	
	struct satoshi_txout txouts[2];
	memset(txouts, 0, sizeof(txouts));
	
	struct satoshi_outpoint outpoints[2];
	memset(outpoints, 0, sizeof(outpoints));
	
	hash256("tx1", 4, (unsigned char *)&outpoints[0].prev_hash);
	outpoints[0].index = 123;
	
	hash256("tx2", 4, (unsigned char *)&outpoints[1].prev_hash);
	outpoints[1].index = 456;
	
	txouts[0].value = 10000;
	txouts[0].scripts = varstr_new((unsigned char []){4, 0x44, 0x33, 0x22, 0x11}, 5);
	
	txouts[1].value = 20000;
	txouts[1].scripts = varstr_new((unsigned char []){4, 0xab, 0xab, 0xab, 0xab}, 5);

	db_record_utxo_t utxo[1];
	memset(utxo, 0, sizeof(utxo));
	
	// deposit
	// add utxo
	DB_ENV * env = priv->env;
	DB_TXN * txn = NULL;
	int ret = env->txn_begin(env, NULL, &txn, 0);
	if(ret)
	{
		db_error(env, "txn_begin", "txn_begin_failed");
		exit(1);
	}
	db->set_txn(db, txn);
	rc = db->add(db, &block_hashes[0], &outpoints[0], &txouts[0]);
	assert(0 == rc);
	
	ret = txn->commit(txn, 0);
	if(ret)
	{
		db_error(env, "txn_commit", "commit failed");
		exit(1);
	}
	txn = NULL;
	
	
	// spend
	// -- find utxo
	
	db->set_txn(db, NULL);
	struct satoshi_txout txout[1];
	memset(txout, 0, sizeof(txout));
	uint256_t hash[1];
	memset(hash, 0, sizeof(hash));
	
	rc = db->find(db, &outpoints[0], txout, hash);
	assert(0 == rc);
	printf("txout: \n"
		"\t value=%" PRIi64 "\n"
		"\t cb_script=%u \n"
		"\t scripts=0x%.8x \n",
		txout->value,
		(unsigned int)varstr_length(txout->scripts),
		*(uint32_t *)varstr_getdata_ptr(txout->scripts));
	satoshi_txout_cleanup(txout);


	ret = env->txn_begin(env, NULL, &txn, 0);
	if(ret)
	{
		db_error(env, "txn_begin", "txn_begin_failed");
		exit(1);
	}
	db->set_txn(db, txn);
	
	// -- step 1. remove outpoint utxo
	rc = db->remove(db, &outpoints[0]);
	if(rc)
	{
		txn->abort(txn);
		exit(111);
	}
	// -- step 2. add new tx's utxoes
	rc = db->add(db, &block_hashes[1], &outpoints[1], &txouts[1]);
	if(rc)
	{
		txn->abort(txn);
		exit(112);
	}
	
	ret = txn->commit(txn, 0);
	if(ret)
	{
		db_error(env, "txn_commit", "commit failed");
		exit(1);
	}
	
	db->set_txn(db, NULL);
	
	memset(txout, 0, sizeof(txout));
	memset(hash, 0, sizeof(hash));
	
	rc = db->find(db, &outpoints[1], txout, hash);
	assert(0 == rc);
	printf("txouts[1]: \n"
		"\t value=%" PRIi64 "\n"
		"\t cb_script=%u \n"
		"\t scripts=0x%.8x \n",
		txout->value,
		(unsigned int)varstr_length(txout->scripts),
		*(uint32_t *)varstr_getdata_ptr(txout->scripts));
	satoshi_txout_cleanup(txout);
	
	
	// cleanup
	satoshi_txout_cleanup(&txouts[0]);
	satoshi_txout_cleanup(&txouts[1]);
	
	if(NULL == utxo_db)
	{
		bitcoin_utxo_db_cleanup(db);
		free(db);
	}
	return;
}


ssize_t load_block(const char * data_file, satoshi_block_t * block)
{
	/**
	 * generate block's hex data
	 * $ bitcoin-cli getblock `bitcoin-cli getblockhash 100000` 0 > block-100000.hex
	**/

	if(NULL == data_file) data_file = "block-100000.hex";	// without block_file_hdr
	FILE * fp = fopen(data_file, "rb");
	assert(fp);
	fseek(fp, 0, SEEK_END);
	ssize_t file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	
	assert(file_size > 0);
	char * hex = malloc(file_size + 1);
	ssize_t cb = fread(hex, 1, file_size, fp);
	assert(cb == file_size);
	fclose(fp);
	
	hex[cb] = '\0';
	while(cb > 0 && (hex[cb - 1] == '\r' || hex[cb - 1] == '\n')) hex[--cb] = '\0';
	assert((cb % 2) == 0);
	
	unsigned char * data = NULL;
	cb = hex2bin(hex, cb, (void **)&data);
	assert(cb > 0);
	
	ssize_t block_size = satoshi_block_parse(block, cb, data);
	assert(block_size);
	
	return block_size;
}


void test_blocks(bitcoin_blocks_db_t * blocks_db, const char * db_home)
{
	static int block_height = 100000;
	
	// prepare data
	satoshi_block_t block[1];
	memset(block, 0, sizeof(block));
	ssize_t block_size = load_block(NULL, block);
	
	bitcoin_blocks_db_t * db = blocks_db;
	if(NULL == db)
	{
		db = bitcoin_blocks_db_init(NULL, NULL);
		assert(db);
	}
	
	blocks_db_private_t * priv = db->priv;
	assert(priv && db->priv == priv);
	
//	DB_ENV * env = priv->env;
	DBT key, value;
	memset(&key, 0, sizeof(key));
	memset(&value, 0, sizeof(value));
	
	int rc = 0;
	// 1. add block
	rc = db->add(db, 
		&block->hash, 
		block_height, 
		&block->hdr,
		0, 0,
		BITCOIN_MESSAGE_MAGIC_MAINNET,
		block_size);
	assert(0 == rc);
	
	// 2. find block
	rc = db->find(db, &block->hash, NULL); 
	assert(0 == rc);
	
	// 3. remove block
	rc = db->remove(db, &block->hash);
	assert(0 == rc);
	
	// 4. add and replace 
	rc = db->add(db, &block->hash, 
		block_height, 
		&block->hdr,
		0, 0,
		BITCOIN_MESSAGE_MAGIC_MAINNET,
		block_size);
	assert(0 == rc);
	
	rc = db->add(db, &block->hash, 
		1, 	// update block_height to 1
		&block->hdr,
		0, 0,
		BITCOIN_MESSAGE_MAGIC_MAINNET,
		block_size);
	assert(0 == rc);
	
	if(NULL == blocks_db)
	{
		bitcoin_blocks_db_cleanup(db);
		free(db);
	}
	
	satoshi_block_cleanup(block);
	return;
}

void test_blockchain(const char * db_home)
{
	static const char * blocks_dir = "blocks";
	bitcoin_blockchain_t * chain = bitcoin_blockchain_init(NULL, 
		BITCOIN_MESSAGE_MAGIC_MAINNET,
		db_home, blocks_dir, 0, NULL);
	assert(chain);
	
	test_utxoes(chain->utxo_db, NULL);
	test_blocks(chain->blocks_db, NULL);
	
	bitcoin_blockchain_cleanup(chain);
	free(chain);

	return;
}
#endif
