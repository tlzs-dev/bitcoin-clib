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

#include "bitcoin-consensus.h"
#include "satoshi-types.h"
#include "utils.h"

#include "blockchain.h"

#include <search.h>
#include <db.h>

#define BLOCKCHAIN_ALLOC_SIZE			(65536)

static void db_error(const DB_ENV * env, 
	const char * errpfx, const char * msg)
{
	fprintf(stderr, "\e[33m" "%s: %s" "\e[39m" "\n", errpfx, msg);
	return;
}

/******************************************
 * db_record_utxo
 *****************************************/
struct db_record_utxo * db_record_utxo_new(
	const uint256_t * block_hash, 
	const satoshi_outpoint_t *outpoint, 
	const satoshi_txout_t * txout)
{
	uint32_t cb_script = txout?0:txout->cb_script;
	struct db_record_utxo * utxo = calloc(
		sizeof(*utxo) + cb_script, // allocate additional size for scripts data
		1); 
	assert(utxo);
	
	utxo->cb_script = cb_script;
	if(cb_script && txout && txout->scripts)
	{
		memcpy(utxo->pk_scripts, txout->scripts, cb_script);
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



static pthread_once_t s_once_key = PTHREAD_ONCE_INIT;
static DB_ENV * s_db_env;
static const char s_db_home[PATH_MAX] = "data";

static int utxo_record_get_block_hash(DB *sdbp,
    const DBT *key, const DBT *value, DBT *result)
{
	memset(result, 0, sizeof(*result));
	result->data = (void *)value->data;
	
	result->size = sizeof(uint256_t);
	return 0;
}

static void init_db_env_default(void)
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
	
	const char * home_dir = s_db_home;
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
	ret = env->open(env, home_dir, flags, mode);
	if(ret)
	{
		fprintf(stderr, "[DB::ERROR]: %s\n", db_strerror(ret));
		env->close(env, 0);
		return;
	}
	
	env->set_errpfx(env, "[DB::ERROR]");
	env->set_errcall(env, db_error);

	s_db_env = env;
	return;
}


static utxo_db_private_t * utxo_db_private_new(bitcoin_utxo_db_t * db, DB_ENV * env, const char * db_name)
{
	if(NULL == env)
	{
		pthread_once(&s_once_key, init_db_env_default);
		env = s_db_env;
		assert(env);
	}
	
	int rc;
	if(NULL == db_name) db_name = "utxo.db";
	utxo_db_private_t * priv = calloc(1, sizeof(*priv));
	assert(priv);
	
	priv->db = db;
	db->priv = priv;
	
	DB * dbp = NULL;		// primary db
	DB * sdbp = NULL;		// secondary db
	
	rc = db_create(&dbp, env, 0);
	if(rc)
	{
		env->err(env, rc, NULL);
		exit(1);
	}
	
	u_int32_t flags = DB_CREATE 
		| DB_READ_UNCOMMITTED
		| DB_AUTO_COMMIT;
	
	rc = dbp->open(dbp, NULL, db_name, NULL, 
		DB_HASH, 
		flags,
		0666);
	if(rc)
	{
		env->err(env, rc, NULL);
		exit(1);
	}
	
	char sdb_name[PATH_MAX] = "";
	int cb = snprintf(sdb_name, sizeof(sdb_name), "blocks-%s", db_name);
	assert(cb >= 0 && cb < PATH_MAX);
	
	rc = db_create(&sdbp, env, 0);
	if(rc)
	{
		env->err(env, rc, NULL);
		exit(1);
	}
	rc = sdbp->set_flags(sdbp, DB_DUPSORT);
	if(rc)
	{
		env->err(env, rc, NULL);
		exit(1);
	}
	
	rc = sdbp->open(sdbp, NULL, 
		sdb_name, NULL,
		DB_HASH, 
		flags, 
		0666);
	if(rc)
	{
		env->err(env, rc, NULL);
		exit(1);
	}
	
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
	
	int txn_mode = dbp->get_transactional(dbp);
	assert(txn_mode != 0);	// primary db MUST support DB transaction operation
	
	txn_mode = sdbp->get_transactional(sdbp);
	assert(txn_mode != 0);	// secondary db MUST support DB transaction operation
	
	strncpy(priv->db_name, db_name, sizeof(priv->db_name));
	return priv;
}

void utxo_db_private_free(utxo_db_private_t * priv)
{
	if(NULL == priv) return;
	int rc = 0;
	DB_ENV * env = priv->env;
	if(priv->sdbp) // close secondary db before primary
	{
		
		rc = priv->sdbp->close(priv->sdbp, 0);
		if(rc)
		{
			env->err(env, rc, NULL);
		//	exit(1);
		}
		priv->sdbp = NULL;
	}
	
	if(priv->dbp)
	{
		rc = priv->dbp->close(priv->dbp, 0);
		if(rc)
		{
			env->err(env, rc, NULL);
		//	exit(1);
		}
		priv->dbp = NULL;
	}
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
	DB_ENV * env = priv->env;
	
	ret = dbp->put(dbp, priv->txn, &key, &value, 0);
	if(ret)
	{
		db_error(env, "dbp->put()", "put utxo failed");
	}
	
	db_record_utxo_free(utxo);
	return ret;
}

int utxo_db_remove(struct bitcoin_utxo_db * db, const struct satoshi_outpoint * outpoint)
{
	return 0;
}

int utxo_db_find(struct bitcoin_utxo_db * db, const satoshi_outpoint_t * outpoint, db_record_utxo_t * utxo)
{
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
	
	
	utxo_db_private_t * priv = utxo_db_private_new(db, NULL, NULL);
	assert((db->priv == priv)); 
	
	
	return db;
}
void bitcoin_utxo_db_cleanup(bitcoin_utxo_db_t * db)
{
	if(NULL == db) return;
	utxo_db_private_free(db->priv);
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

int check_path(const char * path)
{
	assert(path);
	char command[100 + PATH_MAX] = "";
	snprintf(command, sizeof(command), "mkdir -p \"%s\"", path); 
	int rc = system(command);
	assert(0 == rc);
	return rc;
}


void test_utxoes();
int main(int argc, char ** argv)
{
	int rc = set_working_dir(NULL);
	assert(0 == rc);
	
	char db_home[PATH_MAX] = "data";
	check_path(db_home);
	
	bitcoin_utxo_db_t * utxoes_db = bitcoin_utxo_db_init(NULL, NULL);
	assert(utxoes_db);
	
	test_utxoes(utxoes_db);
	
	
	bitcoin_utxo_db_cleanup(utxoes_db);
	
	
	if(s_db_env)
	{
		s_db_env->close(s_db_env, 0);
	}
	return 0;
}

void test_utxoes(bitcoin_utxo_db_t * db)
{
	int rc = 0;
	// prepare data
	uint256_t block_hashes[2];
	memset(block_hashes, 0, sizeof(block_hashes));
	hash256("block1", 7, (unsigned char *)&block_hashes[0]);
	hash256("block2", 7, (unsigned char *)&block_hashes[1]);
	
	struct satoshi_txout txouts[2];
	memset(txouts, 0, sizeof(txouts));
	
	struct satoshi_outpoint outpoints[2];
	memset(outpoints, 0, sizeof(outpoints));
	
	hash256("tx1", 4, (unsigned char *)&outpoints[0].prev_hash);
	outpoints[0].index = 123;
	
	hash256("tx2", 4, (unsigned char *)&outpoints[1].prev_hash);
	outpoints[1].index = 456;
	
	txouts[0].value = 10000;
	txouts[0].cb_script = 4;
	txouts[0].scripts = calloc(4, 1);
	*(uint32_t *)txouts[0].scripts = 0x11223344;
	
	txouts[1].value = 10000;
	txouts[1].cb_script = 4;
	txouts[1].scripts = calloc(4, 1);
	*(uint32_t *)txouts[1].scripts = 0x11223344;
	
	db_record_utxo_t utxo[1];
	memset(utxo, 0, sizeof(utxo));
	
	// deposit
	// add utxo
	DB_ENV * env = s_db_env;
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
	rc = db->find(db, &outpoints[0], utxo);
	assert(0 == rc);

	
	// -- step 1. remove outpoint utxo
	
	ret = env->txn_begin(env, NULL, &txn, 0);
	if(ret)
	{
		db_error(env, "txn_begin", "txn_begin_failed");
		exit(1);
	}
	
	db->set_txn(db, txn);
	rc = db->remove(db, &outpoints[0]);
	if(!rc)
	{
		txn->abort(txn);
		exit(111);
	}
	// -- step 2. add new tx's utxoes
	rc = db->add(db, &block_hashes[1], &outpoints[1], &txouts[1]);
	if(!rc)
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
	
	return;
}

#endif
