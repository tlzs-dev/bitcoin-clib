/*
 * db_engine.c
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

#include <db.h>
#include <pthread.h>

#include <sys/types.h>
#include <unistd.h>
#include <limits.h>

#include "db_engine.h"

typedef struct db_engine_private
{
	DB_ENV * env;
	pthread_mutex_t mutex;
	db_engine_t * engine;
	
	char home_dir[PATH_MAX];
	u_int32_t env_flags;
	
	ssize_t max_size;
	ssize_t count;
	db_handle_t ** databases;
	
	db_handle_t * log_db;
	char error_desc[4096];	//  last error description
}db_engine_private_t;

static inline DB_ENV * db_engine_get_env(db_engine_t * engine) { return *(DB_ENV **)engine->priv; }


/**************************************************
 * struct db_engine_txn
 **************************************************/
static inline DB_TXN * db_txn_get_handle(struct db_engine_txn * txn)
{
	return txn->priv;
}

static int txn_begin(struct db_engine_txn * txn, struct db_engine_txn * parent_txn)
{
	assert(txn && txn->engine);
	assert(NULL == txn->priv);
	
	DB_ENV * env = db_engine_get_env(txn->engine);
	assert(env);
	
	DB_TXN * parent = parent_txn?parent_txn->priv:NULL;
	int rc = env->txn_begin(env, parent, (DB_TXN **)&txn->priv, DB_READ_COMMITTED | DB_TXN_SYNC);
	if(rc) {
		env->err(env, rc, "%s() failed.", __FUNCTION__);
	}
	return rc;
}

static int txn_commit(struct db_engine_txn * txn, int flags)
{
	int rc = -1;
	DB_TXN * db_txn = txn->priv;
	if(db_txn) {
		rc = db_txn->commit(db_txn, flags);
		txn->priv = NULL;
		if(rc) {
			DB_ENV * env = db_engine_get_env(txn->engine);
			assert(env);
			
			env->err(env, rc, "%s() failed.", __FUNCTION__);
		}
	}
	return rc;
}
static int txn_abort(struct db_engine_txn * txn)
{
	int rc = -1;
	DB_TXN * db_txn = txn->priv;
	if(db_txn) {
		rc = db_txn->abort(db_txn);
		txn->priv = NULL;
		if(rc) {
			DB_ENV * env = db_engine_get_env(txn->engine);
			assert(env);
			
			env->err(env, rc, "%s() failed.", __FUNCTION__);
		}
	}
	return rc;
}

static int txn_prepare(struct db_engine_txn * txn, unsigned char gid[])
{
	int rc = -1;
	DB_TXN * db_txn = txn->priv;
	if(db_txn) {
		rc = db_txn->prepare(db_txn, gid);
		if(rc) {
			DB_ENV * env = db_engine_get_env(txn->engine);
			assert(env);
			
			env->err(env, rc, "%s() failed.", __FUNCTION__);
		}
	}
	return rc;
}

static int txn_discard(struct db_engine_txn * txn)
{
	int rc = -1;
	DB_TXN * db_txn = txn->priv;
	if(db_txn) {
		rc = db_txn->discard(db_txn, 0);
		txn->priv = NULL;
		if(rc) {
			DB_ENV * env = db_engine_get_env(txn->engine);
			assert(env);
			
			env->err(env, rc, "%s() failed.", __FUNCTION__);
		}
	}
	return rc;
}

static int txn_set_name(struct db_engine_txn * txn, const char * name)
{
	int rc = -1;
	DB_TXN * db_txn = txn->priv;
	if(db_txn) {
		rc = db_txn->set_name(db_txn, name);
		if(rc) {
			DB_ENV * env = db_engine_get_env(txn->engine);
			assert(env);
			
			env->err(env, rc, "%s() failed.", __FUNCTION__);
		}
	}
	return rc;
}
static const char * txn_get_name(struct db_engine_txn * txn)
{
	int rc = -1;
	const char * name = NULL;
	DB_TXN * db_txn = txn->priv;
	if(db_txn) {
		rc = db_txn->get_name(db_txn, &name);
		if(rc) {
			DB_ENV * env = db_engine_get_env(txn->engine);
			assert(env);
			
			env->err(env, rc, "%s() failed.", __FUNCTION__);
		}
	}
	return name;
}

db_engine_txn_t * db_engine_txn_init(db_engine_txn_t * txn, struct db_engine * engine)
{
	if(NULL == txn) txn = calloc(1, sizeof(*txn));
	txn->engine = engine;
	
	txn->begin = txn_begin;
	txn->commit = txn_commit;
	txn->abort = txn_abort;
	txn->prepare = txn_prepare;
	txn->discard = txn_discard;
	txn->set_name = txn_set_name;
	txn->get_name = txn_get_name;
	
	return txn;
}
void db_engine_txn_cleanup(db_engine_txn_t * txn)
{
	DB_TXN * db_txn = txn->priv;
	if(db_txn) {
		db_txn->discard(db_txn, 0);
	}
	txn->priv = NULL;
	return;
}

/****************************************************************
 * struct db_handle
****************************************************************/
typedef struct db_private
{
	DB * dbp;
	struct db_handle * db;
	int db_type;
	
	pthread_mutex_t mutex;
	char name[PATH_MAX];
	
	db_associate_callback associate_func;
}db_private_t;
static inline DB * db_get_handle(struct db_handle * db) 
{ 
	assert(db && db->priv);
	DB * dbp = ((db_private_t *)db->priv)->dbp;
	assert(dbp);
	return dbp;
}

#define db_lock(db)			pthread_mutex_lock(&((db_private_t *)db->priv)->mutex)
#define db_unlock(db)		pthread_mutex_unlock(&((db_private_t *)db->`priv)->mutex)

db_private_t * db_private_new(db_handle_t * db)
{
	assert(db);
	DB * dbp = NULL;
	DB_ENV * env = db_engine_get_env(db->engine);
	int rc = db_create(&dbp, env, 0);
	if(rc || NULL == dbp ) {
		env->err(env, rc, "%s()::db_create() failed.\n", __FUNCTION__);
		return NULL;
	}
	
	db_private_t * priv = calloc(1, sizeof(*priv));
	assert(priv);
	priv->db = db;
	priv->dbp = dbp;
	rc = pthread_mutex_init(&priv->mutex, NULL);
	assert(0 == rc);
	
	db->priv = priv;
	return priv;
}

void db_private_free(db_private_t * priv)
{
	if(NULL == priv) return;
	pthread_mutex_lock(&priv->mutex);
	if(priv->dbp) {
		priv->dbp->close(priv->dbp, 0);
	}
	pthread_mutex_unlock(&priv->mutex);
	
	pthread_mutex_destroy(&priv->mutex);
	free(priv);
	return;
}

static int db_open(struct db_handle * db, db_engine_txn_t * txn, const char * name, int db_type, int flags)
{
	assert(db && db->priv && name);
	int rc = -1;
	db_private_t * priv = db->priv;
	DB * dbp = priv->dbp;
	assert(dbp);
	
	
	switch(db_type)
	{
	case 0: priv->db_type = DB_BTREE; break;
	case 1: priv->db_type = DB_HASH; break;
	default:
		priv->db_type = DB_UNKNOWN;
	}
	
	if(flags <= 0) flags = DB_CREATE | DB_AUTO_COMMIT;
	rc = dbp->open(dbp, db_txn_get_handle(txn), name, NULL, priv->db_type, flags, 0660);
	if(rc) {
		DB_ENV * env = db_engine_get_env(db->engine);
		assert(env);
		env->err(env, rc, "%s() failed.\n", __FUNCTION__);
	}
	
	return rc;
}

static inline db_handle_t * db_engine_find_db(db_engine_t * engine, DB * dbp)
{
	assert(engine && engine->priv && dbp);
	db_engine_private_t * priv = engine->priv;
	
	for(int i = 0; i < priv->count; ++i)
	{
		if(dbp == db_get_handle(priv->databases[i])) return priv->databases[i];
	}
	return NULL;
}


static int secondary_db_get_key(DB * secondary, const DBT * key, const DBT * value, DBT * result)
{
	db_engine_t * engine = db_engine_get();
	assert(engine);
	
	db_handle_t * db = db_engine_find_db(engine, secondary);
	assert(db && db->priv);
	
	db_private_t * priv = db->priv;
	assert(priv->associate_func);
	
	void * skey = NULL;
	ssize_t cb_skey = 0;
	
	int rc = priv->associate_func(db, 
		key->data, key->size, value->data, value->size,
		&skey, &cb_skey);
	assert(0 == rc);
	
	result->data = skey;
	result->size = cb_skey;
	return 0;
}


static int db_associate(struct db_handle * primary, db_engine_txn_t * txn, 
	struct db_handle * secondary, db_associate_callback associated_by)
{
	db_private_t * priv = secondary->priv;
	priv->associate_func = associated_by;
	
	DB * dbp = db_get_handle(primary);
	DB * sdbp = db_get_handle(secondary);
	int rc = dbp->associate(dbp, db_txn_get_handle(txn), sdbp, secondary_db_get_key, DB_CREATE);
	
	return rc;
}
static int db_close(struct db_handle * db)
{
	return 0;
}
static int db_find(struct db_handle * db, 
	const void * key, size_t cb_key,
	void ** p_value, size_t * cb_value)
{
	return 0;
}

static int db_find_secondary(struct db_handle * db, 
	const void * skey, size_t cb_skey,		// the key of secondary database
	void * p_key, ssize_t * cb_key,			// if need return the key of the primary database
	void ** p_value, ssize_t * cb_value)
{
	return 0;
}
	

static int db_insert(struct db_handle * db, 
	const void * key, size_t cb_key, 
	const void * value, size_t cb_value)
{
	return 0;
}

static int db_update(struct db_handle * db, 
	const void * key, size_t cb_key, 
	const void * value, size_t cb_value)
{
	return 0;
}

static int db_del(struct db_handle * db, const void * key, size_t cb_key)
{
	return 0;
}



db_handle_t * db_handle_init(db_handle_t * db, db_engine_t * engine, void * user_data)
{
	if(NULL == db) db = calloc(1, sizeof(*db));
	assert(db);
	db->user_data = user_data;
	db->engine = engine;
	
	db->open = db_open;
	db->associate = db_associate;
	db->close = db_close;
	db->find = db_find;
	db->find_secondary = db_find_secondary;
	db->insert = db_insert;
	db->update = db_update;
	db->del = db_del;
	
	db_private_t * priv = db_private_new(db);
	assert(priv && db->priv == priv);
	
	return db;
}
void db_handle_cleanup(db_handle_t * db)
{
	return;
}


/*****************************************************************
 * struct db_engine
****************************************************************/


#define DB_ENGINE_ALLOC_SIZE	(64)
static int db_engine_resize(db_engine_t * engine, int new_size)
{
	assert(engine && engine->priv);
	db_engine_private_t * priv = engine->priv;
	
	if(new_size <= 0) new_size = DB_ENGINE_ALLOC_SIZE;
	else new_size = (new_size + DB_ENGINE_ALLOC_SIZE - 1) / DB_ENGINE_ALLOC_SIZE * DB_ENGINE_ALLOC_SIZE;
	
	if(new_size < priv->max_size) return 0;
	
	db_handle_t ** dbs = realloc(priv->databases, new_size * sizeof(*dbs));
	assert(dbs);
	
	memset(dbs, 0, (new_size - priv->max_size) * sizeof(*dbs));
	priv->databases	 = dbs;
	priv->max_size = new_size;
	return 0;
}

static db_engine_private_t * db_engine_private_new(db_engine_t * engine)
{
	db_engine_private_t * priv = calloc(1, sizeof(*priv));
	assert(priv);
	
	int rc = db_env_create(&priv->env, 0);
	assert(0 == rc);
	
	// set default evn_flags
	priv->env_flags = DB_CREATE 
		| DB_INIT_MPOOL 
		| DB_INIT_LOG
		| DB_INIT_LOCK
		| DB_INIT_TXN
		| DB_RECOVER
		| DB_REGISTER
		| DB_THREAD
		| 0;
	
	rc = pthread_mutex_init(&priv->mutex, NULL);
	assert(0 == rc);
	
	db_engine_resize(engine, 0);
	
	return priv;
}

static void db_engine_private_free(db_engine_private_t * priv)
{
	if(NULL == priv) return;
	
	pthread_mutex_lock(&priv->mutex);
	for(int i = 0; i < priv->count; ++i)
	{
		db_handle_t * db = priv->databases[i];
		if(db)
		{
			db_handle_cleanup(db);
			free(db);
			priv->databases[i] = NULL;
		}
	}
	priv->count = 0;
	pthread_mutex_unlock(&priv->mutex);
	
	pthread_mutex_destroy(&priv->mutex);
	free(priv);
}

static int engine_set_home(struct db_engine * engine, const char * home_dir)
{
	return 0;
}

static db_handle_t * engine_open_db(struct db_engine * engine, const char * db_name, int db_type, int flags)
{
	return NULL;
}
static int engine_close_db(db_handle_t * db)
{
	return 0;
}

static db_engine_txn_t * engine_txn_new(struct db_engine * engine, struct db_engine_txn * parent_txn)
{
	db_engine_txn_t * txn = db_engine_txn_init(NULL, engine);
	assert(txn);
	
	int rc = txn->begin(txn, parent_txn);
	if(rc)
	{
		db_engine_txn_cleanup(txn);
		free(txn);
		txn = NULL;
	}
	return txn;
}
static void engine_txn_free(struct db_engine * engine, db_engine_txn_t * txn)
{
	if(txn)
	{
		db_engine_txn_cleanup(txn);
		free(txn);
	}
	return;
}


static db_engine_t g_db_engine[1] = {{
	.set_home = engine_set_home,
	.open_db = engine_open_db,
	.close_db = engine_close_db,
	.txn_new = engine_txn_new,
	.txn_free = engine_txn_free,
}};
db_engine_t * db_engine_get() { return g_db_engine; }
#define db_engine_add_ref(engine)  do { ++engine->refs_count; } while(0)
#define db_engine_unref(engine)		db_engine_cleanup(engine)


db_engine_t * db_engine_init(const char * home_dir, void * user_data)
{
	db_engine_t * engine = g_db_engine;
	engine->user_data = user_data;

	db_engine_private_t * priv = db_engine_private_new(engine);
	assert(priv && engine->priv == priv);

	if(home_dir) engine->set_home(engine, home_dir);
	return engine;
}

void db_engine_cleanup(db_engine_t * engine)
{
	if(0 == engine->refs_count) return;
	
	if(--engine->refs_count == 0)
	{
		db_engine_private_free(engine->priv);
		engine->priv = NULL;
		engine->user_data = NULL;
	}
	
	return;
}

#if defined(_TEST_DB_ENGINE) && defined(_STAND_ALONE)
int main(int argc, char **argv)
{
	
	return 0;
}
#endif
