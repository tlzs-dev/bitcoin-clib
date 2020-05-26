/*
 * db-helpler.c
 * 
 * Copyright 2020 Che Hongwei <htc.chehw@gmail.com>
 * 
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person 
 * obtaining a copy of this software and associated documentation 
 * files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, 
 * publish, distribute, sublicense, and/or sell copies of the Software, 
 * and to permit persons to whom the Software is furnished to do so, 
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 *  in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR 
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "utils.h"
#include "db-helpler.h"
#include "crypto.h"

typedef struct db_helpler
{
	void * user_data;
	char * home_dir;
	DB_ENV * env;
	
//	pthread_mutex_t mutex;
	size_t max_size;
	size_t count;
	DB ** dbs;
	char ** db_names;
	
	int (* on_cleanup)(struct db_helpler * db);
	
}db_helpler_t;

#define db_error_exit(env, ret) do { \
		if (ret) { env->err(env, ret, NULL); exit(1); } \
	} while(0)

db_helpler_t * db_helpler_init(db_helpler_t * db, const char * home_dir, size_t max_size, void * user_data);
void db_helpler_cleanup(db_helpler_t * db);

static pthread_mutex_t s_db_mutex = PTHREAD_MUTEX_INITIALIZER;
static db_helpler_t s_db_helpler[1] = {{
	.home_dir = NULL,
//	.mutex = PTHREAD_MUTEX_INITIALIZER,
	.max_size = 0,
	.count = 0,
	
	.on_cleanup = NULL,
}};

static void db_error(const DB_ENV * env, const char * errpfx, const char * msg)
{
	fprintf(stderr, "\e[33m" "%s: %s" "\e[39m" "\n", errpfx, msg);
	return;
}

#define DB_HELPLER_ALLOC_SIZE	(64)
int db_helpler_resize(db_helpler_t * db, size_t new_size)
{
	if(new_size == 0) new_size = DB_HELPLER_ALLOC_SIZE;
	else new_size = (new_size + DB_HELPLER_ALLOC_SIZE - 1) / DB_HELPLER_ALLOC_SIZE * DB_HELPLER_ALLOC_SIZE;
	if(new_size <= db->max_size) return 0;
	
	pthread_mutex_lock(&s_db_mutex);
	
	DB ** dbs = realloc(db->dbs, new_size * sizeof(db->dbs[0]));
	assert(dbs);
	memset(dbs + db->max_size, 0, (new_size - db->max_size) * sizeof(db->dbs[0]));
	
	db->dbs = dbs;
	db->max_size = new_size;
	
	pthread_mutex_unlock(&s_db_mutex);
	return 0;
}


db_helpler_t * db_helpler_init(db_helpler_t * db, const char * home_dir, size_t max_size, void * user_data)
{
	if(NULL == db) db = s_db_helpler;
	DB_ENV * env = db->env;
	
	int ret = 0;
	if(NULL == home_dir) home_dir = "data";
	if(NULL == env || NULL == db->home_dir || strcmp(home_dir, db->home_dir))
	{
		db->env = NULL;
		if(NULL == db->home_dir || strcmp(home_dir, db->home_dir))
		{
			if(db->home_dir) free(db->home_dir);
			db->home_dir = strdup(home_dir);
		}
		
		if(env)
		{
			env->close(env, 0);
			env = NULL;
		}
		
		ret = db_env_create(&env, 0);
		assert(0 == ret && env);
			
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
			return NULL;
		}
		db->env = env;
		env->app_private = db;
		
		env->set_errpfx(env, "[DB::ERROR]");
		env->set_errcall(env, db_error);
	}
	
	db->user_data = user_data;
	ret = db_helpler_resize(db, max_size);
	assert(0 == ret);
	return db;
}

void db_helpler_cleanup(db_helpler_t * db)
{
	if(NULL == db) return;
	
	pthread_mutex_lock(&s_db_mutex);
//	pthread_mutex_lock(&db->mutex);
	
	if(db->on_cleanup)
	{
		db->on_cleanup(db);
	}
	
//	pthread_mutex_unlock(&db->mutex);
	if(db != s_db_helpler)
	{
//		pthread_mutex_destroy(&db->mutex);
		free(db);
	}
	
	pthread_mutex_unlock(&s_db_mutex);
	return;
}


#if defined(_TEST_DB_HELPLER) && defined(_STAND_ALONE)


typedef struct utxo_record
{
	uint8_t tx_hash[32];
	int32_t index;
	
	uint32_t length;
	uint8_t tx_out[0];
}utxo_record_t;

typedef struct tx_record
{
	uint8_t tx_hash[32];
	uint8_t block_hash[32];
	int32_t block_index;
	
	uint32_t length;
	uint8_t data[0];
}tx_record_t;

#define utxo_record_size(utxo) 	((size_t)(&((utxo_record_t *)NULL)->tx_out) + utxo->length)
#define tx_record_size(tx)		((size_t)(&((tx_record_t * )NULL)->data) + tx->length)

#define calc_record_size(type, data_len)	((size_t)(&((type *)NULL)->length) + sizeof( ((type *)NULL)->length) + data_len)


db_helpler_t * do_init(void);
void test_db(db_helpler_t * db);
void do_cleanup(db_helpler_t * db);

int main(int argc, char ** argv)
{
	db_helpler_t * db = do_init();
	test_db(db);
	
	do_cleanup(db);
	return 0;
}

void do_cleanup(db_helpler_t * db)
{
	DB * utxo_db = db->dbs[0];
	DB * tx_db = db->dbs[1];
	if(utxo_db) utxo_db->close(utxo_db, 0);
	if(tx_db)   tx_db->close(tx_db, 0);
	
	db->dbs[0] = NULL;
	db->dbs[1] = NULL;
	db_helpler_cleanup(db);
}


db_helpler_t * do_init(void)
{
	db_helpler_t * db = db_helpler_init(NULL, NULL, 0, NULL);
	assert(db);
	
	DB_ENV * env = db->env;
	DB * utxo_db = NULL;
	int rc = 0;
	
	rc = db_create(&utxo_db, env, 0);
	if(rc)
	{
		env->err(env, rc, NULL);
		exit(1);
	}
	
	// rc = env->dbremove(env, NULL, "utxo.db", NULL, DB_AUTO_COMMIT);
	
	rc = utxo_db->open(utxo_db, NULL, "utxo.db", NULL, 
		DB_HASH, 
		DB_AUTO_COMMIT | DB_CREATE,
		0666);
	if(rc)
	{
		env->err(env, rc, NULL);
		exit(1);
	}
	
	DB * tx_db = NULL;
	rc = db_create(&tx_db, env, 0);
	if(rc)
	{
		env->err(env, rc, NULL);
		exit(1);
	}
	
	rc = tx_db->open(tx_db, NULL, "tx.db", NULL, 
		DB_HASH, 
		DB_AUTO_COMMIT | DB_CREATE,
		0666);
	db_error_exit(env, rc);
	
	//~ utxo_db->app_private = db;
	//~ tx_db->app_private = db;
	
	db->count = 2;
	db->dbs[0] = utxo_db;
	db->dbs[1] = tx_db;
	
	
	return db;
}

utxo_record_t * utxo_record_new(uint32_t length, const uint8_t * data)
{
	utxo_record_t * utxo = NULL;
	size_t data_size = calc_record_size(utxo_record_t, length);
	assert(data_size > 0);
	utxo = calloc(1, data_size);
	assert(utxo);
	if(length)
	{
		utxo->length = length;
		if(data) memcpy(utxo->tx_out, data, length);
	}
	return utxo;
}

utxo_record_t * utxo_record_set_data(utxo_record_t * utxo, uint32_t length, const uint8_t * data)
{
	if(NULL == utxo) return utxo_record_new(length, data);
	if(length != utxo->length)
	{
		size_t data_size = calc_record_size(utxo_record_t, length);
		assert(data_size > 0);
		
		utxo = realloc(utxo, data_size);
		assert(utxo);
		
		utxo->length = length;
	}
	if(data) memcpy(utxo->tx_out, data, length);
	return utxo;
}


tx_record_t * tx_record_new(uint32_t length, const uint8_t * data)
{
	tx_record_t * tx = NULL;
	size_t data_size = calc_record_size(tx_record_t, length);
	assert(data_size > 0);
	tx = calloc(1, data_size);
	assert(tx);
	if(length)
	{
		tx->length = length;
		if(data) memcpy(tx->data, data, length);
	}
	return tx;
}

tx_record_t * tx_record_set_data(tx_record_t * tx, uint32_t length, const uint8_t * data)
{
	if(NULL == tx) return tx_record_new(length, data);
	if(length != tx->length)
	{
		size_t data_size = calc_record_size(tx_record_t, length);
		assert(data_size > 0);
		
		tx = realloc(tx, data_size);
		assert(tx);
		
		tx->length = length;
	}
	if(data) memcpy(tx->data, data, length);
	return tx;
}


void test_db(db_helpler_t * db)
{
	int ret = 0;
	DB_ENV * env = db->env;
	DB * utxo_db = db->dbs[0];
	DB * tx_db = db->dbs[1];
	assert(utxo_db && tx_db);
	
	uint8_t scripts[4096] = "data1";
	int32_t length = 100;
	
	utxo_record_t * utxo = utxo_record_new(length, scripts);
	assert(utxo);
	
	tx_record_t * tx = tx_record_new(length, scripts);
	assert(tx);
	
	DBT key, value;
	memset(&key, 0, sizeof(key));
	memset(&value, 0, sizeof(value));
	
	key.data = utxo->tx_hash;
	key.size = sizeof(utxo->tx_hash) + sizeof(utxo->index);
	
	value.data = &utxo->length;
	value.size = sizeof(utxo->length) + length;
	
	hash256("hello world", 12, utxo->tx_hash);
	ret = utxo_db->put(utxo_db, NULL, &key, &value, DB_NOOVERWRITE);
	
	if(ret == DB_KEYEXIST)
	{
		db->env->err(db->env, ret, NULL);
	}else
	{
		db_error_exit(db->env, ret);
	}
	
	hash256("from chehw", 11, utxo->tx_hash);
	ret = utxo_db->put(utxo_db, NULL, &key, &value, DB_NOOVERWRITE);
	
	if(ret == DB_KEYEXIST)
	{
		db->env->err(db->env, ret, NULL);
	}else
	{
		db_error_exit(db->env, ret);
	}
	
	
	DBC * cursorp = NULL;
	ret = utxo_db->cursor(utxo_db, NULL, &cursorp, 0);
	db_error_exit(env, ret);
	
	memset(&key, 0, sizeof(key));
	memset(&value, 0, sizeof(value));
	
	int index = 0;
	while(0 == ((ret = cursorp->get(cursorp, &key, &value, DB_NEXT))))
	{
		printf("==== record %d ====\n", index++);
		char * hex = NULL;
		printf("key size: %u, ", key.size);
		ssize_t cb = bin2hex(key.data, key.size, &hex);
		assert(cb > 0);
		printf("key_data=[%s]\n", hex);
		free(hex);
		
		hex = NULL;
		printf("value size: %u, ", value.size);
		cb = bin2hex(value.data, value.size, &hex);
		assert(cb > 0);
		printf("value_data=[%s]\n", hex);
		free(hex);
		
		printf("\n");
	}
	
	if(ret != DB_NOTFOUND) db_error_exit(env, ret);
	
	cursorp->close(cursorp);
	return;
}

#endif


