#ifndef _DB_ENGINE_H_
#define _DB_ENGINE_H_

#include <stdio.h>
#include <pthread.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DB_ENGINE_GID_SIZE
#define DB_ENGINE_GID_SIZE	(128)		// db.h: DB_GID_SIZE
#endif
struct db_handle;
struct db_engine;
typedef struct db_engine_txn
{
	void * priv;
	struct db_engine * engine;
	
// public methods:
	int (* begin)(struct db_engine_txn * txn, struct db_engine_txn * parent_txn);
	int (* commit)(struct db_engine_txn * txn, int flags);
	int (* abort)(struct db_engine_txn * txn);
	
	int (* prepare)(struct db_engine_txn * txn, unsigned char gid[/* DB_ENGINE_GID_SIZE */]);
	int (* discard)(struct db_engine_txn * txn);
	
	int (* set_name)(struct db_engine_txn * txn, const char * name);
	const char * (* get_name)(struct db_engine_txn * txn);
}db_engine_txn_t;
db_engine_txn_t * db_engine_txn_init(db_engine_txn_t * txn, struct db_engine * env);
void db_engine_txn_cleanup(db_engine_txn_t * txn);

typedef int (* db_associate_callback)(struct db_handle * sdb, 
		const void * key, size_t cb_key, const void * value, size_t cb_value, // records in the primary db
		void ** p_skey, ssize_t * cb_skey	// return key(s) in the secondary db
	);
typedef struct db_handle
{
	void * priv;
	struct db_engine * engine;
	
	void * user_data;
	unsigned int err_code;
	
	int (* open)(struct db_handle * db, db_engine_txn_t * txn, const char * name, 
		int db_type, // 0: DB_BTREE, 1: DB_HASH
		int flags);
	int (* associate)(struct db_handle * primary, db_engine_txn_t * txn, struct db_handle * secondary, 
		db_associate_callback associated_by);
	int (* close)(struct db_handle * db);
	
	int (* find)(struct db_handle * db, 
		const void * key, size_t cb_key,		// the key of the primary database
		void ** p_value, size_t * cb_value);
	
	int (* find_secondary)(struct db_handle * db, 
		const void * skey, size_t cb_skey,		// the key of secondary database
		void * p_key, ssize_t * cb_key,			// if need return the key of the primary database
		void ** p_value, ssize_t * cb_value);
		
	
	int (* insert)(struct db_handle * db, 
		const void * key, size_t cb_key, 
		const void * value, size_t cb_value);

	int (* update)(struct db_handle * db, 
		const void * key, size_t cb_key, 
		const void * value, size_t cb_value);
	
	int (* del)(struct db_handle * db, const void * key, size_t cb_key);

}db_handle_t;
db_handle_t * db_handle_init(db_handle_t * db, struct db_engine * engine, void * user_data);
void db_handle_cleanup(db_handle_t * db);

typedef struct db_engine
{
	void * priv;
	void * user_data;
	
	long refs_count;
	unsigned int err_code;
	
	int (* set_home)(struct db_engine * engine, const char * home_dir);
	
	db_handle_t * (* open_db)(struct db_engine * engine, const char * db_name, int db_type, int flags);
	int (* close_db)(db_handle_t * db);
	
	db_engine_txn_t * (* txn_new)(struct db_engine * engine, struct db_engine_txn * parent_txn);
	void (* txn_free)(struct db_engine * engine, db_engine_txn_t * txn);
}db_engine_t;
db_engine_t * db_engine_init(const char * home_dir, void * user_data);
void db_engine_cleanup(db_engine_t * engine);
db_engine_t * db_engine_get();


#ifdef __cplusplus
}
#endif

#endif
