#ifndef _TRANSACTIONS_DB_H_
#define _TRANSACTIONS_DB_H_

#include <stdio.h>
#include <stdint.h>
#include "db_engine.h"
#include "satoshi-types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct db_record_tx db_record_tx_t;
struct db_record_tx
{
	uint256_t wtxid;		// add segwit support, secondary key (no-dup)
	uint256_t block_hash;	// secondary key (dup)
	int32_t tx_index;
	uint32_t flags;			// 0x01: coinbase; 0x02: segwit_v0
}__attribute__((packed));

typedef struct transactions_db
{
	void * priv;
	void * user_data;
	
	int (* add)(struct transactions_db * db, db_engine_txn_t * txn, 
		const uint256_t * txid, 	// key
		const uint256_t * wtxid, const uint256_t * block_hash, int32_t tx_index, uint32_t flags	// value
	);
	
	// remove tx by txid or wtxid
	int (* remove)(struct transactions_db * db, db_engine_txn_t * txn, const uint256_t * txid, const uint256_t * wtxid);
	
	// remove txes in block
	int (* remove_block)(struct transactions_db * db, db_engine_txn_t * txn, const uint256_t * block_hash);
	
	// find
	ssize_t (* find)(struct transactions_db * db, db_engine_txn_t * txn, const uint256_t * txid, db_record_tx_t ** p_txes);
	ssize_t (* find_by_wtxid)(struct transactions_db * db, db_engine_txn_t * txn, 
		const uint256_t * wtxid, 
		uint256_t ** p_txids, db_record_tx_t ** p_txes);
	ssize_t (* find_in_block)(struct transactions_db * db, db_engine_txn_t * txn, 
		const uint256_t * block_hash, 
		uint256_t ** p_txids, db_record_tx_t ** p_txes);

}transactions_db_t;
transactions_db_t * transactions_db_init(transactions_db_t * db, db_engine_t * engine, const char * db_name, void * user_data);
void transactions_db_cleanup(transactions_db_t * db);

#ifdef __cplusplus
}
#endif
#endif
