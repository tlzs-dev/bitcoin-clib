#ifndef _UTXOES_DB_H_
#define _UTXOES_DB_H_

#include <stdio.h>
#include <stdint.h>

#include "db_engine.h"
#include "satoshi-types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UTXOES_DB_MAX_SCRIPT_LENGTH	(80)	// only scripts with a length less than 80 bytes are included in the db
typedef struct db_record_utxo db_record_utxo_t;
struct db_record_utxo
{
	int64_t value;
	uint8_t scripts[UTXOES_DB_MAX_SCRIPT_LENGTH];
	uint256_t block_hash;
	uint16_t is_witness;
	uint16_t p2sh_flags;	// p2sh to p2wpkh or p2wsh
}__attribute__((packed));

typedef struct utxoes_db
{
	void * priv;
	void * user_data;
	
	int (* add)(struct utxoes_db * db, db_engine_txn_t * txn, 
		const satoshi_outpoint_t * outpoint,
		const satoshi_txout_t * txout,
		const uint256_t * block_hash
	);
	
	int (* remove)(struct utxoes_db * db, db_engine_txn_t * txn, const satoshi_outpoint_t * outpoint);
	int (* remove_block)(struct utxoes_db * db, db_engine_txn_t * txn, const uint256_t * block_hash); 
	
	ssize_t (* find)(struct utxoes_db * db, db_engine_txn_t * txn, 
		const satoshi_outpoint_t * outpoint,
		db_record_utxo_t ** p_utxo);
		
	ssize_t (* find_in_block)(struct utxoes_db * db, db_engine_txn_t * txn, 
		const uint256_t * block_hash, 
		satoshi_outpoint_t ** p_outpoints,
		db_record_utxo_t ** p_utxoes);
		
	ssize_t (* find_in_tx)(struct utxoes_db * db, db_engine_txn_t * txn, 
		const uint256_t * tx_hash, 
		int32_t ** p_indexes,
		db_record_utxo_t ** p_utxoes);

}utxoes_db_t;
utxoes_db_t * utxoes_db_init(utxoes_db_t * db, db_engine_t * engine, const char * db_name, void * user_data);
void utxoes_db_cleanup(utxoes_db_t * db);

#ifdef __cplusplus
}
#endif
#endif
