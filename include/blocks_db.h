#ifndef _BLOCKS_DB_H_
#define _BLOCKS_DB_H_

#include <stdio.h>
#include <stdint.h>
#include "db_engine.h"
#include "satoshi-types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct db_record_block db_record_block_t;
struct db_record_block
{
	struct satoshi_block_header hdr;
	struct{ // index of the secondary_db by { heights, is_orphan }
		int32_t is_orphan;
		int32_t height;
	}__attribute__((packed));
	// block.dat file info
	int64_t file_index;
	int64_t start_pos;		// the begining of the block_data (just after block_file_hdr{magic, size} )
	
	// used to verify block_file_hdr : assert( start_pos >= 8 && (*(uint32_t *)(start-8) == magic)  && (*(uint32_t *)(start-4) == block_size) );
	uint32_t magic;
	uint32_t block_size;
}__attribute__((packed));

typedef struct blocks_db
{
	void * priv;
	void * user_data;
	
	int (* add)(struct blocks_db * db, db_engine_txn_t * txn, 
		const uint256_t * hash, 
		const db_record_block_t * block);
		
	int (* remove)(struct blocks_db * db, db_engine_txn_t * txn, const uint256_t * hash);
	ssize_t (* find)(struct blocks_db * db, db_engine_txn_t * txn, const uint256_t * hash, db_record_block_t ** p_block);
	ssize_t (* find_at)(struct blocks_db * db, db_engine_txn_t * txn, 
		int height, uint256_t ** p_hashes, db_record_block_t ** p_blocks);
	
	int32_t (* get_latest)(struct blocks_db * db, db_engine_txn_t * txn, 
		uint256_t * hash,				// nullable
		db_record_block_t * block		// nullable
		); ///< @return  block_height
}blocks_db_t;
blocks_db_t * blocks_db_init(blocks_db_t * db, db_engine_t * engine, const char * db_name, void * user_data);
void blocks_db_cleanup(blocks_db_t * db);

#ifdef __cplusplus
}
#endif
#endif
