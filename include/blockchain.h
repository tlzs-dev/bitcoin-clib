#ifndef _BITCOIN_BLOCKCHAIN_H_
#define _BITCOIN_BLOCKCHAIN_H_

#include <stdio.h>
#include <stdint.h>
#include "satoshi-types.h"

#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************
 * UTXOs
 ******************************************************/
typedef struct db_record_utxo db_record_utxo_t;
struct db_record_utxo_data
{
	uint256_t block_hash;			// secondary key
	// satoshi_txout_t txout;
	int64_t value;	// little-endian
	uint32_t cb_script;
	unsigned char pk_scripts[0];	// variable length data
}__attribute__((packed));
struct db_record_utxo
{
	// key
	satoshi_outpoint_t outpoint;	// primary key, <tx_hash>:<txout_index>
	
	// data
	union
	{
		struct db_record_utxo_data data;
		struct
		{
			uint256_t block_hash;			// secondary key
			// satoshi_txout_t txout;
			int64_t value;	// little-endian
			uint32_t cb_script;
			unsigned char pk_scripts[0];	// variable length data
		}__attribute__((packed));
	};
}__attribute__((packed));
struct db_record_utxo * db_record_utxo_new(
	const uint256_t * block_hash, 
	const satoshi_outpoint_t *outpoint, 
	const satoshi_txout_t * txout);
void db_record_utxo_free(struct db_record_utxo * utxo);
#define db_record_utxo_size(utxo)  (sizeof(struct db_record_utxo) + (utxo?utxo->cb_script:0))

typedef struct bitcoin_utxo_db
{
	void * user_data;
	void * priv;

	int (* add)(struct bitcoin_utxo_db * db, const uint256_t * block_hash, const satoshi_outpoint_t *outpoint, const satoshi_txout_t * txout);
	int (* remove)(struct bitcoin_utxo_db * db, const struct satoshi_outpoint * outpoint);
	int (* find)(struct bitcoin_utxo_db * db, 
		const satoshi_outpoint_t * outpoint, // (NOT NULL)
		satoshi_txout_t * txout, // (nullable)
		uint256_t * block_hash	// (nullable)
	);
	
	// DB Transaction Subsystem Wrapper
	void (* set_txn)(struct bitcoin_utxo_db * db, 
		void * txn /* a DB_TXN object, should be created by db_env->txn_begin() */
	);

	ssize_t (* get_utxoes)(struct bitcoin_utxo_db * db, const uint256_t * block_hash, db_record_utxo_t ** p_utxoes);	// find utxoes in orphan blocks
	
	ssize_t (* get_count)(const struct bitcoin_utxo_db * db, const uint256_t * block_hash);	// if (NULL == block_hash) return all_utxoes_count;
}bitcoin_utxo_db_t;
bitcoin_utxo_db_t * bitcoin_utxo_db_init(bitcoin_utxo_db_t * db, void * user_data);
void bitcoin_utxo_db_cleanup(bitcoin_utxo_db_t * db);



/*******************************************************
 * BLOCKs
 ******************************************************/


struct db_record_block_data
{
	int32_t height;
	struct satoshi_block_header hdr;
	int32_t file_index;
	int64_t start_pos;

	uint32_t magic;
	uint32_t block_size;
}__attribute__((packed));

struct db_record_block
{
	uint256_t hash;		// primary key
	union
	{
		struct db_record_block_data data;
		struct
		{
			int32_t height;		// secondary key
			struct satoshi_block_header hdr;
			int32_t file_index;
			int64_t start_pos;		// without block_file_hdr({magic, size})
			
			// to verify block_file_hdr : assert( start_pos >= 8 && (*(uint32_t *)(start-8) == magic)  && (*(uint32_t *)(start-4) == block_size) );
			uint32_t magic;
			uint32_t block_size;
		}__attribute__((packed));;
	};
}__attribute__((packed));
typedef struct db_record_block db_record_block_t;

typedef struct bitcoin_blocks_db
{
	void * user_data;
	void * priv;
	
	int (* add)(struct bitcoin_blocks_db * db, 
		const uint256_t * block_hash,
		int height,
		const struct satoshi_block_header * hdr,
		int file_index, 
		int64_t start_pos, 
		uint32_t magic, uint32_t block_size
	);
	int (* remove)(struct bitcoin_blocks_db * db, 
		const uint256_t * block_hash);
	int (* find)(struct bitcoin_blocks_db * db, 
		const uint256_t * block_hash, 
		db_record_block_t ** p_record);
	
	void (* set_txn)(struct bitcoin_blocks_db * db, void * txn);
}bitcoin_blocks_db_t;
bitcoin_blocks_db_t * bitcoin_blocks_db_init(bitcoin_blocks_db_t * db, void * user_data);
void bitcoin_blocks_db_cleanup(bitcoin_blocks_db_t * db);


typedef void bitcoin_consensus_t;	///< @todo
typedef struct bitcoin_blockchain
{
	void * user_data;
	void * priv;
	char working_path[PATH_MAX];
	
	uint32_t magic;		// network magic
	
	int (* add)(struct bitcoin_blockchain blockchain, const satoshi_block_t * block);
	int (* remove)(struct bitcoin_blockchain blockchain, const uint256_t * hash);

	void * env;	// DB_ENV 
	bitcoin_utxo_db_t utxo_db[1]; 
	bitcoin_blocks_db_t blocks_db[1];
	
	// TODO:
	bitcoin_consensus_t * consensus;
	void * mempoo;
	size_t mempool_size;
}bitcoin_blockchain_t;

bitcoin_blockchain_t * bitcoin_blockchain_init(bitcoin_blockchain_t * chain, 
	uint32_t magic,
	const char * db_home,		// database home_dir
	const char * blocks_dir,	// to store block_nnnnn.dat files 
	ssize_t mempool_size,		
	void * user_data);
void bitcoin_blockchain_free(bitcoin_blockchain_t * blockchain);



#ifdef __cplusplus
}
#endif
#endif
