#ifndef _BITCOIN_BLOCKCHAIN_H_
#define _BITCOIN_BLOCKCHAIN_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <limits.h>
#include <json-c/json.h>

#include "bitcoin-network.h"
#include "avl_tree.h"
#include "blocks_db.h"
#include "utxoes_db.h"
#include "transactions_db.h"
#include "chains.h"

typedef struct bitcoin_blockchain
{
	blockchain_t main_chain[1];	// base object
	
	void * priv;
	void * user_data;
	
	// persistent storage
	db_engine_t * engine;
	blocks_db_t block_db[1];
	utxoes_db_t utxo_db[1];
	transactions_db_t tx_db[1];
	
	// mempool
	avl_tree_t mem_db[1];
	
	// network
	bitcoin_node_t * bnode;
	
	// rpc server
	void * json_rpc_server;
	
	// callbacks
	int (* on_add_block)(blockchain_t * bchain, const uint256_t * block_hash, int height, void * user_data);
	int (* on_remove_block)(blockchain_t * bchain, const uint256_t * block_hash, int height, void * user_data);

	// public functions
	int (* load_config)(struct bitcoin_blockchain * bitcoin, json_object * jconfig);
	int (* run)(struct bitcoin_blockchain * bitcoin, int async_mode);
	int (* stop)(struct bitcoin_blockchain * bitcoin);

}bitcoin_blockchain_t;
bitcoin_blockchain_t * bitcoin_blockchain_init(bitcoin_blockchain_t * bitcoin, void * user_data);
void bitcoin_blockchain_cleanup(bitcoin_blockchain_t * bitcoin);

#ifdef __cplusplus
}
#endif
#endif
