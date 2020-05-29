#ifndef _JSON_RPC_H_
#define _JSON_RPC_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <json-c/json.h>

#include "bitcoin.h"

#ifndef BITCOIN_JSON_RPC_VERSION
#define BITCOIN_JSON_RPC_VERSION "1.0"
#endif

typedef struct bitcoin_cli_context
{
	void * user_data;
	void * priv;
	char url[4096];
	
	char * rpc_version;		// default: "1.0"
	enum bitcoin_network_type network;
	
	int use_ssl;
	int async_mode;
	char * cert_file;
	char * ca_file;
	
	// public methods
	int (* set_url)(struct bitcoin_cli_context * cli, const char * url);
	int (* set_cert_file)(struct bitcoin_cli_context * cli, const char * cert_file);
	int (* set_ca_file)(struct bitcoin_cli_context * cli, const char * ca_file);
	void (* set_userpass)(struct bitcoin_cli_context * cli, const char * username, const char * password);
	
	int (* request)(struct bitcoin_cli_context * ctx, 
		const char * request_id, 	// lookup_id, nullable
		const char * command,		// json-rpc method 
		const  json_object * jparams, // current method's params
		json_object ** p_jresponse		// { "result": {}, "error", "", "id": "" }
		);
	
	// callbacks
	int (* on_response)(struct bitcoin_cli_context * ctx, const json_object * jresponse);
	
	// virtual functions (overidable)
	void (* reset)(struct bitcoin_cli_context * ctx);
}bitcoin_cli_context_t;

bitcoin_cli_context_t * bitcoin_cli_context_new(
		const char * rpc_version,			///< nullable
		enum bitcoin_network_type network, 	///< default: testnet
		int use_ssl, 						///< @todo
		int async_mode, 					///< @todo
		void * user_data					///< user context
	);
void bitcoin_cli_context_free(struct bitcoin_cli_context * ctx);


/* utils */
json_object * satoshi_block_to_json(const satoshi_block_t * block);
satoshi_block_t * satoshi_block_from_json(satoshi_block_t * block, json_object * jblock);

json_object * satoshi_tx_to_json(const satoshi_tx_t * tx);
satoshi_tx_t * satoshi_tx_from_json(satoshi_tx_t * tx, json_object * jtx);


#ifdef __cplusplus
}
#endif
#endif

