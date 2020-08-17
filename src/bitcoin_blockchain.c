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

#include <stdint.h>
#include <pthread.h>
#include <unistd.h>

#include <limits.h>
#include <json-c/json.h>

#include "bitcoin-network.h"
#include "avl_tree.h"
#include "blocks_db.h"
#include "utxoes_db.h"
#include "transactions_db.h"
#include "chains.h"

#include "bitcoin_blockchain.h"
#include "utils.h"

#include <libgen.h>

typedef struct bitcoin_blockchain_private
{
	bitcoin_blockchain_t * bitcoin;
	json_object * jconfig;
	
	const char * node_port;	// listening port
	const char * rpc_port;
	
	const char * blocks_data_path;
	const char * db_home;
	
	char root_path[PATH_MAX];
	
	uint256_t * genesis_block_hash;
	struct satoshi_block_header * genesis_block_hdr;
	
	uint32_t magic;		// network magic
	
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_t th;

	// thread pool
	void * workers;	// worker threads pool
	
	int async_mode;
	int quit;
}bitcoin_blockchain_private_t;

static pthread_mutexattr_t s_mutexattr_recursive;
static pthread_mutexattr_t s_mutexattr_normal;
static pthread_mutexattr_t s_mutexattr_errcheck;

static pthread_once_t s_once_key = PTHREAD_ONCE_INIT;
static pthread_key_t s_tls_key;	// thread local storage

static void tls_key_on_destroy(void * context)
{
	return;
}

static void init_mutexattrs(void) 
{
	int rc = -1;
	rc = pthread_key_create(&s_tls_key, tls_key_on_destroy);
	
	rc = pthread_mutexattr_init(&s_mutexattr_recursive);
	assert(0 == rc);
	rc = pthread_mutexattr_settype(&s_mutexattr_recursive, PTHREAD_MUTEX_RECURSIVE);
	assert(0 == rc);
	
	rc = pthread_mutexattr_init(&s_mutexattr_normal);
	assert(0 == rc);
	rc = pthread_mutexattr_settype(&s_mutexattr_normal, PTHREAD_MUTEX_NORMAL);
	assert(0 == rc);
	
	rc = pthread_mutexattr_init(&s_mutexattr_errcheck);
	assert(0 == rc);
	rc = pthread_mutexattr_settype(&s_mutexattr_errcheck, PTHREAD_MUTEX_ERRORCHECK);
	assert(0 == rc);
	
	return;
}

static bitcoin_blockchain_private_t * bitcoin_blockchain_private_new(bitcoin_blockchain_t * bitcoin)
{
	assert(bitcoin);
	
	bitcoin_blockchain_private_t *priv = calloc(1, sizeof(*priv));
	assert(priv);
	
	bitcoin->priv = priv;
	priv->bitcoin = bitcoin;
	
	priv->node_port = "28333";
	priv->db_home = "data";
	priv->blocks_data_path = "blocks";
	
	int rc = pthread_mutex_init(&priv->mutex, 
	//	&s_mutexattr_recursive
		&s_mutexattr_errcheck
	);
	assert(0 == rc);
	
	rc = pthread_cond_init(&priv->cond, NULL);
	assert(0 == rc);
	
	
	ssize_t cb = readlink("/proc/self/exe", priv->root_path, sizeof(priv->root_path));
	assert(cb > 0);
	
	dirname(priv->root_path);
	return priv;
}

static int bitcoin_stop(struct bitcoin_blockchain * bitcoin);
static void bitcoin_blockchain_private_free(bitcoin_blockchain_private_t * priv)
{
	if(NULL == priv) return;
	
	if(!priv->quit) bitcoin_stop(priv->bitcoin);

	pthread_mutex_destroy(&priv->mutex);
	pthread_cond_destroy(&priv->cond);
	
	if(priv->jconfig) {
		json_object_put(priv->jconfig);
		priv->jconfig = NULL;
	}
	
	return;
}

static int bitcoin_load_config(struct bitcoin_blockchain * bitcoin, json_object * jconfig)
{
	assert(bitcoin && bitcoin->priv);
	bitcoin_blockchain_private_t * priv = bitcoin->priv;
	
	priv->jconfig = json_object_get(jconfig);
	priv->node_port = json_get_value_default(jconfig, string, port, "28333");
	assert(priv->node_port);
	
	const char * db_home = json_get_value(jconfig, string, db_home);
	if(db_home) priv->db_home = db_home;
	
	const char * blocks_data_path = json_get_value(jconfig, string, blocks);
	if(blocks_data_path) priv->blocks_data_path = blocks_data_path;
	
	
	return 0;
}


static void * process(void * user_data)
{
	int rc = 0;
	bitcoin_blockchain_t * bitcoin = user_data;
	assert(bitcoin && bitcoin->priv);
	
	bitcoin_blockchain_private_t * priv = bitcoin->priv;
	
	// TODO : load blocks from data_files (if available)
	// step 0: lastest_block = blocks_db->get_latest();
	// step 1: load data file if available
	
	
	// TODO : start json-rpc server
	if(priv->rpc_port) {
		// todo 
		// rpc_server_run();
	}

	// start node
	bitcoin_node_t * bnode = bitcoin->bnode;
	assert(bnode);
	rc = bitcoin_node_run(bnode, NULL, priv->node_port, priv->async_mode); 
	
	if(priv->async_mode) {
		pthread_mutex_lock(&priv->mutex);
		
		while(!priv->quit)
		{
			rc = pthread_cond_wait(&priv->cond, &priv->mutex);
			if(rc) break;
		}
		priv->quit = 1;
		bitcoin_node_terminate();
		pthread_mutex_unlock(&priv->mutex);
		
		bitcoin_node_free(bnode);
		bitcoin->bnode = NULL;
	}
	
	if(priv->async_mode) pthread_exit((void *)(long)rc);
	return (void *)(long)rc;
}

static inline ssize_t get_fullname(const char * root_path, const char * path, char fullname[], size_t size)
{
	assert(root_path && path);
	ssize_t cb = 0;
	if(path[0] == '/') cb = snprintf(fullname, size, "%s", path);
	else cb = snprintf(fullname, size, "%s/%s", root_path, path);
	assert(cb > 0 && cb < (ssize_t)size);
	
	return cb;
}

static int bitcoin_run(struct bitcoin_blockchain * bitcoin, int async_mode)
{
	int rc = 0;
	assert(bitcoin && bitcoin->priv);
	bitcoin_blockchain_private_t * priv = bitcoin->priv;
	
	// init node
	assert(priv->node_port);
	bitcoin->bnode = bitcoin_node_new(0, bitcoin);
	assert(bitcoin->bnode);
	
	char path_name[PATH_MAX] = "";
	ssize_t cb = get_fullname(priv->root_path, priv->db_home, path_name, sizeof(path_name));
	assert(cb > 0 && cb < sizeof(path_name));
	
	// init dbs
	db_engine_t * engine =  db_engine_init(NULL, path_name, bitcoin);
	assert(engine);
	bitcoin->engine = engine;
	
	blocks_db_t * blocks = blocks_db_init(bitcoin->block_db, engine, NULL, bitcoin);
	utxoes_db_t * utxoes = utxoes_db_init(bitcoin->utxo_db, engine, NULL, bitcoin);
	transactions_db_t * txes = transactions_db_init(bitcoin->tx_db, engine, NULL, bitcoin);
	assert(blocks && blocks == bitcoin->block_db);
	assert(utxoes && utxoes == bitcoin->utxo_db);
	assert(txes && txes == bitcoin->tx_db);
	
	// init mem db
	avl_tree_t * mem_db = avl_tree_init(bitcoin->mem_db, bitcoin);
	assert(mem_db && mem_db == bitcoin->mem_db);
	
	// init chain
	blockchain_t * main_chain = blockchain_init(bitcoin->main_chain, priv->genesis_block_hash, priv->genesis_block_hdr, bitcoin);
	assert(main_chain && main_chain == bitcoin->main_chain);
	main_chain->on_add_block = bitcoin->on_add_block;
	main_chain->on_remove_block = bitcoin->on_remove_block;
	
	// run
	priv->async_mode = async_mode;
	if(async_mode) rc = pthread_create(&priv->th, NULL, process, bitcoin);
	else process(bitcoin);
	
	return rc;
}

static int bitcoin_stop(struct bitcoin_blockchain * bitcoin)
{
	assert(bitcoin && bitcoin->priv);
	bitcoin_blockchain_private_t * priv = bitcoin->priv;
	
	if(!priv->quit)
	{
		priv->quit = 1;
		if(priv->async_mode && priv->th) {
			
			pthread_mutex_lock(&priv->mutex);
			pthread_cond_signal(&priv->cond);
			pthread_mutex_unlock(&priv->mutex);
			
			void * exit_code = NULL;
			int rc = pthread_join(priv->th, &exit_code);
			fprintf(stderr, "%s(): pthread exit with code %ld, rc = %d\n", 
				__FUNCTION__,
				(long)exit_code,
				rc);
				
			priv->async_mode = 0;
			priv->th = (pthread_t)0;
		
		}else {
			bitcoin_node_terminate();
			bitcoin_node_free(bitcoin->bnode);
			bitcoin->bnode = NULL;
		}
		
	}
	return 0;
}

static int bitcoin_on_add_block(blockchain_t * bchain, const uint256_t * block_hash, int height, void * user_data);
static int bitcoin_on_remove_block(blockchain_t * bchain, const uint256_t * block_hash, int height, void * user_data);
bitcoin_blockchain_t * bitcoin_blockchain_init(bitcoin_blockchain_t * bitcoin, void * user_data)
{
	int rc = -1;
	
	rc = pthread_once(&s_once_key, init_mutexattrs);
	assert(0 == rc);
	
	if(NULL == bitcoin) bitcoin = calloc(1, sizeof(*bitcoin));
	assert(bitcoin);
	
	bitcoin->user_data = user_data;
	bitcoin->load_config = bitcoin_load_config;
	bitcoin->run = bitcoin_run;
	bitcoin->stop = bitcoin_stop;
	
	bitcoin->on_add_block = bitcoin_on_add_block;
	bitcoin->on_remove_block = bitcoin_on_remove_block;
	
	bitcoin_blockchain_private_t * priv = bitcoin_blockchain_private_new(bitcoin);
	assert(priv && bitcoin->priv == priv);
	
	return bitcoin;
}

void bitcoin_blockchain_cleanup(bitcoin_blockchain_t * bitcoin)
{
	debug_printf("%s(%p)...\n", __FUNCTION__, bitcoin);
	if(NULL == bitcoin) return;
	bitcoin_blockchain_private_free(bitcoin->priv);
	bitcoin->priv = NULL;
	
	blocks_db_cleanup(bitcoin->block_db);
	utxoes_db_cleanup(bitcoin->utxo_db);
	transactions_db_cleanup(bitcoin->tx_db);
	
	avl_tree_cleanup(bitcoin->mem_db);
	return;
}


/**********************************************************
 * on add/remove block
**********************************************************/
static int bitcoin_on_add_block(blockchain_t * bchain, const uint256_t * block_hash, int height, void * user_data)
{
	debug_printf("%s(height=%d)...\n", __FUNCTION__, height);
	bitcoin_blockchain_t * bitcoin = user_data;
	assert(bitcoin && bitcoin->priv);
	
	bitcoin_blockchain_private_t * priv = bitcoin->priv;
	pthread_mutex_lock(&priv->mutex);
	
	// todo
	// ...
	
	pthread_mutex_unlock(&priv->mutex);
	return 0;
}
static int bitcoin_on_remove_block(blockchain_t * bchain, const uint256_t * block_hash, int height, void * user_data)
{
	debug_printf("%s(height=%d)...\n", __FUNCTION__, height);
	bitcoin_blockchain_t * bitcoin = user_data;
	assert(bitcoin && bitcoin->priv);
	
	bitcoin_blockchain_private_t * priv = bitcoin->priv;
	pthread_mutex_lock(&priv->mutex);
	
	// todo
	// ...
	
	pthread_mutex_unlock(&priv->mutex);
	return 0;
}



#if defined(_TEST_BITCOIN_BLOCKCHAIN) && defined(_STAND_ALONE)

#include <getopt.h>
#include <signal.h>

void on_signal(int sig) 
{
	switch(sig) {
	case SIGINT: case SIGUSR1:
		bitcoin_node_terminate();
		return;
	default:
		break;
	}
	abort();
	return;
}

int main(int argc, char **argv)
{
	struct option options[] = {
		{ "daemon", no_argument, 0, 'd' },
		{ "help", no_argument, 0, 'h' },
		{NULL},
	};
	
	int daemon_mode = 0;
	while(1) {
		int opt_index = 0;
		int c = getopt_long(argc, argv, "dh", options, &opt_index);
		if(c == -1) break;
		
		switch(c) {
		case 'd': daemon_mode = 1; break;
		case 'h': exit(0); break;
		default:
			break;
		}
	}
	
	char root_path[PATH_MAX] = "";
	readlink("/proc/self/exe", root_path, sizeof(root_path) - 1);
	dirname(root_path);

	printf("daemon mode: %d\n", daemon_mode);
	if(daemon_mode) daemon(0, 1);
	
	chdir(root_path);
	printf("process id: %ld\n", (long)getpid());
	
	signal(SIGINT, on_signal);
	bitcoin_blockchain_t bitcoin[1];
	memset(bitcoin, 0, sizeof(bitcoin));
	
	bitcoin_blockchain_init(bitcoin, NULL);
	
	json_object * jconfig = json_object_from_file("conf/bitcoin.json");
	assert(jconfig);
	
	int rc = bitcoin->load_config(bitcoin, jconfig);
	assert(0 == rc);
	
	close(0); close(1); close(2); // close stdio

	bitcoin->run(bitcoin, 0);
	
	bitcoin_blockchain_cleanup(bitcoin);
	return 0;
}
#endif

