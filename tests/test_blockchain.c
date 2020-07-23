/*
 * test_blockchain.c
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

#include <search.h>
#include <pthread.h>

#include "chains.h"
#include "satoshi-types.h"
#include "satoshi-script.h"
#include "utxoes_db.h"
#include "blocks_db.h"

#include "utils.h"
#include "avl_tree.h"

typedef struct blocks_record
{
	uint256_t hash;
	db_record_block_t block;
}blocks_record_t;

typedef struct memcache
{
	avl_tree_t search_tree[1]; // base object
	ssize_t max_size;
}memcache_t;

#define memcache_add(cache, data) ((avl_tree_t *)cache)->add((avl_tree_t *)cache, data)
#define memcache_del(cache, data) ((avl_tree_t *)cache)->del((avl_tree_t *)cache, data)
#define memcache_find(cache, data) ((avl_tree_t *)cache)->find((avl_tree_t *)cache, data)

memcache_t * memcache_init(memcache_t * cache, ssize_t max_size, 
	int (* on_compare)(const void *, const void *),
	void (* on_free)(void *),
	void * user_data);
void memcache_cleanup(memcache_t * cache);
int memcache_resize(memcache_t * cache, ssize_t new_size);

typedef struct test_context
{
	uint32_t magic;
	char * blocks_data_path;
	char * db_home;
	
	db_engine_t * db_mgr;
	blockchain_t chain[1];
	utxoes_db_t utxo_db[1];
	blocks_db_t block_db[1];
	
	ssize_t memcache_max_size;
	ssize_t count;
	blocks_record_t * blocks;
	
	
}test_context_t;

test_context_t * test_context_init(test_context_t * ctx, int argc, char ** argv, void * user_data);
void test_context_cleanup(test_context_t * ctx);
int test_run(test_context_t * ctx);

int main(int argc, char **argv)
{
	test_context_t * ctx = test_context_init(NULL, argc, argv, NULL);
	assert(ctx);
	test_run(ctx);
	test_context_cleanup(ctx);
	return 0;
}

/*******************************************************
 * test_context
 ******************************************************/

static test_context_t g_context[1] = {{
	.magic = BITCOIN_MESSAGE_MAGIC_TESTNET3,
	.blocks_data_path = "blocks",
	.db_home = "data",
}};

static const char * s_testnet_block_hex = "01000000"
	"0000000000000000000000000000000000000000000000000000000000000000"
	"3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
	"dae5494d"
	"ffff001d"
	"1aa4ae18"
	"01"
		"01000000"
		"01"
			"0000000000000000000000000000000000000000000000000000000000000000ffffffff"
			"4d" 
				"04" "ffff001d"
				"0104"
				"455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73"
			"ffffffff"
		"01"
			"00f2052a01000000" "434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
	"00000000";


static struct satoshi_block_header s_testnet_hdr[1];
static pthread_once_t s_once_key = PTHREAD_ONCE_INIT;
static void global_init(void)
{
	void * p_hdr = s_testnet_hdr;
	ssize_t cb = hex2bin(s_testnet_block_hex, 160, &p_hdr);
	assert(cb == 80);
	
	dump_line("genesis block hdr: ", p_hdr, 80);
	return;
}

static int check_path(const char * path);
static ssize_t load_blocks(test_context_t * ctx);
static int on_remove_block(struct blockchain * chain, const uint256_t * block_hash, const int height, void * user_data);
static int on_add_block(struct blockchain * chain, const uint256_t * block_hash, const int height, void * user_data);

test_context_t * test_context_init(test_context_t * ctx, int argc, char ** argv, void * user_data)
{
	int rc;
	rc = pthread_once(&s_once_key, global_init);
	assert(0 == rc);
	
	if(NULL == ctx) ctx = g_context;
	assert(ctx->db_home && ctx->blocks_data_path);
	check_path(ctx->db_home);
	check_path(ctx->blocks_data_path);
	
	global_lock();
	db_engine_t * db_mgr = db_engine_init(ctx->db_home, ctx);
	assert(db_mgr);
	ctx->db_mgr = db_mgr;
	
	blocks_db_t * block_db = blocks_db_init(ctx->block_db, db_mgr, NULL, ctx);
	assert(block_db);
	
	utxoes_db_t * utxo_db = utxoes_db_init(ctx->utxo_db, db_mgr, NULL, ctx);
	assert(utxo_db);
	
	blockchain_t * chain = blockchain_init(ctx->chain, NULL, s_testnet_hdr, ctx);
	assert(chain);
	
	chain->on_add_block = on_add_block;
	chain->on_remove_block = on_remove_block;
	
	
	load_blocks(ctx);
	global_unlock();
	
	return ctx;
}
void test_context_cleanup(test_context_t * ctx)
{
	global_lock();
	blockchain_cleanup(ctx->chain);
	utxoes_db_cleanup(ctx->utxo_db);
	blocks_db_cleanup(ctx->block_db);
	if(ctx->db_mgr) {
		db_engine_cleanup(ctx->db_mgr);
		ctx->db_mgr = NULL;
	}
	global_unlock();
	return;
}


int test_run(test_context_t * ctx)
{
	return 0;
}



/*******************************************************
 * test load_blocks
 ******************************************************/
 
static int on_remove_block(struct blockchain * chain, const uint256_t * block_hash, const int height, void * user_data)
{
	return 0;
}

static int on_add_block(struct blockchain * chain, const uint256_t * block_hash, const int height, void * user_data)
{
	return 0;
}


static ssize_t load_blocks(test_context_t * ctx)
{
	return 0;
}




/*******************************************************
 * utils
 ******************************************************/
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h> 
#include <limits.h>
static int check_path(const char * path)
{
	assert(path && path[0]);
	int rc = 0;
	struct stat st[1];
	memset(st, 0, sizeof(st));
	rc = stat(path, st);
	if(0 == rc) {
		switch((st->st_mode & S_IFMT)) 
		{
		case S_IFDIR: return 0;
		default: return -1;
		}
	}
	
	char command[PATH_MAX + 100] = "";
	int cb = snprintf(command, sizeof(command), "mkdir -p \"%s\"", path);
	assert(cb > 0 && cb < (int)sizeof(command));
	
	rc = system(command);
	
	return 0;
}




/*******************************************************
 * mem cache
 ******************************************************/
memcache_t * memcache_init(memcache_t * cache, ssize_t max_size, 
	int (* on_compare)(const void *, const void *),
	void (* on_free)(void *),
	void * user_data)
{
	if(NULL == cache) cache = calloc(1, sizeof(*cache));
	assert(cache);

	avl_tree_t * tree = avl_tree_init(cache->search_tree, cache);
	assert(tree == cache->search_tree);
	tree->on_compare = on_compare;
	tree->on_free_data = on_free;
	
	return cache;
}

void memcache_reset(memcache_t * cache)
{
	if(NULL == cache) return;
	avl_tree_cleanup(cache->search_tree);
}

void memcache_cleanup(memcache_t * cache)
{
	if(cache) {
		avl_tree_cleanup(cache->search_tree);
	}
	
	
	return;
}

