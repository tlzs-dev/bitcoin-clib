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

typedef struct memcache_block_info
{
	uint256_t hash;
	db_record_block_t data;
	satoshi_block_t * block;
}memcache_block_info_t;
 
memcache_block_info_t * memcache_block_info_new(const uint256_t * hash, 
	const struct satoshi_block_header * hdr, 
	int64_t file_index, int64_t file_offset, 
	satoshi_block_t * block)
{
	memcache_block_info_t * binfo = calloc(1, sizeof(*binfo));
	assert(binfo);
	binfo->hash = *hash;
	binfo->data.hdr = * hdr;
	binfo->data.file_index = file_index;
	binfo->data.start_pos = file_offset;
	binfo->block = block;
	return binfo;
}
void memcache_block_info_set(memcache_block_info_t * dst, const memcache_block_info_t * src) 
{
	if(dst->block) { satoshi_block_cleanup(dst->block); dst->block = NULL; };
	*dst = *src;
	return;
}

void memcache_block_info_free(memcache_block_info_t * binfo)
{
	if(NULL == binfo) return;
	if(binfo->block) {
		satoshi_block_cleanup(binfo->block);
		free(binfo->block);
		binfo->block = NULL;
	}
	free(binfo);
}

static int memcache_block_info_compare(const void * a, const void * b) 
{
	return uint256_compare(a, b);
}

typedef struct memcache
{
	avl_tree_t search_tree[1]; // base object
	ssize_t max_size;
	
	int (* on_compare)(const void *, const void *);
}memcache_t;

#define memcache_add(cache, data)  avl_tree_add((avl_tree_t *)cache, data, cache->on_compare)
#define memcache_del(cache, data)  avl_tree_del((avl_tree_t *)cache, data, cache->on_compare)
#define memcache_find(cache, data) avl_tree_find((avl_tree_t *)cache, data, cache->on_compare)

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
	
	memcache_t cache[1];
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
	//~ .magic = BITCOIN_MESSAGE_MAGIC_TESTNET3,
	.magic = BITCOIN_MESSAGE_MAGIC_MAINNET,
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
static ssize_t load_block(test_context_t * ctx, const char * filename);
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
	
	memcache_init(ctx->cache, 0, 
		memcache_block_info_compare, 
		(void (*)(void *))memcache_block_info_free, 
		ctx);
	
	db_engine_t * db_mgr = db_engine_init(NULL, ctx->db_home, ctx);
	assert(db_mgr);
	ctx->db_mgr = db_mgr;
	
	blocks_db_t * block_db = blocks_db_init(ctx->block_db, db_mgr, NULL, ctx);
	assert(block_db);
	
	utxoes_db_t * utxo_db = utxoes_db_init(ctx->utxo_db, db_mgr, NULL, ctx);
	assert(utxo_db);
	
	blockchain_t * chain = blockchain_init(ctx->chain, NULL, 
		NULL, ctx);
		//s_testnet_hdr, ctx);
	assert(chain);
	
	chain->on_add_block = on_add_block;
	chain->on_remove_block = on_remove_block;
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
	
	memcache_cleanup(ctx->cache);
	global_unlock();
	return;
}

#include <fcntl.h>
#include <dirent.h>
static int blocks_file_filter(const struct dirent * entry) 
{
	if((entry->d_type & DT_REG) != DT_REG) return 0;
	
	// check prefix
	if(strstr(entry->d_name, "blk") != entry->d_name) return 0; 
	
	// check ext_name
	const char * p_ext = strrchr(entry->d_name, '.');
	if(NULL == p_ext || strcasecmp(p_ext, ".dat")) return 0;

	return 1;
}

int test_run(test_context_t * ctx)
{
	const char * blocks_dir = ctx->blocks_data_path;
	assert(blocks_dir);
	
	char path_name[PATH_MAX] = "";
	struct dirent ** blocks_filelist = NULL;
	ssize_t count = scandir(blocks_dir, &blocks_filelist, blocks_file_filter, versionsort);
	printf("block files count: %Zd\n", count);
	
	for(int i = 0; i < count; ++i)
	{
		struct dirent * entry = blocks_filelist[i];
		int cb = snprintf(path_name, sizeof(path_name), "%s/%s", blocks_dir, entry->d_name);
		assert(cb > 0 && cb < sizeof(path_name));
		free(entry);
		
		printf("==== load %s ====\n", path_name);
		load_block(ctx, path_name);
	}
	free(blocks_filelist);
	
	return 0;
}

struct block_file_header
{
	uint32_t magic;
	uint32_t length;
};

static inline int64_t get_block_file_index(const char * block_file)
{
	assert(block_file);
	char path_name[PATH_MAX] = "";
	strncpy(path_name, block_file, sizeof(path_name));
	char * filename = basename(path_name);
	assert(filename && filename[0]);
	
	char * p_ext = strrchr(filename, '.');
	assert(p_ext);
	*p_ext = '\0';
	
	char * prefix = strstr(filename, "blk");
	assert(prefix && prefix == filename);
	
	int64_t index = atol(filename + 3);
	return index;
}

static ssize_t load_block(test_context_t * ctx, const char * filename)
{
#define BUFFER_SIZE (4 * 1024 * 1024)
	unsigned char * buffer = malloc(BUFFER_SIZE);
	assert(buffer);
	
	struct block_file_header file_hdr[1];
	FILE * fp = fopen(filename, "rb");
	assert(fp);
	ssize_t cb = 0;
	int file_index = get_block_file_index(filename);
	assert(file_index >= 0);
	
	memcache_t * cache = ctx->cache;
	
	blockchain_t * chain = ctx->chain;
	blocks_db_t * block_db = ctx->block_db;
	utxoes_db_t * utxo_db = ctx->utxo_db;
	
	assert(chain && block_db && utxo_db);
	
	ssize_t blocks_count = 0;
	int64_t file_offset = 0;
	while((cb = fread(file_hdr, sizeof(file_hdr), 1, fp)) == 1) {
		assert(file_hdr->magic == ctx->magic);
		if(file_hdr->magic != ctx->magic) return -1;
		file_offset += sizeof(file_hdr);
		
		cb = fread(buffer, 1, file_hdr->length, fp);
		assert(cb == file_hdr->length);
		if(cb != file_hdr->length) return -1;
		
		satoshi_block_t * block = calloc(1, sizeof(*block));
		assert(block);
		
		ssize_t length = satoshi_block_parse(block, cb, buffer);
		assert(length == cb);
		
		
		
		file_offset += cb;
		memcache_block_info_t * binfo = memcache_block_info_new(&block->hash, &block->hdr, file_index, file_offset, block);
		assert(binfo);
		memcache_block_info_t ** p_node = memcache_add(cache, binfo);
		assert(p_node);
		
		if(*p_node != binfo) {	// dupliate blocks
			memcache_block_info_set(*p_node, binfo);
			binfo->block = NULL;
			memcache_block_info_free(binfo);
			binfo = *p_node;
		}
		assert(*p_node == binfo);

		enum blockchain_error err_code = chain->add(chain, &block->hash, &block->hdr);
		if(err_code == blockchain_error_no_error) { // new block found
			++blocks_count;
		}
		
		printf("current height: %ld\n", chain->height);
	}
	
	
	
	fclose(fp);
	free(buffer);
#undef BUFFER_SIZE
	return 0;
}


/*******************************************************
 * test load_blocks
 ******************************************************/
#include "bitcoin-consensus.h"

static int load_block_from_file(const char * blocks_data_path, int file_index, int64_t start_pos, satoshi_block_t ** p_block)
{
	assert(blocks_data_path & p_block && file_index >= 0 && start_pos >= 8);
	char path_name[PATH_MAX] = "";
	ssize_t cb = snprintf(path_name, sizeof(path_name), "%s/blk%.5d.dat", ctx->blocks_data_path, (int)record->file_index);
	assert(cb > 0 && cb < PATH_MAX);
		
	struct block_file_header file_hdr[1];
	FILE * fp = fopen(path_name, "rb");
	assert(fp);
	
	fseek(fp, record->start_offset - 8, SEEK_SET);
	cb = fread(file_hdr, sizeof(file_hdr), 1, fp);
	assert(cb == 1);
	assert(file_hdr->length > 0 && file_hdr->length <= MAX_BLOCK_SERIALIZED_SIZE); // bitcoin consensus
	
	unsigned char * block_data = malloc(file_hdr->length);
	assert(block_data);
	cb = fread(block_data, 1, file_hdr->length, fp);
	assert(cb == file_hdr->length);
	
	fclose(fp);
	
	satoshi_block_t * block = *p_block;
	if(NULL == block) {
		block = calloc(1, sizeof(*block));
		assert(block);
	}
	
	cb = satoshi_block_parse(block, file_hdr->length, block_data);
	assert(cb == file_hdr->length);
	
	*p_block = block;
	return 0;
} 
 
 
static int on_remove_block(struct blockchain * chain, const uint256_t * block_hash, const int height, void * user_data)
{
	test_context_t * ctx = user_data;
	assert(ctx);
	memcache_t * cache = ctx->cache;
	assert(cache);
	
	db_engine_txn_t * txn = db_mgr->txn_new(db_mgr, NULL);
	assert(txn);
	
	
	
	
	
	memcache_block_info_t binfo_buf[1];
	memset(binfo_buf, 0, sizeof(binfo_buf));
	
	memcache_block_info_t * binfo = NULL;
	
	// find from memcache first
	memcache_block_info_t ** p_node = memcache_find(cache, block_hash);
	if(p_node) { *binfo = p_node; }
	else {	// not found in the memcache, and search from the blocks_db
		binfo = binfo_buf;
		db_record_block_t * record = &binfo->data;
		blocks_db_t * block_db = ctx->block_db;
		assert(block_db);
		
		record->height = -1;
		ssize_t count = block_db->find(block_db, txn, block_hash, &record);
		
		assert(count == 1);
		if(count != 1) return -1;
	}
	
	if(NULL == binfo->block) {	// need to load block data from file
		db_record_block_t * record = &binfo->data;
		assert(record->height ==  height);
		int rc = load_block_from_file(ctx->blocks_data_path, record->file_index, record->start_pos, &binfo->block);
		assert(0 == rc);
	}
	satoshi_block_t * block = binfo->block;
	assert(block);
	assert(block->txn_count > 0);
	
	// rollback utxo_db
	utxoes_db_t * utxo_db = ctx->utxo_db;
	utxo_db->remove_block(utxo_db, txn, block_hash);
	
	return 0;
}

static int on_add_block(struct blockchain * chain, const uint256_t * block_hash, const int height, void * user_data)
{
	test_context_t * ctx = user_data;
	assert(ctx);
	memcache_t * cache = ctx->cache;
	assert(cache);
	
	db_engine_t * db_mgr = ctx->db_mgr;
	assert(db_mgr);
	
	memcache_block_info_t ** p_node = memcache_find(cache, block_hash);
	assert(p_node);
	
	memcache_block_info_t * binfo = *p_node;
	assert(binfo);
	
	db_engine_txn_t * txn = db_mgr->txn_new(db_mgr, NULL);
	assert(txn);
	
	blocks_db_t * block_db = ctx->block_db;
	utxoes_db_t * utxo_db = ctx->utxo_db;
	assert(block_db && utxo_db);
	
	int rc = 0;
	binfo->data.height = height;
	rc = block_db->add(block_db, txn, &binfo->hash, &binfo->data);
	assert(0 == rc);
	
	satoshi_block_t * block = binfo->block;
	assert(block);
	
	assert(block->txn_count > 0);
	for(ssize_t i = 0; i < block->txn_count; ++i) {
		satoshi_tx_t * tx = &block->txns[i];
		assert(tx->txin_count > 0 && tx->txout_count > 0 && tx->txins && tx->txouts);
		
		satoshi_txin_t * txins = tx->txins;
		satoshi_txout_t * txouts = tx->txouts;
		
		satoshi_outpoint_t outpoint[1];
		memset(outpoint, 0, sizeof(outpoint));
		memcpy(outpoint->prev_hash, tx->txid, 32);
		
		if(i != 0) { // not coinbase tx
			// Todo: verify txin scripts
			// ...
			// destroy spent tx outputs
			for(ssize_t ii = 0; ii < tx->txin_count; ++ii)
			{
				satoshi_txin_t * txin = &txins[ii];
				utxo_db->remove(utxo_db, txn, &txin->outpoint);
			}
		}
		
		for(ssize_t ii = 0; ii < tx->txout_count; ++ii)
		{
			
			satoshi_txout_t * txout = &txouts[ii];
			outpoint->index = (int32_t)ii;
			utxo_db->add(utxo_db, txn, outpoint, txout, &block->hash);
		}
		
	}
	
	txn->commit(txn, 0);
	db_mgr->txn_free(db_mgr, txn);

	memcache_del(cache, block_hash);
	memcache_block_info_free(binfo);
	
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
	assert(0 == rc);
	return rc;
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
	
	cache->on_compare = on_compare;

	avl_tree_t * tree = avl_tree_init(cache->search_tree, cache);
	assert(tree == cache->search_tree);
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

