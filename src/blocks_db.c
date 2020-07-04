/*
 * blocks_db.c
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



#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include <db.h>
#include <endian.h>


#include "blocks_db.h"
#include "satoshi-types.h"
#include "utils.h"

typedef struct blocks_db_private
{
	blocks_db_t * db;
	db_engine_t * engine;
	
	db_handle_t * blocks;
	db_handle_t * heights_db;		// sorted by 'height'
	db_handle_t * orphan_blocks;	// sorted by 'is_orphan'

	char db_name[PATH_MAX];
	char heights_db_name[PATH_MAX];
	char orphans_db_name[PATH_MAX];
}blocks_db_private_t;



static ssize_t associate_blocks_height(db_handle_t * db, 
	const db_record_data_t * key, 
	const db_record_data_t * value, 
	db_record_data_t ** p_result)
{
	static const int num_results = 1;	
	if(NULL == p_result) return num_results;	// returns the required array size for custom memory allocator
	
	db_record_data_t * results = * p_result;
	if(NULL == results) {
		results = calloc(num_results, sizeof(*results));
		*p_result = results;
	}
	
	struct db_record_block * block = (struct db_record_block *)value->data;
	assert(sizeof(*block) == value->size);
	
	results[0].data = &block->height;
	results[0].size = sizeof(block->height);
	
	return num_results;
}

static ssize_t associate_blocks_is_orphan(db_handle_t * db, 
	const db_record_data_t * key, 
	const db_record_data_t * value, 
	db_record_data_t ** p_result)
{
	static const int num_results = 1; 
	if(NULL == p_result) return num_results;	// returns the required array size for custom memory allocator
	
	db_record_data_t * results = * p_result;
	if(NULL == results) {
		results = calloc(num_results, sizeof(*results));
		*p_result = results;
	}
	
	struct db_record_block * block = (struct db_record_block *)value->data;
	assert(sizeof(*block) == value->size);
	
	results[0].data = &block->is_orphan;
	results[0].size = sizeof(block->is_orphan);
	
	return num_results;
}


#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static int compare_little_endian_int32(DB * db, const DBT * dbt1, const DBT * dbt2)
{
	int32_t a = *(int32_t *)dbt1->data;
	int32_t b = *(int32_t *)dbt2->data;
	return a - b;
}

//~ static int compare_height_and_orphan(DB * db, const DBT * dbt1, const DBT * dbt2)
//~ {
	//~ const struct {
		//~ int32_t height;
		//~ int32_t is_orphan;
	//~ } *a = dbt1->data, *b = dbt2->data;
	
	//~ if(a->height == b->height) {
		//~ if(dbt1->size == sizeof(uint64_t) && dbt2->size == sizeof(uint64_t)) 
			//~ return a->is_orphan - b->is_orphan;
		//~ return 0;
	//~ }
	//~ return a->height - b->height;
//~ }
#endif

blocks_db_private_t * blocks_db_private_new(blocks_db_t * db, db_engine_t * engine, const char * db_name)
{
#define HEIGHTS_DB_SUFFIX "_heights.db"
#define ORPHANS_DB_SUFFIX "_orphans.db"
	assert(db && engine);
	int rc = -1;
	if(NULL == db_name) db_name = "blocks.db";

	blocks_db_private_t * priv = calloc(1, sizeof(*priv));
	assert(priv);
	
	priv->engine = engine;
	priv->db = db;
	db->priv = priv;
	
	strncpy(priv->db_name, db_name, sizeof(priv->db_name));
	strncpy(priv->heights_db_name, db_name, sizeof(priv->heights_db_name) - sizeof(HEIGHTS_DB_SUFFIX));
	strncpy(priv->orphans_db_name, db_name, sizeof(priv->orphans_db_name) - sizeof(ORPHANS_DB_SUFFIX));
	
	char * p_ext = strstr(priv->heights_db_name, ".db");
	if(NULL == p_ext) p_ext = priv->heights_db_name + strlen(priv->heights_db_name);
	strcpy(p_ext, HEIGHTS_DB_SUFFIX);
	
	p_ext = strstr(priv->orphans_db_name, ".db");
	if(NULL == p_ext) p_ext = priv->orphans_db_name + strlen(priv->orphans_db_name);
	strcpy(p_ext, ORPHANS_DB_SUFFIX);
	
	
	/**
	 * open blocks_heights.db and blocks_orphans.db
	 * we need to set compare function before the db->open, 
	 * so we cannot use engine->open_db() directly
	 */
	db_handle_t * heights_db = db_handle_init(priv->heights_db, engine, db);
	db_handle_t * orphan_blocks = db_handle_init(priv->orphan_blocks, engine, db);
	assert(heights_db && orphan_blocks);
	priv->heights_db = heights_db;
	priv->orphan_blocks = orphan_blocks;
	
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	// do not use memcmp to compare an (LE)interger value.
	DB * sdbp = *(DB **)heights_db->priv;
	sdbp->set_bt_compare(sdbp, compare_little_endian_int32); // sorted by { is_orphan, height }
	
	sdbp = *(DB **)orphan_blocks->priv;
	sdbp->set_bt_compare(sdbp, compare_little_endian_int32);
#endif

	rc = heights_db->open(heights_db, NULL, priv->heights_db_name, db_format_type_btree, db_flags_dup_sort);
	assert(0 == rc);
	engine->list_add(engine, heights_db);
	
	rc = orphan_blocks->open(orphan_blocks, NULL, priv->orphans_db_name, db_format_type_btree, db_flags_dup_sort);
	assert(0 == rc);
	engine->list_add(engine, orphan_blocks);
	
	
	// open blocks.db
	priv->blocks = engine->open_db(engine, db_name, db_format_type_btree, 0);
	assert(priv->blocks);

	// sorted by 'height' and 'is_orphan' fields
	rc = priv->blocks->associate(priv->blocks, NULL, heights_db, associate_blocks_height);
	assert(0 == rc);

	rc = priv->blocks->associate(priv->blocks, NULL, orphan_blocks, associate_blocks_is_orphan);
	assert(0 == rc);

	return priv;
#undef HEIGHTS_DB_SUFFIX
#undef ORPHANS_DB_SUFFIX
}

static void blocks_db_private_free(blocks_db_private_t * priv)
{
	if(NULL == priv) return;
	db_engine_t * engine = priv->engine;
	if(engine) {
		if(priv->heights_db) {
			engine->list_remove(engine, priv->heights_db);
			priv->heights_db->close(priv->heights_db);
			priv->heights_db = NULL;
		}
		
		if(priv->orphan_blocks)
		{
			engine->list_remove(engine, priv->orphan_blocks);
			priv->orphan_blocks->close(priv->orphan_blocks);
			priv->orphan_blocks = NULL;
		}
		
		if(priv->blocks) {
			engine->list_remove(engine, priv->blocks);
			priv->blocks->close(priv->blocks);
			priv->blocks = NULL;
		}
	}
	free(priv);
	return;
}

static int blocks_db_add(struct blocks_db * db, db_engine_txn_t * txn, 
	const uint256_t * hash,
	const db_record_block_t * block)
{
	assert(db && db->priv && hash && block);
	blocks_db_private_t * priv = db->priv;
	db_handle_t * blocks = priv->blocks;
	assert(blocks);
	
	return blocks->insert(blocks, txn, 
		&(db_record_data_t){.data = (void *)hash, .size = sizeof(uint256_t)},
		&(db_record_data_t){.data = (void *)block, .size = sizeof(*block)}); 
}
static int blocks_db_remove(struct blocks_db * db, db_engine_txn_t * txn, const uint256_t * hash)
{
	assert(db && db->priv && hash);
	blocks_db_private_t * priv = db->priv;
	db_handle_t * blocks = priv->blocks;
	assert(blocks);
	
	return blocks->del(blocks, txn, 
		&(db_record_data_t){.data = (void *)hash, .size = sizeof(uint256_t)});
}
static ssize_t blocks_db_find(struct blocks_db * db, db_engine_txn_t * txn, 
	const uint256_t * hash, 
	db_record_block_t ** p_block)
{
	assert(db && db->priv && hash && p_block);
	blocks_db_private_t * priv = db->priv;
	db_handle_t * blocks = priv->blocks;
	assert(blocks);
	
	db_record_data_t * value = NULL;
	
	ssize_t count = blocks->find(blocks, txn, 
		&(db_record_data_t){.data = (void *)hash, .size = sizeof(uint256_t)},
		&value);
	if(count > 0)
	{
		assert(count == 1);
		assert(value->size == sizeof(db_record_block_t));
		
		db_record_block_t * block = *p_block;
		if(NULL == block) {
			if(value->flags == 1)	// dynamically allocated memory by calloc
			{
				*p_block = value->data;
				value->data = NULL;
				value->flags = 0;
			}else
			{
				block = calloc(1, sizeof(*block));
				assert(block);
				*p_block = block;
			}
		}
		if(value->data) memcpy(block, value->data, value->size);
	}

// cleanup
	if(value)
	{
		db_record_data_cleanup(value);
		free(value);
	}
	return count;
}

static ssize_t blocks_db_find_at(struct blocks_db * db, db_engine_txn_t * txn, 
	const int32_t height, 
	uint256_t ** p_hashes, db_record_block_t ** p_blocks)
{
	ssize_t count = 0;
	assert(db && db->priv && (p_hashes || p_blocks));
	
	blocks_db_private_t * priv = db->priv;
	db_handle_t * sdb = priv->heights_db;
	assert(sdb);
	
	db_record_data_t * keys = NULL;
	db_record_data_t * values = NULL;
	
	count = sdb->find_secondary(sdb, txn, 
		&(db_record_data_t){.data = (void *)&height, .size = sizeof(int32_t)},
		&keys, &values);
	if(count > 0)
	{
		uint256_t * hashes = NULL;
		db_record_block_t * results = NULL;
		
		if(p_hashes) {
			hashes = *p_hashes;
			if(NULL == hashes) {
				hashes = calloc(count, sizeof(*hashes));
				assert(hashes);
				*p_hashes = hashes;
			}
		}
		if(p_blocks) {
			results = *p_blocks;
			if(NULL == results) {
				results = calloc(count, sizeof(*results));
				assert(results);
				*p_blocks = results;
			}
		}
		
		for(ssize_t i = 0; i < count; ++i)
		{
			if(hashes) {
				assert(keys[i].size == sizeof(uint256_t));
				memcpy(&hashes[i], keys[i].data, keys[i].size);
			}
			if(results) {
				assert(values[i].size == sizeof(db_record_block_t));
				memcpy(&results[i], values[i].data, values[i].size);
			}
			
			db_record_data_cleanup(&keys[i]);
			db_record_data_cleanup(&values[i]);
		}
	}
	
	if(keys) free(keys);
	if(values) free(values);
	
	
	
	return count;
}

static int32_t blocks_db_get_latest(struct blocks_db * db, db_engine_txn_t * txn, 
	uint256_t * hash,
	db_record_block_t * block
)
{
	int rc = -1;
	assert(db && db->priv);
	
	blocks_db_private_t * priv = db->priv;
	assert(priv->heights_db && priv->heights_db->priv);
	
	DB * sdbp = *(DB **)priv->heights_db->priv;
	DBC * cursor = NULL;
	
	struct {
		int32_t height;
		int32_t is_orphan;
	}indice;
	memset(&indice, 0, sizeof(indice));
	
	rc = sdbp->cursor(sdbp, txn?txn->priv:NULL, &cursor, DB_READ_COMMITTED);
	assert(0 == rc);
	
	DBT skey, key, value;
	memset(&skey, 0, sizeof(skey));
	memset(&key, 0, sizeof(key));
	memset(&value, 0, sizeof(value));

	skey.data = &indice;
	skey.ulen = sizeof(indice);
	skey.flags = DB_DBT_USERMEM;
	
	key.flags = DB_DBT_MALLOC;
	value.flags = DB_DBT_MALLOC;
	
	if(hash){
		key.flags = DB_DBT_USERMEM;
		key.data = hash;
		key.ulen = sizeof(*hash);
	}
	
	if(block) {
		value.flags = DB_DBT_USERMEM;
		value.data = block;
		value.ulen = sizeof(*block);
	}
	
	rc = cursor->pget(cursor, &skey, &key, &value, DB_LAST);
	while(0 == rc)
	{
		if(0 == indice.is_orphan) break;
		rc = cursor->pget(cursor, &skey, &key, &value, DB_PREV_DUP);
	}
	cursor->close(cursor);
	if(key.flags & DB_DBT_MALLOC) free(key.data);
	if(value.flags & DB_DBT_MALLOC) free(value.data);
	
	if(0 == rc) return indice.height;
	return -1;
}

blocks_db_t * blocks_db_init(blocks_db_t * db, db_engine_t * engine, const char * db_name, void * user_data)
{
	if(NULL == db_name) db_name = "blocks.db";
	
	if(NULL == db) db = calloc(1, sizeof(*db));
	assert(db);
	
	db->user_data = user_data;
	
	db->add = blocks_db_add;
	db->remove = blocks_db_remove;
	db->find = blocks_db_find;
	db->find_at = blocks_db_find_at;
	db->get_latest = blocks_db_get_latest;
	
	blocks_db_private_t * priv = blocks_db_private_new(db, engine, db_name);
	assert(priv && db->priv == priv);
	
	return db;
}

void blocks_db_cleanup(blocks_db_t * db)
{
	if(NULL == db) return;
	blocks_db_private_free(db->priv);
	db->priv = NULL;
	return;
}


#if defined(_TEST_BLOCKS_DB) && defined(_STAND_ALONE)


static void dump_records(db_handle_t * db)
{
	DBC * cursor = NULL;
	DB * dbp = *(DB **)db->priv;
	assert(dbp);
	int rc = -1;
	
	unsigned char hash[32];
	memset(hash, 0, sizeof(hash));
	
	rc = dbp->cursor(dbp, NULL, &cursor, DB_READ_COMMITTED);
	assert(0 == rc);
	
	DBT key, value;
	memset(&key, 0, sizeof(key));
	memset(&value, 0, sizeof(value));
	
	
	key.flags = DB_DBT_USERMEM;
	key.data = hash;
	key.ulen = 32;
	
	rc = cursor->get(cursor, &key, &value, DB_FIRST);
	assert(0 == rc);
	
	while(0 == rc)
	{
		struct db_record_block * data = value.data;
		assert(data && value.size == sizeof(*data));
		
		if(key.size != sizeof(int64_t))
		{
			printf("key: %d, value: height=%d, timestamp=%d, is_orphan=%d\n", 
				*(int *)hash, 
				data->height, data->hdr.timestamp,
				data->is_orphan
				);
		}else
		{
			int32_t * p_key = (int32_t *)hash;
			printf("key: {%d, %d}, value: height=%d, timestamp=%d, is_orphan=%d\n", 
				p_key[0], p_key[1],
				data->height, data->hdr.timestamp,
				data->is_orphan
				);
		}
		rc = cursor->get(cursor, &key, &value, DB_NEXT);
	}
	
	assert(rc == DB_NOTFOUND);
	cursor->close(cursor);
	return;
}

int main(int argc, char **argv)
{
	system("mkdir -p data1");
	db_engine_t * engine = db_engine_init("data1", NULL);
	assert(engine);
	
	blocks_db_t * db = blocks_db_init(NULL, engine, "blocks.db", NULL);
	assert(db);
	
	int rc = 0;
	// add records 
	uint256_t hash[1];
	memset(hash, 0, sizeof(hash));
	struct db_record_block block[1];

	for(int i = 0; i < 10; ++i)
	{	
		*(int *)hash->val = 1000 + i + 1;
		memset(block, 0, sizeof(block));
		block->height = i;
		block->hdr.timestamp = 1000 + i;
		
		rc = db->add(db, NULL, hash, block);
		if(rc == DB_KEYEXIST) break;
		assert(0 == rc);
	}
	
	// append orphan blocks (same height but diffent hash)
	memset(block, 0, sizeof(block));
	
	for(int i = 3; i < 5; ++i)
	{
		*(int *)hash->val = 2000 + i + 1;
		block->height = i;
		block->hdr.timestamp = 1000 + i;
		block->is_orphan = 1;
		rc = db->add(db, NULL, hash, block);
		if(rc == DB_KEYEXIST) break;
		assert(0 == rc);
	}
	
	blocks_db_private_t * priv = db->priv;
	printf("=== dump blocks.db ====\n");
	dump_records(priv->blocks);
	
	printf("=== dump blocks_heights.db ====\n");
	dump_records(priv->heights_db);
	
	printf("=== dump blocks_orphans.db ====\n");
	dump_records(priv->orphan_blocks);
	
	
	// get latest block
	memset(hash, 0, sizeof(uint256_t));
	memset(block, 0, sizeof(block));
	int32_t height = db->get_latest(db, NULL, hash, block);
	printf("== latest: height=%d, hash=%d, timestamp=%d\n",
		height, 
		*(int32_t *)hash,
		block->hdr.timestamp);
	
	// find at (height = 3)
	memset(hash, 0, sizeof(uint256_t));
	memset(block, 0, sizeof(block));
	
	uint256_t * hashes = NULL;
	db_record_block_t * blocks = NULL;
	ssize_t count = db->find_at(db, NULL, 3, &hashes, &blocks);
	printf("height: 3, count=%Zd\n", count);
	
	for(ssize_t i = 0; i < count; ++i)
	{
		printf("hash: %d, is_orphan: %d\n", *(int *)hashes[i].val, blocks[i].is_orphan);
	}
	free(hashes);
	free(blocks);
	
	
	blocks_db_cleanup(db);
	return 0;
}
#endif

