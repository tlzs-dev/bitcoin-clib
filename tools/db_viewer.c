/*
 * db_viewer.c
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

#include "db_engine.h"
#include "shell.h"
#include <gtk/gtk.h>

#include <db.h>
#include "blocks_db.h"


int main(int argc, char **argv)
{
	db_manager_t * db_mgr = db_manager_init(NULL, NULL, NULL);
	shell_context_t * shell = shell_context_init(NULL, argc, argv, db_mgr);
	assert(shell);
	
	shell->init(shell, NULL);
	shell->run(shell);
	
	shell_context_cleanup(shell);
	db_manager_cleanup(db_mgr);
	
	return 0;
}

#include <endian.h>
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static int compare_little_endian_int32(DB * db, const DBT * dbt1, const DBT * dbt2)
{
	int32_t a = *(int32_t *)dbt1->data;
	int32_t b = *(int32_t *)dbt2->data;
	return a - b;
}
#endif

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

db_manager_t * db_manager_init(db_manager_t * db_mgr, const char * db_home, void * user_data)
{
	int rc = 0;
	if(NULL == db_home) db_home = "../tests/data";
	if(NULL == db_mgr) db_mgr = calloc(1, sizeof(*db_mgr));
	db_mgr->db_home = strdup(db_home);
	
	db_engine_t * engine = db_engine_init(NULL, db_home, user_data);
	assert(engine);
	db_mgr->engine = engine;
	
	db_handle_t * heights_db = db_handle_init(NULL, engine, NULL);

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	// do not use memcmp to compare an (LE)interger value.
	DB * sdbp = *(DB **)heights_db->priv;
	sdbp->set_bt_compare(sdbp, compare_little_endian_int32); // sorted by { is_orphan, height }
#endif

	rc = heights_db->open(heights_db, NULL, "blocks_height.db", db_format_type_btree, db_flags_dup_sort);
	assert(0 == rc);
	engine->list_add(engine, heights_db);
	db_mgr->heights_db = heights_db;
	
	db_handle_t * block_db = engine->open_db(engine, "blocks.db", db_format_type_btree, 0);
	assert(block_db);
	db_mgr->block_db = block_db;
	
	rc = block_db->associate(block_db, NULL, heights_db, associate_blocks_height);
	assert(0 == rc);
	
	db_handle_t * utxo_db = engine->open_db(engine, "utxoes.db", db_format_type_hash, 0);
	assert(utxo_db);
	db_mgr->utxo_db = utxo_db;
	
	return db_mgr;
}
void db_manager_cleanup(db_manager_t * db_mgr)
{
	if(NULL == db_mgr) return;
	db_engine_cleanup(db_mgr->engine);
	return;
}

