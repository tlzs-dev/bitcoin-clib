/*
 * merkle_tree.c
 * 
 * Copyright 2020 Che Hongwei <htc.chehw@gmail.com>
 * 
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person 
 * obtaining a copy of this software and associated documentation 
 * files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, 
 * publish, distribute, sublicense, and/or sell copies of the Software, 
 * and to permit persons to whom the Software is furnished to do so, 
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 *  in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR 
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#include "bitcoin.h"
#include "crypto.h"
#include "utils.h"

#include "satoshi-types.h"
#define MERKLE_TREE_MAX_LAYERS (32)
typedef struct merkle_tree_layer
{
	int max_size;
	int count;
	uint256_t * items;
}merkle_tree_layer_t;

int merkle_tree_layer_resize(merkle_tree_layer_t * layer, int size)
{
	size += size & 0x01;
	if(size <= layer->max_size) return 0;
	
	uint256_t * items = realloc(layer->items, size * sizeof(*items));
	assert(items);
	
	memset(&items[layer->max_size], 0, (size - layer->max_size) * sizeof(*items));
	layer->items = items;
	layer->max_size = size;
	return 0;
}

typedef struct merkle_tree_private
{
	uint256_merkle_tree_t * mtree;
	int layers_count;	// mtree->levels
	merkle_tree_layer_t layers[MERKLE_TREE_MAX_LAYERS];
}merkle_tree_private_t;

static void merkle_tree_private_free(merkle_tree_private_t * priv)
{
	if(NULL == priv) return;
	for(int i = 0; i < MERKLE_TREE_MAX_LAYERS; ++i)
	{
		merkle_tree_layer_t * layer = &priv->layers[i];
		if(layer->items)
		{
			free(layer->items);
			layer->items = NULL;
			layer->max_size = 0;
			layer->count = 0;
		}
	}
	
	free(priv);
	return;
}
static merkle_tree_private_t * merkle_tree_private_new(uint256_merkle_tree_t * mtree)
{
	merkle_tree_private_t * priv = calloc(1, sizeof(*priv));
	assert(priv);
	priv->mtree = mtree;
	mtree->priv = priv;

	return priv;
}

static int merkle_tree_recalc(struct uint256_merkle_tree * mtree, int start_index, int count)
{
	if(NULL == mtree->hash_func) mtree->hash_func = hash256;	// default hash function
	
	if(count < 0) count = (mtree->count - start_index);
	
	if(mtree->count <= 1) {
		if(mtree->count == 1) memcpy(&mtree->merkle_root, &mtree->items[0], 32);
		return 0;	// no need to recalc
	}
	assert(start_index >= 0 && start_index < mtree->count);
	
	if(count <= 0) count = mtree->count - start_index;
	merkle_tree_private_t * priv = mtree->priv;
	assert(priv);
	
	int rc = 0;
	int layer_index;
	
	uint256_t * items = mtree->items;
	uint256_t data[2];	// if count is an odd number, take the last_hash twice
	
	assert(start_index == 0);	///< @todo: update dirty hashes only ( update from start_index)
	for(layer_index = 0; layer_index < MERKLE_TREE_MAX_LAYERS; ++layer_index)
	{
		merkle_tree_layer_t * layer = &priv->layers[layer_index];
		int layer_size = (count + 1) / 2;
		rc = merkle_tree_layer_resize(layer, layer_size);
		assert(0 == rc);
		int i;
		for(i = 0; i < count / 2; ++i)
		{
			mtree->hash_func(&items[i * 2], 64, layer->items[i].val);
		}
		if(count & 0x01)
		{
			data[0] = items[count - 1];
			data[1] = data[0];
			mtree->hash_func(data, 64, layer->items[i].val);
		}
		
		layer->count = layer_size;
		items = layer->items;
		count = layer_size;
		
		if(layer_size == 1)
		{
			mtree->merkle_root = layer->items[0];
			break;
		}
	}
	priv->layers_count = layer_index;
	return 0;
}

#define MERKLE_TREE_ALLOC_SIZE (4096)
static int merkle_tree_resize(struct uint256_merkle_tree * mtree, ssize_t size)
{
	ssize_t	 new_size = (size + MERKLE_TREE_ALLOC_SIZE - 1) / MERKLE_TREE_ALLOC_SIZE * MERKLE_TREE_ALLOC_SIZE;
	if(new_size <= mtree->max_size) return 0;
	
	uint256_t * items = realloc(mtree->items, new_size * sizeof(*items));
	assert(items);
	
	memset(&items[mtree->max_size], 0, (new_size - mtree->max_size) * sizeof(*items));
	mtree->items = items;
	mtree->max_size = new_size;
	
	return 0;
}
#undef MERKLE_TREE_ALLOC_SIZE

static int merkle_tree_add(struct uint256_merkle_tree * mtree, int count, const uint256 * items)
{
	assert((mtree->count + count) > mtree->count); // (count >=0 and no integer overflow)
	assert(mtree && items);
	
	int rc = merkle_tree_resize(mtree, mtree->count + count);
	assert(0 == rc);
	
	uint256 * dst = mtree->items + mtree->count;
	for(int i = 0; i < count; ++i)
	{
		dst[i] = items[i];
	}
	mtree->count += count;
	return 0;
}

static int merkle_tree_remove(struct uint256_merkle_tree * mtree, int index)
{
	if(mtree->count <= 0 || index < 0 || index >= mtree->count) return -1;
	--mtree->count;
	if(index < mtree->count)
	{
		mtree->items[index] = mtree->items[mtree->count];
	}
	memset(&mtree->items[mtree->count], 0, sizeof(mtree->items[0]));
	return 0;
}

static int merkle_tree_set(struct uint256_merkle_tree * mtree, int index, const uint256 item)
{
	if(mtree->count <= 0 || index < 0 || index >= mtree->count) return -1;
	mtree->items[index] = item;
	return 0;
}

uint256_merkle_tree_t * uint256_merkle_tree_new(ssize_t max_size, void * user_data)
{
	uint256_merkle_tree_t * mtree = calloc(1, sizeof(*mtree));
	assert(mtree);
	
	mtree->user_data = user_data;
	
	mtree->hash_func = hash256;
	mtree->add = merkle_tree_add;
	mtree->remove = merkle_tree_remove;
	mtree->recalc = merkle_tree_recalc;
	
	mtree->set = merkle_tree_set;

	merkle_tree_private_t * priv = merkle_tree_private_new(mtree);
	assert(priv && priv->mtree == mtree && mtree->priv == priv);
	
	merkle_tree_resize(mtree, max_size);
	
	return mtree;
}

void uint256_merkle_tree_free(uint256_merkle_tree_t * mtree)
{
	if(NULL == mtree) return;
	merkle_tree_private_free(mtree->priv);
	free(mtree->items);
	free(mtree);
	return;
}

/**********************************************************************
 * TEST MODULE
 * 	build and test: 
 * ( $ cd ${project_dir} && mkdir -p tests )
 $ gcc -std=gnu99 -g -Wall -D_TEST_MERKLE_TREE -D_STAND_ALONE \
    -o tests/test_merkle_tree src/merkle_tree.c src/satoshi-types.c \
    src/base/sha256.c src/utils/utils.c \
    -Iinclude -lm -lpthread -ljson-c 

 $ valgrind --leak-check=full tests/test_merkle_tree
**********************************************************************/
#if defined(_TEST_MERKLE_TREE) && defined(_STAND_ALONE)

#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <json-c/json.h>

#include "utils.h"
void recalc(const uint256_t * txes, ssize_t count, uint256_t * merkle_root);
int main(int argc, char ** argv)
{
	char exe_name[PATH_MAX] = "";
	readlink("/proc/self/exe", exe_name, sizeof(exe_name));
	
	char * dir = dirname(exe_name);
	printf("working directory: %s\n", dir);
	
	int rc = chdir(dir);
	assert(0 == rc);

	const char * block_file = "block.json";
	json_object * jblock = json_object_from_file(block_file);
	assert(jblock);
	
	const char * block_hash_hex = json_get_value(jblock, string, hash);
	int block_height = json_get_value(jblock, int, height);
	const char * merkle_root_hash_hex = json_get_value(jblock, string, merkleroot);
	json_object * jtxes = NULL;
	json_bool ok = FALSE;
	ok = json_object_object_get_ex(jblock, "tx", &jtxes);
	assert(ok);
	
	printf("block %d: hash='%s', merkle_root='%s'\n", 
		block_height, 
		block_hash_hex, 
		merkle_root_hash_hex);
	
	int tx_count = json_object_array_length(jtxes);
	assert(tx_count >= 1);
	
	uint256_merkle_tree_t * mtree = uint256_merkle_tree_new(tx_count, NULL);
	
	uint256_t * txes = calloc(tx_count + (tx_count & 0x01), sizeof(*txes));
	
	for(int i = 0; i < tx_count; ++i)
	{
		json_object * jtx = json_object_array_get_idx(jtxes, i);
		assert(jtx);
		
		const char * tx_hex = json_object_get_string(jtx);
		assert(tx_hex);
		
		uint256_t * tx = &txes[i];
		ssize_t cb = uint256_from_string(tx, 1, tx_hex, -1);
		printf("tx[%d]: cb=%d, str=", i, (int)cb);
		dump(tx, 32);
		printf("\n");
		
		
	}
	mtree->add(mtree, tx_count, txes);
	merkle_tree_recalc(mtree, 0, -1);
	printf("merkle_tree_recalc::merkle_root: ");
	dump(&mtree->merkle_root, 32);
	printf("\n");
	
	uint256_t merkle_root[1];
	memset(merkle_root, 0, sizeof(merkle_root));
	recalc(txes, tx_count, merkle_root); // truth function, to verify the result of merkle_tree_recalc() 
	
	assert(0 == memcmp(merkle_root, &mtree->merkle_root, sizeof(merkle_root)));
	
	free(txes);
	uint256_merkle_tree_free(mtree);
	json_object_put(jblock);
	return 0;
}

// verify result
void recalc(const uint256_t * txes, ssize_t count, uint256_t * merkle_root)	
{
	merkle_tree_layer_t layeres[32];
	memset(layeres, 0, sizeof(layeres));
	
	const uint256_t * items = txes;
	uint256_t data[2];
	
	for(int layer_index = 0; layer_index < MERKLE_TREE_MAX_LAYERS; ++layer_index)
	{
		ssize_t layer_size = (count + 1) / 2;
		merkle_tree_layer_t * layer = &layeres[layer_index];
		merkle_tree_layer_resize(layer, layer_size);
		layer->count = layer_size;
	//	printf("layer[%d]: max_size = %d, count = %d\n", layer_index, (int)layer->max_size, (int)layer->count);
		int i;
		for(i = 0; i < count / 2; ++i)
		{
			hash256(&items[i * 2], 64, (unsigned char *)&layer->items[i]);
		}
	//	printf("\t i = %d\n", i);
		if(count & 0x01)	// if count is an odd number
		{
			data[0] = items[count - 1];
			data[1] = data[0];
			hash256(data, 64, (unsigned char *)&layer->items[i]);
		}
		items = layer->items;
		count = layer->count;
		if(count == 1) {
			memcpy(merkle_root, layer->items, 32);
			printf("TRUTH::merkle_root: ");
			dump(layer->items, 32);
			printf("\n");
			break;
		}
	}
	
	for(int layer_index = 0; layer_index < MERKLE_TREE_MAX_LAYERS; ++layer_index)
	{
		merkle_tree_layer_t * layer = &layeres[layer_index];
		if(layer->items) free(layer->items);
	}
	return;
}
#endif

#undef MERKLE_TREE_MAX_LAYERS // (32)
