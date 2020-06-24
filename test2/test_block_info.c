/*
 * test_block_info.c
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

#include "satoshi-types.h"

/**
 * Functions test: 
 *  - block_info_new()
 *  - block_info_add_child()
 *  - block_info_free()
 * 
 * compile:
 *   $ cd test2
 * 	 $ gcc -std=gnu99 -g -Wall -I../include -o test_block_info test_block_info.c ../src/compact_int.c  -lgmp -lm -D_DEBUG
 * 
 * test:
 *   $ valgrind --leak-check=full ./test_block_info
 * 
 */

typedef struct block_info
{
	uint256_t hash;
	
	/**
	 * hdr: 
	 *   nullable, 
	 *   can be attached to a (struct satoshi_block_header *) or a (struct satoshi_block *)
	 */
	const struct satoshi_block_header * hdr;	
	
	int height;		// the index in the longest-chain, -1 means not attached to any chains
	double cumulative_difficulty;
	compact_uint256_t cumulative_difficulty_cint;	// use compact int to calc cumulative difficulty.
	
	struct block_info * parent;	// there can be only one parent for each block
	struct block_info * first_child;	// the first child will belong to the longest-chain
	
	/*
	 * All siblings would be abondanded and regarded as orphans, 
	 * but if they can reproduce enough offspring (longer the first-child) , 
	 * they can regain their family status and become the first-child.
	 */
	struct block_info * next_sibling;

#ifdef _DEBUG
	int id;
#endif
}block_info_t;

block_info_t * block_info_new(const uint256_t * hash, const struct satoshi_block_header * hdr)
{
	block_info_t * info = calloc(1, sizeof(*info));
	assert(info);
	
	if(hash) memcpy(&info->hash, hash, sizeof(*hash));
	info->hdr = hdr;
	info->height = -1;
	
	return info;
}

void block_info_free(block_info_t * info)
{
	if(info->next_sibling)
	{
		block_info_free(info->next_sibling);
		info->next_sibling = NULL;
	}
	
	if(info->first_child) {
		block_info_free(info->first_child);
		info->first_child = NULL;
	}
	
#ifdef _DEBUG
	printf("free info: id = %d\n", info->id);
#endif

	free(info);
}


int block_info_add_child(block_info_t * parent, block_info_t * child)
{
	assert(parent);
	if(NULL == parent->first_child) parent->first_child = child;
	else {
		block_info_t * sibling = parent->first_child;
		while(sibling->next_sibling) sibling = sibling->next_sibling;
		sibling->next_sibling = child;
	}
	child->parent = parent;
	return 0;
}

#ifdef _DEBUG
#define MAX_QUEUE_SIZE  4096
struct block_info_queue
{
	const block_info_t * data[MAX_QUEUE_SIZE];
	int start_pos;
	int length;
};

static int queue_enter(struct block_info_queue * queue, const block_info_t * info)
{
	int cur_pos = queue->start_pos + queue->length;
	cur_pos %= MAX_QUEUE_SIZE;
	
	//printf("queue.data[%d] = %d\n", cur_pos, info->id);
	queue->data[cur_pos] = info;
	++queue->length;
	assert(queue->length < MAX_QUEUE_SIZE);
	return 0;
}

static const block_info_t * queue_leave(struct block_info_queue * queue)
{
	if(queue->length <= 0) return NULL;
	
	int start_pos = queue->start_pos++;
	queue->start_pos %= MAX_QUEUE_SIZE;
	
	--queue->length;
	return queue->data[start_pos];
}

// Breadth-first search
void block_info_dump_BFS(const block_info_t * root)
{
	struct block_info_queue queue[1];
	memset(queue, 0, sizeof(queue));
	
	queue_enter(queue, root);
	
	int level = 0;
	int last_id_of_current_level = root->id;
	
	printf("======== level %d ========\n", level++);
	while(queue->length > 0)
	{
		const block_info_t * node = queue_leave(queue);
		printf("\t info.id = %d\n", node->id);
		if(node->id == last_id_of_current_level)
		{
			
			printf("======== level %d ========\n", level++);
			last_id_of_current_level = -1;
		}

		const block_info_t * sibling = node->first_child;
		while(sibling)
		{
			queue_enter(queue, sibling);
			if(last_id_of_current_level < 0 && sibling->next_sibling == NULL) last_id_of_current_level = sibling->id;
			sibling = sibling->next_sibling;
		}
	}
}
#undef MAX_QUEUE_SIZE
#endif

int test_block_info(void)
{
#define NUM_BLOCK_INFO	(10)
	block_info_t * blocks[NUM_BLOCK_INFO] = { NULL };
	for(int i = 0; i < NUM_BLOCK_INFO; ++i)
	{
		blocks[i] = block_info_new(NULL, NULL);
		assert(blocks[i]);
		
	#ifdef _DEBUG
		blocks[i]->id = i;
	#endif
	}
	
	/**
	 * Create Tree:
	 * level-0     level-1     level-2
	 * ------------------------------------------
	 *    0     -     1     -     2
	 *          -     3     -     5
	 *                      -     6     -     8
	 *          -     4     -     7
	 *                      -     9
	 * -----------------------------------------
	 */
	// level 0
	block_info_add_child(blocks[0], blocks[1]);
	block_info_add_child(blocks[0], blocks[3]);
	block_info_add_child(blocks[0], blocks[4]);
	
	// level 1
	block_info_add_child(blocks[1], blocks[2]);
	block_info_add_child(blocks[3], blocks[5]);
	block_info_add_child(blocks[3], blocks[6]);
	
	block_info_add_child(blocks[4], blocks[7]);
	block_info_add_child(blocks[4], blocks[9]);
	
	// level-2
	block_info_add_child(blocks[6], blocks[8]);
	
	
	block_info_dump_BFS(blocks[0]);
	
	// Destroy Tree:
	block_info_free(blocks[0]);

	return 0;
#undef NUM_BLOCK_INFO
}

int main(int argc, char ** argv)
{
	test_block_info();
}

