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
#include "../src/chains.c"

/**
 * Functions test: 
 *  - block_info_new()
 *  - block_info_add_child()
 *  - block_info_free()
 *  - block_info_update_cumulative_difficulty()
 * 
 * 
 * 
 * compile:
 *   $ cd test2
 * 	 $ gcc -std=gnu99 -g -Wall -I../include -o test_block_info test_block_info.c ../src/compact_int.c  -lgmp -lm -D_DEBUG
 * 
 * test:
 *   $ valgrind --leak-check=full ./test_block_info
 * 
 */


#ifdef _DEBUG

// Breadth-first search
void block_info_dump_BFS(block_info_t * root)
{
	struct clib_queue queue[1];
	memset(queue, 0, sizeof(queue));
	clib_queue_init(queue, 0);
	
	queue->enter(queue, root);
	
	int level = 0;
	int last_id_of_current_level = root->id;
	
	printf("======== level %d ========\n", level++);
	while(queue->length > 0)
	{
		block_info_t * node = queue->leave(queue);
		printf("\t info.id = %d, cumulative_difficulty = 0x%.8x\n", node->id, node->cumulative_difficulty.bits);
		if(node->id == last_id_of_current_level)
		{
			
			printf("======== level %d ========\n", level++);
			last_id_of_current_level = -1;
		}

		block_info_t * sibling = node->first_child;
		while(sibling)
		{
			queue->enter(queue, sibling);
			if(last_id_of_current_level < 0 && sibling->next_sibling == NULL) last_id_of_current_level = sibling->id;
			sibling = sibling->next_sibling;
		}
	}
	
	clib_queue_cleanup(queue);
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
		blocks[i]->hdr->bits = 0x20FFFFFE;		// set difficulty to (int)1
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
	
	
	
	
	
	printf("==== update cumulative_difficulty ...\n");
	block_info_update_cumulative_difficulty(blocks[0], 
		(compact_uint256_t){.bits = 0 }	// blocks[0] is the genesis block and has no parent 
	);
	
	// dump info
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

