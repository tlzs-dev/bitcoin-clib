/*
 * chains.c
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

#include "satoshi-types.h"
#include "utils.h"

#include "chains.h"

/**
 * @file chains.c
 * 
 * If two nodes broadcast different versions of the next block simultaneously, 
 * there will be disputes about who is orthodox.
 * 
 * According to the Satoshi paper, 
 * "Nodes always consider the longest chain to be the correct one and will keep working on extending it."
 
 * However, if multiple nodes broadcast different versions of the next block, 
 * there will be multiple active chains at the same time, each will be keeping exists 
 * until the tie was broken by one of chain who successfully acquired the largest amount of proof-of-work.
 * 
 * When multiple chains coexist, it may become the following complicated situation, 
 * making the problem difficult to solve.
 * 
 *   chain1:  (parent) - A0 - B0 - C0
 *                            B0 - C1 - D0
 *                            B1 - C2
 *                            B1 - C3 - D1 - E0 - F0
 *   
 *   chain2:  (parent) - A0 - B2 
 *                            B3 - C4 - D2 - E1
 *   
 *   chain3:  (parent) - A1 - B4
 *                            B5 - C5 - D3 - E3 - F1 - G0
 *                            B5 - C6
 *                            B5 - C7 - D4 - E4 - F2 - G1 - H0
 *   
 *   ...
 *  
 * so, we need to find an algorithm to solve this problem
 */


/**
 * struct active_chain 
 * struct active_chain_list
 * 
 * @details
 * - Rule 0. Any orphan MUST be checked by themselves and by chains, to find out 
 *   whether the orphan is a clone. (duplicated, current processing should be ignored). 
 * 
 * - Rule I. Any orphans should first look for their parents in the chains-list.
 * 
 * - Rule II. If parents can be found in one of the chains, then join the chain and do the following steps:
 *     1. get the current cumulative difficulty of the parent;
 *     2. calcute and find the tail-node with the the largest cumulative-difficulty of his own branch; 
 *     3. report the tail-node to the chain;
 *     4. if the the tail-node's cumulative-difficulty is also the largest in the chain, 
 *     the chain will revise the family tree, make all nodes on this branch containing the tail-node 
 *     become the first-child or their parents.
 * 
 * - Rule III. Any orphans who do not know their parents should create a new chain, then find out 
 *   whether there are children in the chains-list. Since any orphans can only have one unique parent,
 *   the child (or children) must be the head of his (or their) chain. Claim this(these) chain(s) and
 *   make them be their children. 
 *   
 * 
 * - Rule IV. If a chain known his parent in the BLOCKCHAIN and his longest-offspring is supper than the current,
 *   replace the current one, and bring all the first-child on his chain back to the royal family.
 * 
 */
int block_info_update_cumulative_difficulty(
	block_info_t * node, // current node
	compact_uint256_t cumulative_difficulty,	// parent's cumulative_difficulty
	block_info_t ** p_longest_offspring			// the child who currently at the end of the longest-chain  
);
int block_info_declare_inheritance(block_info_t * heir);
static int active_chain_list_resize(active_chain_list_t * list, ssize_t max_size);


enum traverse_action_type
{
	traverse_action_type_add,
	traverse_action_type_remove,
	traverse_action_types_count
};
static int search_tree_traverse_BFS(void ** p_search_root, enum traverse_action_type type, block_info_t * node);

#define MAX_FUTURE_BLOCK_TIME	(2 * 60 * 60)
const uint256_t g_genesis_block_hash[1] = {{
		.val = {
			0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
			0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 
			0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 
			0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00
		}
}};

/**
 * genesis block
01000000
0000000000000000000000000000000000000000000000000000000000000000
3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a
29ab5f49
ffff001d
1dac2b7c
0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000
 
 */
const struct satoshi_block_header g_genesis_block_hdr[1] = {{
	.version = 1,
	.prev_hash = {{ .val = { 0 } }},
	.merkle_root = {{
		.val = {
			0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 
			0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61, 
			0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 
			0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a
		}
	}},
	.timestamp = 0x495fab29,
	.bits = 0x1d00ffff,
	.nonce = 0x7c2bac1d,
}};

#define BLOCKCHAIN_DEFAULT_ALLOC_SIZE (6 * 24 * 365 * 100)	// (6 blocks per hour) * 24hours * 365days * 100years

/***********************************************************************
 * blockchain
 **********************************************************************/
typedef int (* blockchain_heir_compare_func)(const void *, const void *);
static blockchain_heir_compare_func blockchain_heir_compare = (blockchain_heir_compare_func)uint256_compare; 

static int blockchain_resize(blockchain_t * chain, ssize_t size)
{
	if(size <= 0) size = BLOCKCHAIN_DEFAULT_ALLOC_SIZE;
	else size = (size + BLOCKCHAIN_DEFAULT_ALLOC_SIZE - 1) / BLOCKCHAIN_DEFAULT_ALLOC_SIZE * BLOCKCHAIN_DEFAULT_ALLOC_SIZE;
	
	if(size <= chain->max_size) return 0;
	
	blockchain_heir_t * heirs = realloc(chain->heirs, size * sizeof(*heirs));
	assert(heirs);
	
	memset(heirs, 0, (size - chain->max_size) * sizeof(*heirs));
	chain->heirs = heirs;
	chain->max_size = size;
	return 0;
}

static int blockchain_add(blockchain_t * chain, const uint256_t * hash, const struct satoshi_block_header * hdr);
static const blockchain_heir_t * blockchain_find(blockchain_t * chain, const uint256_t * hash);
static const blockchain_heir_t * blockchain_get(blockchain_t * chain, ssize_t height);
static ssize_t blockchain_get_height(blockchain_t * chain, const uint256_t * hash);


/**
 * abandon_child():
 *  export heir's data to a block_info object and return the pointer.
 */
static inline block_info_t * abandon_child(
	blockchain_t * chain,
	const blockchain_heir_t * parent, 
	const blockchain_heir_t * heir)
{
	assert(parent && heir);
	
	block_info_t * orphan = block_info_new(heir->hash, NULL);
	assert(orphan);

	memcpy(&orphan->hdr->prev_hash, parent->hash, sizeof(uint256_t));
	orphan->hdr->bits = heir->bits;
	orphan->hdr->timestamp = (uint32_t)heir->timestamp;
	orphan->cumulative_difficulty = heir->cumulative_difficulty;
	
	tdelete(heir, &chain->search_root, blockchain_heir_compare);
	return orphan;
}

static inline blockchain_heir_t * add_heir(blockchain_t * chain,
	blockchain_heir_t * parent, 
	const block_info_t * child)
{
	assert(parent && child && child);
	assert(0 == memcmp(parent->hash, &child->hdr->prev_hash, sizeof(uint256_t)));
	
	blockchain_resize(chain, (1 + chain->height) + 1);
	blockchain_heir_t * heir = parent + 1;
	
	memcpy(heir->hash, &child->hash, sizeof(uint256_t));
	heir->bits = child->hdr->bits;
	heir->timestamp = child->hdr->timestamp;
	compact_uint256_t difficulty = compact_uint256_complement(*(compact_uint256_t *)&heir->bits);
	heir->cumulative_difficulty = compact_uint256_add(difficulty, parent->cumulative_difficulty);
	
	// verify difficulty
	assert(0 == compact_uint256_compare(
		&heir->cumulative_difficulty, 
		&child->cumulative_difficulty));
		
	tsearch(heir, &chain->search_root, blockchain_heir_compare);
	return heir;
}


static block_info_t * blockchain_abandon_inheritances(blockchain_t * chain, blockchain_heir_t * parent)
{
	ssize_t height = parent - chain->heirs;
	assert(height >= 0 && height <= chain->height);
	
	if(height == chain->height) { // no children that need to be remove
		return NULL;
	}
	
	blockchain_heir_t * last_offspring = &chain->heirs[chain->height];
	struct block_info * orphans = abandon_child(chain, parent, parent + 1);
	
	if(orphans)
	{
		// bring all the orphan's heirs away
		struct block_info * orphan = orphans;
		++parent;	// next child
		while(parent < last_offspring)
		{
			struct block_info * child = abandon_child(chain, parent, parent + 1);
			block_info_add_child(orphan, child);
			
			orphan = child;
			++parent;
		}
	}
	
	// reset current blockchain's height
	chain->height = height;
	return orphans;
}

static struct block_info * blockchain_add_inheritances(blockchain_t * chain, 
	blockchain_heir_t * parent,
	block_info_t * child)
{
	assert(chain && parent && child);
	ssize_t height = parent - chain->heirs;
	
	block_info_t * orphans = blockchain_abandon_inheritances(chain, parent);
	while(child)
	{
		parent = add_heir(chain, parent, child);
		assert(parent);
		
		++height;
		child = child->first_child;
	}
	
	chain->height = height;
	return orphans;
}

blockchain_t * blockchain_init(blockchain_t * chain, 
	const uint256_t * genesis_block_hash, 
	const struct satoshi_block_header * genesis_block_hdr,
	void * user_data)
{
	if(NULL == genesis_block_hash) genesis_block_hash = g_genesis_block_hash;
	if(NULL == genesis_block_hdr) genesis_block_hdr = g_genesis_block_hdr;
	
	if(NULL == chain) chain = calloc(1, sizeof(*chain));
	assert(chain);
	chain->user_data = user_data;
	chain->add = blockchain_add;
	
	chain->find = blockchain_find;
	chain->get = blockchain_get;
	chain->get_height = blockchain_get_height;
	
	int rc = blockchain_resize(chain, 0);
	assert(0 == rc);
	
	memcpy(chain->heirs[0].hash, genesis_block_hash, sizeof(uint256_t));
	
	if(genesis_block_hdr) {
		chain->heirs[0].timestamp = genesis_block_hdr->timestamp;
		chain->heirs[0].bits = genesis_block_hdr->bits;
		chain->heirs[0].cumulative_difficulty = 
			compact_uint256_complement(*(compact_uint256_t *)&genesis_block_hdr->bits);
	}
	
	tsearch(&chain->heirs[0], // add genesis block to the search-tree
		&chain->search_root, 
		blockchain_heir_compare
	);
	
	active_chain_list_init(chain->candidates_list, 0, chain);
	return chain;
}

void blockchain_reset(blockchain_t * chain)
{
	if(NULL == chain || NULL == chain->heirs) return;
	active_chain_list_cleanup(chain->candidates_list);
	
	for(ssize_t i = 0; i < (chain->height + 1); ++i) {
		tdelete(&chain->heirs[i], &chain->search_root, blockchain_heir_compare);
	}
	chain->height = -1;
	return;
}

void blockchain_cleanup(blockchain_t * chain)
{
	if(NULL == chain) return;
	
	active_chain_list_cleanup(chain->candidates_list);
	free(chain->heirs);
	chain->heirs = NULL;
	chain->max_size = 0;
	chain->height = -1;
	return;
}
static const blockchain_heir_t * blockchain_find(blockchain_t * chain, const uint256_t * hash)
{
	void ** p_node = tfind(hash, &chain->search_root, blockchain_heir_compare);
	if(p_node) return *p_node;
	
	return NULL;
}

static block_info_t * active_chain_list_find(active_chain_list_t * list, const uint256_t * hash)
{
	void ** p_node = tfind(hash, &list->search_root, blockchain_heir_compare);
	if(p_node) return *p_node;
	
	return NULL;
}

static inline active_chain_t * get_current_chain(block_info_t * parent)
{
	if(NULL == parent) return NULL;
	
	while(parent->parent) parent = parent->parent;
	return (active_chain_t *)parent;
}


static int abandon_siblings(block_info_t * successor, active_chain_list_t * list);

static void update_first_child_cumulative_difficulty(block_info_t * child, compact_uint256_t cumulative_difficulty)
{
	while(child)
	{
		compact_uint256_t difficulty = compact_uint256_complement(*(compact_uint256_t *)&child->hdr->bits);
		child->cumulative_difficulty = compact_uint256_add(difficulty, cumulative_difficulty);
		child = child->first_child;
	}
	return;
}

static int blockchain_add(blockchain_t * block_chain, 
	const uint256_t * block_hash, 
	const struct satoshi_block_header * hdr)
{
	assert(block_hash && hdr);
	
	unsigned char hash[32];
	hash256(hdr, sizeof(*hdr), hash);
	assert(0 == memcmp(hash, block_hash, sizeof(uint256_t)));
	
	active_chain_list_t * list = block_chain->candidates_list;
	const blockchain_heir_t * heir = NULL;
	block_info_t * orphan = NULL;
	active_chain_t * chain = NULL;
	block_info_t * longest_end = NULL;
	
	// Rule 0. check if it is already on the chain
	heir = block_chain->find(block_chain, block_hash);
	if(heir) return -1;	// already on the BLOCKCHAIN
	
	orphan = active_chain_list_find(list, block_hash);
	if(orphan){
		// check chain's sub-rule
		if(orphan->parent != NULL) return -1;
	
		/**
		 * orphan is the 'head' of an active_chain, 
		 * and the pointer of the 'head' can also represent the chain itself.
		 * claim all the orphans on the chain.
		 */
		block_info_t * head = orphan;
		chain = (active_chain_t *)head;
		
		// First, remove the head->hash from the search-root.
		tdelete(head, &list->search_root, blockchain_heir_compare);
		
		// create a new node
		orphan = block_info_new(block_hash, NULL);
		assert(orphan);
		memcpy(orphan->hdr, hdr, sizeof(*hdr));
		
		// set parent hash to the 'head', and claim the chain
		memcpy(head, hdr->prev_hash, sizeof(uint256_t));
		block_info_t * child = head->first_child;
		while(child) {
			block_info_add_child(orphan, child);
			child = child->next_sibling;
		}
		head->first_child = orphan;
		
		// add the new orphan and 'head->hash' to the search-root
		tsearch(orphan, &list->search_root, blockchain_heir_compare);
		tsearch(head, &list->search_root, blockchain_heir_compare);
	}
	
	if(NULL == chain)
	{
		// create a new node
		assert(NULL == orphan);
		orphan = block_info_new(block_hash, NULL);
		assert(orphan);
		memcpy(orphan->hdr, hdr, sizeof(*hdr));
		
		// Rule I. find parent in the active_chain_list
		block_info_t * parent = active_chain_list_find(list, orphan->hdr->prev_hash);
		if(parent) { // Rule II.
			chain = get_current_chain(parent);
			assert(chain);
			
			block_info_add_child(parent, orphan);
			block_info_update_cumulative_difficulty(orphan, parent->cumulative_difficulty, &longest_end);
			
			// add the new orphan to the search-root
			tsearch(orphan, &list->search_root, blockchain_heir_compare);
			
			// update chain's longest_end
			if(longest_end != chain->longest_end)
			{
				block_info_declare_inheritance(longest_end);
				chain->longest_end = longest_end;
			}
		}else { // Rule III.
			chain = active_chain_new(orphan, &list->search_root);
			assert(chain);
			
			// find the longest-end
			block_info_update_cumulative_difficulty(orphan, 
				compact_uint256_zero,
				&chain->longest_end);
			
			// add chain to the chains-list
			active_chain_list_resize(list, list->count + 1);
			list->chains[list->count++] = chain;
		}
	}
	
	assert(chain);
	
	longest_end = chain->longest_end;
	
	// Rule IV. find parent in the BLOCKCHAIN
	heir = block_chain->find(block_chain, &chain->head->hash);
	if(NULL == heir) return 0;
	
	// update longest_end's cumulative_difficulty 
	update_first_child_cumulative_difficulty(chain->head->first_child, heir->cumulative_difficulty);
	blockchain_heir_t * current = &block_chain->heirs[block_chain->height];
	
	if(compact_uint256_compare(
		&chain->longest_end->cumulative_difficulty, 
		&current->cumulative_difficulty) > 0 ) // win the round. 
	{
		// replace the current one
		block_info_t * orphans = blockchain_abandon_inheritances(block_chain, (blockchain_heir_t *)heir);
		block_info_t * successor = chain->head->first_child;
		
		blockchain_add_inheritances(block_chain, (blockchain_heir_t *)heir, successor);
		
		/**
		 * forget the successor and all his first-child, 
		 * they no longer belong to our group (temporarily).
		 * 
		 * offsprings of the suceesor who does not have the 'first-child' position will be abandoned as orphans,
		 * those orphans shoud establish a new chain of their own.
		 */
		
		// remove all first_child nodes from the search-tree
		block_info_t * child = successor->first_child;
		while(child)	
		{
			tdelete(child, &list->search_root, blockchain_heir_compare);
			child = child->next_sibling;
		} 
		
		
		
		// leave the current chain (swap positions with the orphan or the next_sibling)
		if(orphans) {
			// join the orphan's family to the search-tree
			search_tree_traverse_BFS(&list->search_root, traverse_action_type_add, orphans);
			
			// claim siblings
			orphans->next_sibling = successor->next_sibling;
			chain->head->first_child = orphans;
		}else {
			chain->head->first_child = successor->next_sibling;
		}
		
		// tell the first-child discard his siblings. 
		abandon_siblings(successor->first_child, list);
		
		// destroy old identities
		tdelete(successor, &list->search_root, blockchain_heir_compare);
		block_info_free(successor);
		
		if(NULL == chain->head->first_child) { // all children have left home
			list->remove(list, chain);	
		}
	}

	return 0;
}

static int abandon_siblings(block_info_t * successor, active_chain_list_t * list)
{
	if(NULL == successor) return 0;
	
	// discard his siblings
	block_info_t * sibling = successor->next_sibling;
	
	/**
	 * his next_sibling will lead all other brothers to a new chain.
	 * do not set new chain's search-root pointer when creating,
	 * all nodes are already in the search-tree,
	 * just add the new chain's 'head' only.
	 */
	if(sibling)
	{
		active_chain_t * chain = active_chain_new(sibling, NULL);
		assert(chain);
		tsearch(chain->head, &list->search_root, blockchain_heir_compare); 
		
		chain->p_search_root = &list->search_root;
		list->add(list, chain);
	}
	
	// no more brothers
	successor->next_sibling = NULL;
	
	// tell his first-child to do the same thing
	return abandon_siblings(successor->first_child, list);	// tail-recursion, no need to optimize
}


static const blockchain_heir_t * blockchain_get(blockchain_t * chain, ssize_t height)
{
	return NULL;
}

static ssize_t blockchain_get_height(blockchain_t * chain, const uint256_t * hash)
{
	return -1;
}



/***********************************************************************
 * struct block_info
 **********************************************************************/
block_info_t * block_info_new(const uint256_t * hash, struct satoshi_block_header * hdr)
{
	block_info_t * info = calloc(1, sizeof(*info));
	assert(info);
	
	if(hash) memcpy(&info->hash, hash, sizeof(*hash));
	
	if(NULL == hdr) {
		hdr = calloc(1, sizeof(*hdr));
		info->hdr_free = free;
	}
	assert(hdr);
	
	info->hdr = hdr;
	info->height = -1;
	return info;
}

void block_info_free(block_info_t * info)
{
	if(NULL == info) return;
	
	if(info->next_sibling) {
		block_info_free(info->next_sibling);
		info->next_sibling = NULL;
	}
	
	if(info->first_child) {
		block_info_free(info->first_child);
		info->first_child = NULL;
	}
	
	if(info->hdr_free) {
		info->hdr_free(info->hdr);
	}
	
#ifdef _DEBUG
	printf("==> free %p, id=%d\n", info, info->id);
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

#define CLIB_QUEUE_ALLOC_SIZE (4096)
struct clib_queue
{
	void ** nodes;
	ssize_t max_size;
	ssize_t start_pos;
	ssize_t length;
	
	int (* resize)(struct clib_queue * queue, ssize_t new_size);
	int (* enter)(struct clib_queue * queue, void * node);
	void * (* leave)(struct clib_queue * queue);
	
	// cleanup callbacks
	void * (* free_node)(void * node);
};

static int queue_resize(struct clib_queue * queue, ssize_t new_size)
{
	if(new_size <= 0) new_size = CLIB_QUEUE_ALLOC_SIZE;
	else new_size = (new_size + CLIB_QUEUE_ALLOC_SIZE - 1) / CLIB_QUEUE_ALLOC_SIZE * CLIB_QUEUE_ALLOC_SIZE;
	
	if(new_size <= queue->max_size) return 0;
	
	void ** nodes = realloc(queue->nodes, new_size * sizeof(*nodes));
	assert(nodes);
	
	memset(nodes + queue->max_size, 0, (new_size - queue->max_size) * sizeof(*nodes));
	queue->nodes = nodes;
	queue->max_size = new_size;
	return 0;
}
static int queue_enter(struct clib_queue * queue, void * node)
{
	int rc = queue->resize(queue, queue->length + 1);
	if(rc) return rc;
	
	int cur_pos = queue->start_pos + queue->length;
	cur_pos %= queue->max_size;
	
	queue->nodes[cur_pos] = node;
	++queue->length;
	return 0;
}

static void * queue_leave(struct clib_queue * queue)
{
	if(queue->length <= 0) return NULL;
	void * node = queue->nodes[queue->start_pos++];
	
	queue->start_pos %= queue->max_size;
	--queue->length;
	
	return node;
}

struct clib_queue * clib_queue_init(struct clib_queue * queue, ssize_t size)
{
	if(NULL == queue) queue = calloc(1, sizeof(*queue));
	assert(queue);
	
	queue->resize = queue_resize;
	queue->enter = queue_enter;
	queue->leave = queue_leave;
	
	int rc = queue->resize(queue, size);
	assert(0 == rc);
	
	return queue;
}

void clib_queue_cleanup(struct clib_queue * queue)
{
	if(queue->nodes && queue->free_node)
	{
		for(ssize_t i = 0; i < queue->length; ++i) {
			ssize_t index = (queue->start_pos + i) % queue->max_size;
			queue->free_node(queue->nodes[index]);
		}
	}
	free(queue->nodes);
	queue->nodes = NULL;
	queue->free_node = NULL;
	return;
}

int block_info_update_cumulative_difficulty(
	block_info_t * node, // current node
	compact_uint256_t cumulative_difficulty,	// parent's cumulative_difficulty
	block_info_t ** p_longest_offspring			// the child who currently at the end of the longest-chain  
)
{
	if(NULL == node) return -1;
	
	// update current node's cumulative_difficulty
	compact_uint256_t difficulty = compact_uint256_complement(*(compact_uint256_t *)&node->hdr->bits);
	node->cumulative_difficulty = compact_uint256_add(difficulty, cumulative_difficulty);
	
	if(p_longest_offspring)	// if need to declare the winner at the same time 
	{
		block_info_t * heir = *p_longest_offspring;
		if(NULL == heir 
			|| compact_uint256_compare(
					&node->cumulative_difficulty, 
					&heir->cumulative_difficulty) > 0
			)
		{
			*p_longest_offspring = node;
		}
	} 
	
	// update first-child
	block_info_update_cumulative_difficulty(node->first_child, node->cumulative_difficulty, p_longest_offspring);
	
	// update all siblings's cumulative_difficulty
	block_info_t * sibling = node->next_sibling;
	while(sibling)
	{
		block_info_update_cumulative_difficulty(sibling, cumulative_difficulty, p_longest_offspring);
		sibling = sibling->next_sibling;
	}
	return 0;
}

int block_info_declare_inheritance(block_info_t * heir)
{
	if(NULL == heir || NULL == heir->parent) return 0;
	block_info_t * parent = heir->parent;
		
	block_info_t * first_child = parent->first_child;
	if(first_child != heir)
	{
		block_info_t * prev = first_child;
		while(prev && prev->next_sibling != heir) prev = prev->next_sibling;
		assert(prev);
		
		
		// jump to first place
		prev->next_sibling = heir->next_sibling;
		heir->next_sibling = first_child;
		parent->first_child = heir;
	}
	
	
	return block_info_declare_inheritance(parent);	// Tail recursion.
}


active_chain_t * active_chain_new(block_info_t * orphan, void ** p_search_root)
{
	assert(orphan && orphan->hdr);
	assert(p_search_root);
	
	active_chain_t * chain = calloc(1, sizeof(*chain));
	assert(chain);
	chain->p_search_root = p_search_root;

	block_info_t * head = chain->head;

	memcpy(&head->hash, &orphan->hdr->prev_hash, sizeof(uint256_t));	// save parent hash
	head->first_child = orphan;
	orphan->parent = head;

	// find the longest-end
	block_info_t * longest_end = orphan;
	while(longest_end->first_child) longest_end	= longest_end->first_child;
	chain->longest_end = longest_end;
	
	// add the new orphan and 'head->hash' to the search-root
	if(p_search_root)
	{
		tsearch(orphan, p_search_root, blockchain_heir_compare);
		tsearch(head, p_search_root, blockchain_heir_compare);
	}
	
	return chain;
}

static void active_chain_remove_child(block_info_t * parent, void ** p_search_root)
{
	if(NULL == parent) return;
	
	block_info_t * child = parent->first_child;
	while(child)
	{
		active_chain_remove_child(child, p_search_root);
		tdelete(child, p_search_root, blockchain_heir_compare);
		
		child = child->next_sibling;
	}
	return;
}

void active_chain_free(active_chain_t * chain)
{
	if(NULL == chain) return;
	
	// remove all children from the tsearch-tree first. 
	active_chain_remove_child(chain->head, chain->p_search_root);
	
	// free all nodes except the 'head'
	block_info_t * child = chain->head->first_child;
	while(child)
	{
		block_info_free(child);
		child = child->next_sibling;
	}
	free(chain);
}

/*****************************************************************
 * struct active_chain_list
 * 
 ****************************************************************/
static int active_chain_list_resize(active_chain_list_t * list, ssize_t max_size);

// use a queue to remove recursion. (breadth first)
typedef void * (*traverse_action_callback)(const void *, void **, int (*)(const void *, const void *));

static int search_tree_traverse_BFS(void ** p_search_root, enum traverse_action_type type, block_info_t * node)
{
	static traverse_action_callback actions[traverse_action_types_count] = {
		[traverse_action_type_add] = tsearch,
		[traverse_action_type_remove] = tdelete,
	};
	
	assert(type >= 0 && type < traverse_action_types_count);
	traverse_action_callback action = actions[type];
	
	struct clib_queue queue[1];
	memset(queue, 0, sizeof(queue));
	clib_queue_init(queue, 100);
	
	int rc = queue->enter(queue, node);
	assert(0 == rc);
	
	while((node = queue->leave(queue)))
	{
		// add or remove node from the search-tree
		action(node, p_search_root, blockchain_heir_compare);
		
		// enqueue all siblings
		block_info_t * sibling = node->next_sibling;
		while(sibling) {
			rc = queue->enter(queue, sibling);
			assert(0 == rc);
			sibling = sibling->next_sibling;
		}
		
		// enqueue child
		rc = queue->enter(queue, node->first_child);
		assert(0 == rc);
	}
	
	assert(queue->length == 0);
	clib_queue_cleanup(queue);
	return 0;
}

static int list_add(active_chain_list_t * list, active_chain_t * chain)
{
	assert( (NULL == chain->p_search_root) || (chain->p_search_root == &list->search_root) );
	
	int rc = active_chain_list_resize(list, list->count + 1);
	assert(0 == rc);

	list->chains[list->count++] = chain;
	
	if(NULL == chain->p_search_root)
	{
		chain->p_search_root = &list->search_root;
		search_tree_traverse_BFS(&list->search_root, traverse_action_type_add, chain->head);
	}
	return 0;
}

static int list_remove(active_chain_list_t * list, active_chain_t * chain)
{
	assert(chain);
	ssize_t i = 0;
	for(i = 0; i < list->count; ++i)
	{
		if(list->chains[i] == chain) {
			list->chains[i] = list->chains[--list->count];
			list->chains[list->count] = NULL;
			break;
		}
	}
	if(i == list->count) return -1;
	
	search_tree_traverse_BFS(&list->search_root, traverse_action_type_remove, chain->head);
	return 0;
}
 
 
#define ACTIVE_CHAIN_LIST_ALLOC_SIZE (1024)
static int active_chain_list_resize(active_chain_list_t * list, ssize_t max_size)
{
	assert(list);
	if(max_size <= 0) max_size = ACTIVE_CHAIN_LIST_ALLOC_SIZE;
	else max_size = (max_size + ACTIVE_CHAIN_LIST_ALLOC_SIZE - 1) / ACTIVE_CHAIN_LIST_ALLOC_SIZE * ACTIVE_CHAIN_LIST_ALLOC_SIZE;
	if(max_size <= list->max_size) return 0;
	
	active_chain_t ** chains = realloc(list->chains, max_size * sizeof(*chains));
	assert(chains);
	
	memset(chains + list->max_size, 0, (max_size - list->max_size) * sizeof(*chains));
	list->max_size = max_size;
	list->chains = chains;
	
	return 0;
}

active_chain_list_t * active_chain_list_init(active_chain_list_t * list, ssize_t max_size, void * user_data)
{
	if(NULL == list) list = calloc(1, sizeof(*list));
	assert(list);
	list->user_data = user_data;
	
	list->add = list_add;
	list->remove = list_remove;
	
	int rc = active_chain_list_resize(list, max_size);
	assert(0 == rc);
	
	return list;
}

void active_chain_list_reset(active_chain_list_t * list)
{
	if(list->chains)
	{
		for(int i = 0; i < list->count; ++i)
		{
			active_chain_free(list->chains[i]);
			list->chains[i] = NULL;
		}
	}
	list->count = 0;
	return;
}


void active_chain_list_cleanup(active_chain_list_t * list)
{
	active_chain_list_reset(list);
	
	free(list->chains);
	list->chains = NULL;
	list->max_size = 0;
	return;
}


/**
 * Difficulty is a measure of how difficult it is to find a hash below a given target.
 * Each block stores a packed representation (called 'Bits') for its actual target(uint256). 
 * The Bitcoin network uses the following formula to define difficulty:
 * 
 * difficulty_1_target: (compact_int)0x1d00FFFF
 *                      (uint256)0x00000000 FFFF0000 00000000 00000000 00000000 00000000 00000000 00000000
 * current_target:      (compact_int)block_hdr.bits
 *                      (uint256) (convert block_hdr.bits to uint256)
 * 
 * difficulty = difficulty_1_target / current_target
 * 
 * 
 * In order to avoid a large number of floating-point division operations, 
 * we try to use another way (using compact_int) to represent the difficulty, 
 * and made the following definition:
 * 
 * compact_int:        compact_uint256
 * cint_max:    { .bits = 0x20FFFFFF,  .exp = 32, .mantissa = {0xff, 0xff, 0xff} }
 * current_target:      block_hdr.bits
 * 
 * difficulty_cint = compact_int_max - (compact_int)target
 * 
 * To improve precision, we try to keep as many valid bits as possible in mantissa,
 * we define difficulty_cint.mantissa as an unsigned integer,
 * so the highest bit is allowed to be '1'.
 * 
 * DO NOT use 'compact_uint256_compare()' function to 
 * compare (unsigned type)'difficulty' and (signed type)'target' directly,
 * this should not happen within the system, 
 * there are no relevant implementations, the result is undefined.
 * 
 * The 'addition' and 'complement(~, 1's complement)' operation of compact_uint256 are defined as below:
 */
compact_uint256_t compact_uint256_add(const compact_uint256_t a, const compact_uint256_t b)
{
	compact_uint256_t c;	// c = a + b
	
	int val_a = a.bits & 0x0FFFFFF;
	int val_b = b.bits & 0x0FFFFFF;
	
	// make a and b same exponent
	int exp_diff = (int)a.exp - (int)b.exp; 
	int exp = a.exp;
	if(exp_diff > 0) {
		val_b >>= exp_diff * 8;	// bytes to bits
	}else if(exp_diff < 0) {
		exp = b.exp;
		val_a >>= (-exp_diff) * 8;
	}
	
	/*
	 * Since A and B can only have 24 valid bits at most, and C has 32 bits, 
	 * it is safe to assign A+B directly to C.
	 */
	c.bits = val_a + val_b;
	
	// make sure c's mantissa is equal or less than 24 bits
	if(c.bits & 0xFF000000) { c.bits >>= 8; exp++; }
	
	c.exp = exp;
	return c;
} 

compact_uint256_t compact_uint256_complement(const compact_uint256_t target)
{
	// cint_max:    { .bits = 0x20FFFFFF,  .exp = 32, .mantissa = {0xff, 0xff, 0xff} }
	compact_uint256_t c;	// c = ~target;
	uint32_t mantissa = target.bits & 0x0FFFFFF;
	c.bits = ~mantissa;
	c.exp = (unsigned char)32 - target.exp; //  target.exp should less than 32 <== sizeof(uint256).
	
	return c;
}

#if defined(_TEST_CHAINS) && defined(_STAND_ALONE)
void test_compact_int_arithmetic_operations(void)
{
	compact_uint256_t a = {.bits = 0x1d00ffff};
	compact_uint256_t b = {.bits = 0x1cffff00};
	
	int rc = compact_uint256_compare(&a, &b);
	assert(0 == rc);
	
	compact_uint256_t target = { .bits = 0x1b0404cb };
	
	compact_uint256_t difficulty = compact_uint256_complement(target);
	
	compact_uint256_t difficulty_accum = compact_uint256_add(difficulty, difficulty);
	
	printf("difficulty: 0x%.8x\n"
		"\texp = 0x%.2x, mantissa = 0x%.8x\n",
		difficulty.bits,
		difficulty.exp,
		difficulty.bits & 0x0FFFFFF
		);
		
	printf("difficulty: 0x%.8x\n"
		"\texp = 0x%.2x, mantissa = 0x%.8x\n",
		difficulty_accum.bits,
		difficulty_accum.exp,
		difficulty_accum.bits & 0x0FFFFFF
		);
	return ;
}

int main(int argc, char **argv)
{
	test_compact_int_arithmetic_operations();
	exit(0);
	
	const char * block_file = "blocks/blk00000.dat";
	uint32_t magic = 0;
	uint32_t length = 0;
	
	FILE * fp = fopen(block_file, "rb");
	assert(fp);
	
	static unsigned char buffer[1024 * 1024];
	int height = 0;
	while(1)
	{
		ssize_t cb = 0;
		cb = fread(&magic, sizeof(uint32_t), 1, fp); 
		if(cb <= 0) break;
		assert(cb == 1 && magic == 0xD9B4BEF9);
		
		cb = fread(&length, sizeof(uint32_t), 1, fp); 
		if(cb <= 0) break;
	
		cb = fread(buffer, 1, length, fp);
		if(cb != length) break;
		
		satoshi_block_t block[1];
		memset(block, 0, sizeof(block));
		cb = satoshi_block_parse(block, length, buffer);
		assert(cb == length);
		
		// todo: blockchain_add();
		
		satoshi_block_cleanup(block);
		++height;
	}
	printf("height: %d\n", height);
	fclose(fp);
	return 0;
}
#endif
