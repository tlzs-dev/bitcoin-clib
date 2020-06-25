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

#include "satoshi-types.h"
#include <search.h>

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


#define MAX_FUTURE_BLOCK_TIME	(2 * 60 * 60)
static const uint256_t g_genesis_block_hash = {
	.val = {
		0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
		0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 
		0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 
		0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00
	}
};

#define BLOCKCHAIN_DEFAULT_ALLOC_SIZE (6 * 24 * 365 * 100)	// (6 blocks per hour) * 24hours * 365days * 100years

/***********************************************************************
 * blockchain
 **********************************************************************/
typedef int (* blockchain_heir_compare_func)(const void *, const void *);
static blockchain_heir_compare_func blockchain_heir_compare = (blockchain_heir_compare_func)uint256_compare; 

int blockchain_resize(blockchain_t * chain, ssize_t size)
{
	if(size <= 0) size = (size + BLOCKCHAIN_DEFAULT_ALLOC_SIZE - 1) / BLOCKCHAIN_DEFAULT_ALLOC_SIZE * BLOCKCHAIN_DEFAULT_ALLOC_SIZE;
	if(size <= chain->max_size) return 0;
	
	blockchain_heir_t * heirs = realloc(chain->heirs, size * sizeof(*heirs));
	assert(heirs);
	
	memset(heirs, 0, (size - chain->max_size) * sizeof(*heirs));
	chain->heirs = heirs;
	chain->max_size = size;
	return 0;
}



struct active_chain * blockchain_remove_inheritance_after(blockchain_t * chain, int height)
{
	assert(height > 0);
	
	if(height >= chain->height) { // no children that need to be remove
		return NULL;
	}
	
	blockchain_heir_t * parent = &chain->heirs[height];
	blockchain_heir_t * child = parent + 1;	// first child
	blockchain_heir_t * last_offspring = &chain->heirs[chain->height];
	
	// orphan the current child
	tdelete(child, &chain->search_root, blockchain_heir_compare);
	struct block_info * orphan = block_info_new(child->hash, NULL);
	assert(orphan);
	
	// set parent-hash (prev_hash) of the child
	memcpy(&orphan->hdr->prev_hash, parent->hash, sizeof(uint256_t));
	orphan->hdr->bits = child->bits;
	
	orphan->cumulative_difficulty = child->cumulative_difficulty;
	
	active_chain_t * orphans_chain = active_chain_new(orphan);	// create a new orphan chain
	assert(orphans_chain);
	
	// bring all the orphan's heirs away
	while(last_offspring != child)
	{
		++child;	// child of the child
		
		tdelete(child, &chain->search_root, blockchain_heir_compare);
		struct block_info * next = block_info_new(child->hash, NULL);
		block_info_add_child(orphan, next);
		
		orphan = next;
	}
	
	// reset current blockchain's height
	chain->height = height;
	
	return orphans_chain;
}

struct active_chain * blockchain_append_active_chain(blockchain_t * chain, struct active_chain * new_chain)
{
	assert(chain && new_chain);
	
	blockchain_heir_t * parent = tfind(&new_chain->head->hash, 
		&chain->search_root, 
		blockchain_heir_compare);
	if(NULL == parent) return new_chain;	// unable to append, return the chain itself
	
	blockchain_heir_t * heirs = chain->heirs;
	ssize_t height = parent - heirs;	// calc block height
	
	struct active_chain * orphans_chain = blockchain_remove_inheritance_after(chain, height);
	assert(orphans_chain != new_chain);
	
	block_info_t * first_child = new_chain->head->first_child;
	
	while(first_child)
	{
		blockchain_heir_t * heir = &heirs[++height];	// first child of the parent
		
		assert(first_child->hdr);
		compact_uint256_t difficulty = compact_uint256_complement(*(compact_uint256_t *)&first_child->hdr->bits);
		heir->cumulative_difficulty = compact_uint256_add(parent->cumulative_difficulty, difficulty);
		
		memcpy(&heir->hash, &first_child->hash, sizeof(uint256_t));
		heir->timestamp = first_child->hdr->timestamp;
		
		// verify cumulative_difficulty
		assert(0 == compact_uint256_compare(
				&heir->cumulative_difficulty,
				&first_child->cumulative_difficulty)
		);
		
		first_child = first_child->first_child;
	}
	chain->height = height;
	return orphans_chain;
}

blockchain_t * blockchain_init(blockchain_t * chain, 
	const uint256_t * genesis_block_hash, 
	const struct satoshi_block_header * genesis_block_hdr,
	void * user_data)
{
	assert(genesis_block_hash);
	
	if(NULL == chain) chain = calloc(1, sizeof(*chain));
	assert(chain);
	chain->user_data = user_data;
	
	int rc = blockchain_resize(chain, 0);
	assert(0 == rc);
	
	if(genesis_block_hdr) {
		chain->heirs[0].timestamp = genesis_block_hdr->timestamp;
		chain->heirs[0].cumulative_difficulty = *(compact_uint256_t *)&genesis_block_hdr->bits;
	}
	
	tsearch(&chain->heirs[0], // add genesis block to the search-tree
		&chain->search_root, 
		blockchain_heir_compare
	);
	return chain;
}

void blockchain_reset(blockchain_t * chain)
{
	if(NULL == chain || NULL == chain->heirs) return;
	for(ssize_t i = 0; i < (chain->height + 1); ++i) {
		tdelete(&chain->heirs[i], &chain->search_root, blockchain_heir_compare);
	}
	chain->height = 0;
}

void blockchain_cleanup(blockchain_t * chain) 
{
	if(NULL == chain) return;
	blockchain_reset(chain);
	
	free(chain->heirs);
	chain->heirs = NULL;
	chain->max_size = 0;
	return;
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
			queue->free_node(queue->nodes[i]);
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

active_chain_t * active_chain_new(block_info_t * orphan)
{
	assert(orphan && orphan->hdr);
	
	active_chain_t * chain = calloc(1, sizeof(*chain));
	assert(chain);
	
	block_info_t * head = chain->head;

	memcpy(&head->hash, &orphan->hdr->prev_hash, sizeof(uint256_t));	// save parent hash
	head->first_child = orphan;

	// find the longest-end
	block_info_t * longest_end = orphan;
	while(longest_end->first_child) longest_end	= longest_end->first_child;
	chain->longest_end = longest_end;
	
	return chain;
}

void active_chain_free(active_chain_t * chain)
{
	if(NULL == chain) return;
	
	// the head should never have siblings, 
	// only head->first_child need free
	///< @todo notify chains-list to remove nodes from the tsearch-tree. 
	block_info_free(chain->head->first_child);
	free(chain);
}

#define ACTIVE_CHAIN_LIST_ALLOC_SIZE (1024)
static int active_chain_list_resize(active_chain_list_t * list, ssize_t max_size)
{
	assert(list);
	if(max_size <= 0) max_size = (max_size + ACTIVE_CHAIN_LIST_ALLOC_SIZE - 1) / ACTIVE_CHAIN_LIST_ALLOC_SIZE * ACTIVE_CHAIN_LIST_ALLOC_SIZE;
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


static inline active_chain_t * get_current_chain(block_info_t * parent)
{
	if(NULL == parent) return NULL;
	
	while(parent->parent) parent = parent->parent;
	return (active_chain_t *)parent;
}

active_chain_t * active_chain_list_add_orphan(active_chain_list_t * list, block_info_t * orphan)
{
	// rule 0. confirm the orphan is not a duplicate.
	block_info_t ** p_node = tsearch(orphan, 
		&list->search_root, 
		(int (*)(const void *, const void *))uint256_compare // the first field of block_info struct is an uint256 hash.
	);
	assert(p_node);
	if(*p_node != orphan) { // duplicated
		return NULL;
	}
	
	active_chain_t * chain = NULL;
	
	// rule 1. find parent
	assert(orphan->hdr);
	p_node = tfind(&orphan->hdr->prev_hash,		// parent hash
		&list->search_root,
		(int (*)(const void *, const void *))uint256_compare
	);
	
	if(p_node && *p_node) // parent was found
	{
		block_info_t * parent = *p_node;
		chain = get_current_chain(parent);
		
		// rule 2. 
		///< @todo
		//... 
		
	}else {
		// rule 3
		chain = active_chain_new(orphan);
		
		///< @todo
		// ...
	}

	assert(chain);
	
	// rule 4
	if(chain->parent) // has parent in the BLOCKCHAIN
	{
		///< @todo
		//...
	}
	
	return chain;  
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
