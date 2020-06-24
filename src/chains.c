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

#define MAX_FUTURE_BLOCK_TIME	(2 * 60 * 60)
static const uint256_t g_genesis_block_hash = {
	.val = {
		0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
		0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 
		0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 
		0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00
	}
};

#define BLOCK_HASHES_PRE_ALLOC_SIZE (6 * 24 * 365 * 100)	// (6 blocks per hour) * 24hours * 365days * 100years

/*
 * use an array to keep all verified blocks
 *  g_blocks_hashes[height] = the hash of block@heigth;
 * 
 * 	if any hash_ptr(pointer) has been obtained by searching, the 'height' can be calculate by the following method:
 *   height = hash_ptr - g_blocks_hashes;
 */
static uint256_t g_blocks_hashes[BLOCK_HASHES_PRE_ALLOC_SIZE];	
static void * g_blocks_hashes_root;	// tsearch root

/**
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
 * so, o we need to find a relatively good algorithm to solve this problem
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
 * - Rule II. If parents can be found in one of the chains, the join the chain and do the following steps:
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
 
typedef struct active_chain
{
	/**
	 * Set head to array type and place it in the first field, 
	 * when backtracking from end to the head, 
	 * this pointer can also represent the active_chain struct,
	 * makes it easy to get chain->parent and other fields.
	 */
	struct block_info head[1];
	
	struct block_info * parent;	// the node belongs to the verified blockchain, can be null if it is not currently known
	// The fields below are for internal use only,
	// used to quickly find the longest-chain within current branch
	struct block_info * longest_end;
}active_chain_t;

active_chain_t * active_chain_new(block_info_t * orphan)
{
	assert(orphan);
	
	active_chain_t * chain = calloc(1, sizeof(*chain));
	assert(chain);
	
	block_info_t * head = chain->head;
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

typedef struct active_chain_list
{
	ssize_t max_size;
	ssize_t count;
	active_chain_t ** chains;
	
	void * search_root;	// tsearch root, used to find if a block is already in the list.
	void * user_data;
}active_chain_list_t;

#define ACTIVE_CHAIN_LIST_ALLOC_SIZE (1024)
int active_chain_list_resize(active_chain_list_t * list, ssize_t max_size)
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
 * and made the following defination:
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
	if(exp_diff > 0)
	{
		val_b >>= exp_diff * 8;	// bytes to bits
	}else if(exp_diff < 0)
	{
		exp = b.exp;
		val_a >>= (-exp_diff) * 8;
	}
	
	/*
	 * Since A and B can only have 24 valid bits at most, and C has 32 bits, 
	 * it is safe to assign A+B directly to C.
	 */
	c.bits = val_a + val_b;
	
	// make sure c's mantissa is equal or less than 24 bits
	if(c.bits & 0xFF000000) {
		c.bits >>= 8;
		exp++;
	}
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
