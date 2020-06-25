#ifndef _CHAINS_
#define _CHAINS_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include "satoshi-types.h"

struct block_info;
struct active_chain;

typedef struct blockchain_heir
{
	uint256_t hash[1];
	uint64_t timestamp;	// add support for BIP0113 (Median time-past as endpoint for lock-time calculations)
	
	uint32_t bits;		// current target
	compact_uint256_t cumulative_difficulty;
}blockchain_heir_t;

typedef struct blockchain
{
	blockchain_heir_t * heirs;
	ssize_t max_size;
	ssize_t height;
	
	void * search_root;
	void * user_data;
}blockchain_t;

typedef struct block_info
{
	uint256_t hash;
	/**
	 * hdr: 
	 *   nullable, 
	 *   can be attached to a (struct satoshi_block_header *) or a (struct satoshi_block *)
	 */
	struct satoshi_block_header * hdr;
	void (* hdr_free)(void *);	// set to NULL if no need to free
	
	int height;		// the index in the blockchain, -1 means not attached to any chains
//	double cumulative_difficulty;

	compact_uint256_t cumulative_difficulty;	// use compact_uint256 to represent cumulative difficulty.
	
	struct block_info * parent;	// there can be only one parent for each block
	struct block_info * first_child;	// the first child will belong to the longest-chain
	
	/*
	 * All siblings would be abondanded and regarded as orphans, 
	 * but if they can reproduce enough offsprings (longer than the current heir in the chain ) , 
	 * they can regain their family status and become the first-child.
	 */
	struct block_info * next_sibling;
	
#ifdef _DEBUG
	int id;
#endif
}block_info_t;
block_info_t * block_info_new(const uint256_t * hash, struct satoshi_block_header * hdr);
int block_info_add_child(block_info_t * parent, block_info_t * child);
void block_info_free(block_info_t * info);


 
typedef struct active_chain
{
	/**
	 * Set head to array type and place it in the first field, 
	 * when backtracking from end to the head, 
	 * this pointer can also represent the active_chain struct,
	 * makes it easy to get chain->parent and other fields.
	 */
	struct block_info head[1];
	
	struct blockchain_heir * parent;	// the node belongs to the verified blockchain, can be null if it is not currently known
	// The fields below are for internal use only,
	// used to quickly find the longest-chain within current branch
	struct block_info * longest_end;
}active_chain_t;
active_chain_t * active_chain_new(block_info_t * orphan);
void active_chain_free(active_chain_t * chain);

typedef struct active_chain_list
{
	ssize_t max_size;
	ssize_t count;
	active_chain_t ** chains;
	
	void * search_root;	// tsearch root, used to find if a block is already in the list.
	void * user_data;
}active_chain_list_t;
active_chain_list_t * active_chain_list_init(active_chain_list_t * list, ssize_t max_size, void * user_data);


/**
 * define the 'addition' and 'complement(~, 1's complement)' operation of compact_uint256 as below:
 * 
 * compact_uint256_t a , b;
 *  - compact_uint256_add(a, b):  c = (a + b)
 *      make the exponent of a and b same ==> exp;
 *      c.mantissa = (a.mantissa + b.mantissa); 
 *      c.exp = exp;
 * 
 * - compact_uint256_complement(a): c = ~a
 * 	    c.mantissa = ~a.mantissa;
 *      c.exp = 32 - a.exp;
 */ 
compact_uint256_t compact_uint256_add(const compact_uint256_t a, const compact_uint256_t b);
compact_uint256_t compact_uint256_complement(const compact_uint256_t target);

#ifdef __cplusplus
}
#endif
#endif
