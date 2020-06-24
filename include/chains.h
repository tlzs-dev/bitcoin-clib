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
	int hdr_flags;	// 0: created by calloc, need free;  1: attached block_header_ptr; 2: attached satoshi_block ptr. 
	
	int height;		// the index in the blockchain, -1 means not attached to any chains
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


compact_uint256_t compact_uint256_add(const compact_uint256_t a, const compact_uint256_t b);
compact_uint256_t compact_uint256_complement(const compact_uint256_t target);

#ifdef __cplusplus
}
#endif
#endif
