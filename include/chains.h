#ifndef _CHAINS_
#define _CHAINS_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include "satoshi-types.h"

struct block_info;

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
 * - Rule III. Any orphans who do not know their parents should create a new chain.
 * 	 @deprecated [ then find out whether there are children in the chains-list. Since any orphans can only have one unique parent,
 *   the child (or children) must be the head of his (or their) chain. Claim this(these) chain(s) and
 *   make them be their children. ]
 *   
 * 
 * - Rule IV.  If a chain known his parent in the BLOCKCHAIN and his longest-offspring is supper than the current,
 *   replace the current one, and bring all the first-child on his chain back to the royal family.
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

typedef struct active_chain
{
	/**
	 * Set head to array type and place it in the first field, 
	 * when backtracking from end to the head, 
	 * this pointer can also represent the active_chain struct,
	 * makes it easy to get chain->longest_end and other fields.
	 * 
	 * In order to simplify the implementation, we defined the following sub-rules:
	 * 
		- Define 'head' as the currently unknown parent that orphan-nodes of the chain are looking for;
		- The 'head->hash' will also need to be added to the chains-list's search-root.
		- Except for the 'head', any nodes on the chain must have a non-null parent pointer,
		  This also means that if the parent of a node is NULL, the node must be the 'head'
		
		- When a new-orphan(A) is looking for himself according to the Rule-0,
		  and gets a node whose parent is NULL, then the node is not A himself, 
		  but A is the parent whom the chain is looking for, and A should claim the children on the chain.
		
		- After claiming the children, continue to execute Rule-I.
	 */
	struct block_info head[1];
	
	// The fields below are for internal use only,
	struct block_info * longest_end; // used to quickly find the longest-chain within current branch
	
	/**
	 * A pointer to the search-root of chains-list, 
	 * used to update the search-tree when adding or deleting a child-node.
	 */
	void ** p_search_root;
	
	// add child to 'head'
	int (* add_child)(struct active_chain * chain, struct block_info * child);
	
}active_chain_t;
active_chain_t * active_chain_new(block_info_t * orphan, void ** p_search_root);
void active_chain_free(active_chain_t * chain);

typedef struct active_chain_list
{
	ssize_t max_size;
	ssize_t count;
	active_chain_t ** chains;
	
	void * search_root;	// tsearch root, used to find if a block is already in the list.
	void * user_data;
	
	block_info_t * (* find_node)(struct active_chain_list * list, const uint256_t * hash, active_chain_t ** p_chain);
	
	// add or remove the node from the 'search-tree' 
	int (* search_tree_add)(struct active_chain_list * list, block_info_t * node); 
	int (* search_tree_remove)(struct active_chain_list * list, block_info_t * node); 
	
	int (* add)(struct active_chain_list * list, struct active_chain * chain);
	int (* remove)(struct active_chain_list * list, struct active_chain * chain);
	
}active_chain_list_t;
active_chain_list_t * active_chain_list_init(active_chain_list_t * list, ssize_t max_size, void * user_data);
void active_chain_list_cleanup(active_chain_list_t * list);

/**
 * struct blockchain_heir
 * @details
 * 
 * Individuals on the verified chain, since it need to be stored in memory.
 * the size of the struct needs to be limited as small as possible.
 * 
 * Unlike 'satoshi_block_header', this structure cannot prove the genuineness of itself by itself.
 * so do not add it directly to the BLOCKCHAIN, only appending block_header is allowed.
 */
typedef struct blockchain_heir
{
	uint256_t hash[1];
	uint64_t timestamp;	// add support for BIP0113 (Median time-past as endpoint for lock-time calculations)
	
	uint32_t bits;		// current target
	compact_uint256_t cumulative_difficulty;
}blockchain_heir_t;


/**
 * struct blockchain
 * @details:
 * 	heirs: currently the longest-chain with the largest cumulative difficulty.
 *  candidates_list:  chains that containing valid blocks but not the longest one.
 */ 
typedef struct blockchain
{
	blockchain_heir_t * heirs;
	ssize_t max_size;
	ssize_t height;
	
	void * search_root;
	void * user_data;
	struct active_chain_list candidates_list[1];
	
	// public functions
	const blockchain_heir_t * (*find)(struct blockchain * chain, const uint256_t * hash);
	ssize_t (* get_height)(struct blockchain * chain, const uint256_t * hash);
	const blockchain_heir_t * (* get)(struct blockchain * chain, ssize_t height);
	
	/**
	 * add(): only increments are allowed, any reorganization must be done by internal.
	 */
	int (* add)(struct blockchain * chain, const uint256_t * hash, const struct satoshi_block_header * hdr);
}blockchain_t;

blockchain_t * blockchain_init(blockchain_t * chain, 
	const uint256_t * genesis_block_hash, 
	const struct satoshi_block_header * genesis_block_hdr, 
	void * user_data);
void blockchain_cleanup(blockchain_t * chain);


block_info_t * block_info_new(const uint256_t * hash, struct satoshi_block_header * hdr);
int block_info_add_child(block_info_t * parent, block_info_t * child);
void block_info_free(block_info_t * info);




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
