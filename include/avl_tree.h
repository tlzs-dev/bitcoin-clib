#ifndef _AVL_TREE_H_
#define _AVL_TREE_H_
#include <search.h>
/*****************************************************
 * AVL Tree (tsearch impl.)
 * 
 * origin: [ musl_libc-1.2.0 ]( https://www.musl-libc.org )
 *     musl as a whole is licensed under the following standard MIT license.
 *     Copyright © 2005-2020 Rich Felker, et al.
 * 
 * modified by: chehw (htc.chehw@gmail.com)
 *    - append a context parameter (user_data) to twalk() 
 *    - add items count
 *    - add tree_iterator
 */ 

#ifdef __cplusplus
extern "C" {
#endif

struct avl_node {
	const void * key;
	struct avl_node * a[2];	// children: [0]==left, [1]==right
	int h;
};

typedef struct avl_tree
{
	struct avl_node * root;
	void * user_data;
	ssize_t count;

	/**
	 * virtual public methods: [ overidable ]
	 * can be overiden to use inline compare functions
	 */
	void *(* add)(struct avl_tree * tree, const void * key);	// tsearch, 
	void *(* del)(struct avl_tree * tree, const void * key);	// tdelete
	void *(*find)(struct avl_tree * tree, const void * key);	// tfind
	void  (*traverse)(struct avl_tree * tree);					// twalk
	
	struct avl_node * (* iter_begin)(struct avl_tree * tree);
	struct avl_node * (* iter_next)(struct avl_tree * tree);
	
	// callbacks, need to be set in advance if use the default processing
	int (* on_compare)(const void * a, const void * b);
	void (* on_traverse)(const struct avl_node * nodep, const VISIT which, const int depth, void * user_data);
	void (* on_free_data)(void * data);
	
	// priv
	void * stack;
}avl_tree_t;

avl_tree_t * avl_tree_init(avl_tree_t * tree, void * user_data);
void avl_tree_cleanup(avl_tree_t * tree);

#ifdef __cplusplus
}
#endif
#endif
