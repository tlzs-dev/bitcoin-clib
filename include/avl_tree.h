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
	void (* on_free_data)(void * data);
	
	// priv
	void * stack;
}avl_tree_t;

avl_tree_t * avl_tree_init(avl_tree_t * tree, void * user_data);
void avl_tree_cleanup(avl_tree_t * tree);


void * avl_tree_add(struct avl_tree * tree, const void *key, int (*cmp)(const void *, const void *));	// tsearch, 
void * avl_tree_del(struct avl_tree * tree, const void * key, int (*cmp)(const void *, const void *));	// tdelete
void * avl_tree_find(struct avl_tree * tree, const void * key, int (*cmp)(const void *, const void *));	// tfind
void avl_tree_traverse(struct avl_tree * tree,
	void (* on_traverse)(const struct avl_node * nodep, const VISIT which, const int depth, void * user_data),
	void * user_data
);					// twalk
void avl_tree_destroy(struct avl_node *root, void (*on_free_data)(void *));	// tdestroy
struct avl_node * avl_tree_iter_begin(struct avl_tree * tree);
struct avl_node * avl_tree_iter_next(struct avl_tree * tree);

#ifdef __cplusplus
}
#endif
#endif
