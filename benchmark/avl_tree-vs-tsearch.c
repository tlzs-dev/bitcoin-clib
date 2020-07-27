/*
 * avl_tree-vs-tsearch.c
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

/**
 * $ gcc -std=gnu99 -D_GNU_SOURCE -DNDEBUG -Wall -O3 -o %e %f ../src/utils/utils.c  -I../include -lm -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <time.h>
#include <sys/times.h>

#include "utils.h"
#include <search.h>
#include "../src/algorithm/avl_tree.c"



/***************************************************
 * musl-libc::tsearch.c
 **************************************************/
 
#define MAXH (sizeof(void*)*8*3/2)

struct node {
	const void *key;
	void *a[2];
	int h;
};
 
static inline int height(struct node *n) { return n ? n->h : 0; }

static int rot(void **p, struct node *x, int dir /* deeper side */)
{
	struct node *y = x->a[dir];
	struct node *z = y->a[!dir];
	int hx = x->h;
	int hz = height(z);
	if (hz > height(y->a[dir])) {
		/*
		 *   x
		 *  / \ dir          z
		 * A   y            / \
		 *    / \   -->    x   y
		 *   z   D        /|   |\
		 *  / \          A B   C D
		 * B   C
		 */
		x->a[dir] = z->a[!dir];
		y->a[!dir] = z->a[dir];
		z->a[!dir] = x;
		z->a[dir] = y;
		x->h = hz;
		y->h = hz;
		z->h = hz+1;
	} else {
		/*
		 *   x               y
		 *  / \             / \
		 * A   y    -->    x   D
		 *    / \         / \
		 *   z   D       A   z
		 */
		x->a[dir] = z;
		y->a[!dir] = x;
		x->h = hz+1;
		y->h = hz+2;
		z = y;
	}
	*p = z;
	return z->h - hx;
}

/* balance *p, return 0 if height is unchanged.  */
int __tsearch_balance(void **p)
{
	struct node *n = *p;
	int h0 = height(n->a[0]);
	int h1 = height(n->a[1]);
	if (h0 - h1 + 1u < 3u) {
		int old = n->h;
		n->h = h0<h1 ? h1+1 : h0+1;
		return n->h - old;
	}
	return rot(p, n, h0<h1);
}


void * musl_tsearch(const void *key, void **rootp,
	int (*cmp)(const void *, const void *))
{
	if (!rootp)
		return 0;

	void **a[MAXH];
	struct node *n = *rootp;
	struct node *r;
	int i=0;
	a[i++] = rootp;
	for (;;) {
		if (!n)
			break;
		int c = cmp(key, n->key);
		if (!c)
			return n;
		a[i++] = &n->a[c>0];
		n = n->a[c>0];
	}
	r = malloc(sizeof *r);
	if (!r)
		return 0;
	r->key = key;
	r->a[0] = r->a[1] = 0;
	r->h = 1;
	/* insert new node, rebalance ancestors.  */
	*a[--i] = r;
	while (i && __tsearch_balance(a[--i]));
	return r;
}


/******************************************
 * utils
 *****************************************/

typedef struct sys_timer
{
	struct tms begin;
	struct tms end;
	clock_t t0;
	clock_t t1;
	
/**
 * sysconf(_SC_CLK_TCK);  In POSIX.1-1996 the symbol CLK_TCK (defined in <time.h>)  is  mentioned 
 * as obsolescent.  It is obsolete now.
 */
//	long clk_tck;
}sys_timer_t;

static sys_timer_t g_sys_timer[1];
clock_t sys_timer_start(sys_timer_t * stimer)
{
	if(NULL == stimer) stimer = g_sys_timer;
	stimer->t0 = times(&stimer->begin);
	if(stimer->t0 == -1) perror("sys_timer_start()");
	return stimer->t0;
}

clock_t sys_timer_stop(sys_timer_t * stimer) 
{
	if(NULL == stimer) stimer = g_sys_timer;
	stimer->t1 = times(&stimer->end);
	if(stimer->t1 == -1) perror("sys_timer_start()");
	return stimer->t1;
}

void sys_timer_dump2(const sys_timer_t * stimer, FILE * fp)
{
	if(NULL == stimer) stimer = g_sys_timer;
	if(NULL == fp) fp = stdout;
	fprintf(fp, "sys_timer::time_elapsed: (ticks0=%ld, ticks1=%ld, %ld ms)\n"
		"\tuser time: %ld ms\n"
		"\t sys time: %ld ms\n"
		"\tchildren user time: %ld ms\n"
		"\tchildren  sys time: %ld ms\n",
		stimer->t0, stimer->t1, (stimer->t1 - stimer->t0) * 10,
		(long)(stimer->end.tms_utime  - stimer->begin.tms_utime ) * 10,
		(long)(stimer->end.tms_stime  - stimer->begin.tms_stime ) * 10 ,
		(long)(stimer->end.tms_cutime - stimer->begin.tms_cutime) * 10 ,
		(long)(stimer->end.tms_cstime - stimer->begin.tms_cstime) * 10 
	);
}


static void prepare_data(void);
static void avl_tree_benchmark(void);
static void tsearch_benchmark(void);
static void musl_tsearch_benchmark(void);

int main(int argc, char **argv)
{
	prepare_data();
	
	tsearch_benchmark();
	musl_tsearch_benchmark();
	avl_tree_benchmark();
	return 0;
}

#define ROUNDS (1000)	// test find data
#define WORKING_SET_SIZE	(10000)	// test add data
static int s_test_data[WORKING_SET_SIZE];

static void prepare_data()
{
	for(ssize_t i = 0; i < WORKING_SET_SIZE; ++i) {
		s_test_data[i] = i + 1;
	}
	return;
}

static void no_free(void * p) {
	return;
}

static int on_compare(const void * a, const void * b)
{
	return *(int *)a - *(int *)b;
}

static void avl_tree_benchmark()
{
	printf("\n=============== %s() ===================\n", __FUNCTION__);
	avl_tree_t avl[1];
	memset(avl, 0, sizeof(avl));
	avl_tree_init(avl, NULL);

	app_timer_start(NULL);
	sys_timer_start(NULL);
	
	for(ssize_t r = 0; r < ROUNDS; ++r) {
		for(ssize_t i = 0; i < WORKING_SET_SIZE; ++i) {
			avl_tree_add(avl, &s_test_data[i], on_compare);
		}
	}
	
	sys_timer_stop(NULL);
	
	double time_elapsed = app_timer_stop(NULL);
	sys_timer_dump2(NULL, NULL);
	printf("app_timer::time_elapsed: %.3f ms\n", time_elapsed * 1000.0);
	
	avl_tree_cleanup(avl);
	return;
}
static void tsearch_benchmark()
{
	printf("\n=============== %s() ===================\n", __FUNCTION__);
	app_timer_start(NULL);
	sys_timer_start(NULL);
	
	void * root = NULL;

	for(ssize_t r = 0; r < ROUNDS; ++r) {
		for(ssize_t i = 0; i < WORKING_SET_SIZE; ++i) {
			tsearch(&s_test_data[i], &root, on_compare);
		}
	}
	
	sys_timer_stop(NULL);
	
	double time_elapsed = app_timer_stop(NULL);
	sys_timer_dump2(NULL, NULL);
	printf("app_timer::time_elapsed: %.3f ms\n", time_elapsed * 1000.0);
	tdestroy(root, no_free);
	return;
}


static void musl_tsearch_benchmark(void)
{
	printf("\n=============== %s() ===================\n", __FUNCTION__);
	app_timer_start(NULL);
	sys_timer_start(NULL);
	
	void * root = NULL;

	for(ssize_t r = 0; r < ROUNDS; ++r) {
		for(ssize_t i = 0; i < WORKING_SET_SIZE; ++i) {
			musl_tsearch(&s_test_data[i], &root, on_compare);
		}
	}
	
	sys_timer_stop(NULL);
	
	double time_elapsed = app_timer_stop(NULL);
	sys_timer_dump2(NULL, NULL);
	printf("app_timer::time_elapsed: %.3f ms\n", time_elapsed * 1000.0);
	
}
