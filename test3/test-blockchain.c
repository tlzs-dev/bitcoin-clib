/*
 * test-blockchain.c
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

#include "chains.h"
#include <gtk/gtk.h>

#include <pthread.h>

#include <locale.h>
#include <libintl.h>
#ifndef _
#define _(str) gettext(str)
#endif

typedef struct shell_context
{
	void * user_data;
	void * priv;
	
	int quit;
	
	GtkWidget * window;
	GtkWidget * header_bar;
	GtkWidget * content_area;
	GtkWidget * statusbar;
	
	GtkWidget * main_chain;	// the BLOCKCHAIN
	
	ssize_t num_active_chains;
	GtkWidget ** active_chains;

}shell_context_t;

static blockchain_t g_main_chain[1];
static shell_context_t g_shell[1];

shell_context_t * shell_new(int argc, char ** argv, void * user_data);
int shell_init(shell_context_t * shell, void * jconfig);
int shell_run(shell_context_t * shell);
int shell_stop(shell_context_t * shell);
void shell_cleanup(shell_context_t * shell);

int main(int argc, char **argv)
{
	#define TEXT_DOMAIN "bitcoin-clib"
	setlocale(LC_ALL, "");
	bindtextdomain(TEXT_DOMAIN, NULL);
	textdomain(TEXT_DOMAIN);
	
	blockchain_t * main_chain = blockchain_init(g_main_chain, NULL, NULL, NULL);
	shell_context_t * shell = shell_new(argc, argv, main_chain);
	assert(shell);

	shell_init(shell, NULL);
	shell_run(shell);
	shell_cleanup(shell);
	
	blockchain_cleanup(main_chain);
	
	return 0;
}

enum 
{
	main_chain_column_height,
	main_chain_column_bits,
	main_chain_column_difficulty_accum,
	main_chain_column_timestamp,
	main_chain_column_nonce,
	main_chain_columns_count
};

static void on_cell_data(GtkTreeViewColumn * col, GtkCellRenderer * cr, GtkTreeModel * model, 
	GtkTreeIter * iter, gpointer user_data)
{
	int index = GPOINTER_TO_INT(user_data);
	uint64_t u64 = 0;
	char text[100] = "";
	
	switch(index)
	{
	case main_chain_column_bits:
	case main_chain_column_difficulty_accum:
	case main_chain_column_timestamp:
		gtk_tree_model_get(model, iter, index, &u64, -1);
		snprintf(text, sizeof(text), "0x%.8x", (uint32_t)u64);
		break;
	default:
		abort();
	}
	
	g_object_set(cr, "text", text, NULL);
	
	return;
}

static void init_treeview_main_chain(GtkTreeView * main_chain)
{
	GtkCellRenderer * cr = NULL;
	GtkTreeViewColumn * col = NULL;
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes("height", cr, "text", main_chain_column_height, NULL);
	gtk_tree_view_append_column(main_chain, col);
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes("bits", cr, "text", main_chain_column_bits, NULL);
	gtk_tree_view_column_set_cell_data_func(col, cr, on_cell_data, 
		GINT_TO_POINTER(main_chain_column_bits), 
		NULL);
	gtk_tree_view_append_column(main_chain, col);
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes("difficulty", cr, "text", main_chain_column_difficulty_accum, NULL);
	gtk_tree_view_column_set_cell_data_func(col, cr, on_cell_data, 
		GINT_TO_POINTER(main_chain_column_difficulty_accum),
		NULL);
	gtk_tree_view_append_column(main_chain, col);
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes("timestamp", cr, "text", main_chain_column_timestamp, NULL);
	gtk_tree_view_column_set_cell_data_func(col, cr, on_cell_data, 
		GINT_TO_POINTER(main_chain_column_timestamp), 
		NULL);
	gtk_tree_view_append_column(main_chain, col);
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes("nonce", cr, "text", main_chain_column_nonce, NULL);
	gtk_tree_view_append_column(main_chain, col);
	
	GtkListStore * store = gtk_list_store_new(main_chain_columns_count, 
		G_TYPE_INT, 
		G_TYPE_UINT, 
		G_TYPE_UINT,
		G_TYPE_INT64, 
		G_TYPE_UINT);
	gtk_tree_view_set_model(main_chain, GTK_TREE_MODEL(store));
	return;
}

static void run_test(shell_context_t * shell);

shell_context_t * shell_new(int argc, char ** argv, void * user_data)
{
	char * text_domain = textdomain("bitcoin-clib");
	
	
	gtk_init(&argc, &argv);
	shell_context_t * shell = g_shell;
	
	shell->user_data = user_data;
	
	GtkWidget * window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	GtkWidget * header_bar = gtk_header_bar_new();
	gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header_bar), TRUE);
	gtk_header_bar_set_title(GTK_HEADER_BAR(header_bar), "test blockchain ...");
	
	gtk_window_set_titlebar(GTK_WINDOW(window), header_bar);
	gtk_window_set_default_size(GTK_WINDOW(window), 1280, 720);
	
	GtkWidget * vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
	gtk_widget_set_size_request(vbox, 640, 480);	// min size
	gtk_container_add(GTK_CONTAINER(window), vbox);
	
	GtkWidget * frame = gtk_frame_new(NULL);
	GtkWidget * statusbar = gtk_statusbar_new();
	gtk_widget_set_hexpand(statusbar, TRUE);
	
	gtk_box_pack_start(GTK_BOX(vbox), frame, TRUE, TRUE, 0);
	gtk_box_pack_end(GTK_BOX(vbox), statusbar, FALSE, TRUE, 0);
	
	gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_ETCHED_IN);
	
	gtk_widget_set_hexpand(frame, TRUE);
	gtk_widget_set_vexpand(frame, TRUE);
	GtkWidget * grid = gtk_grid_new();
	gtk_container_add(GTK_CONTAINER(frame), grid);
	
	shell->window = window;
	shell->header_bar = header_bar;
	shell->content_area = grid;
	shell->statusbar = statusbar;
	
	GtkWidget * scrolled_win = NULL;
	
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	GtkWidget * treeview = gtk_tree_view_new();
	gtk_container_add(GTK_CONTAINER(scrolled_win), treeview);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_win), GTK_SHADOW_ETCHED_IN);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_win), GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
	gtk_widget_set_vexpand(scrolled_win, TRUE);
	gtk_widget_set_hexpand(scrolled_win, TRUE);
	
	gtk_widget_set_size_request(scrolled_win, 300, 180);
	shell->main_chain = treeview;
	
	init_treeview_main_chain(GTK_TREE_VIEW(treeview));
	gtk_widget_set_hexpand(treeview, TRUE);
	gtk_widget_set_vexpand(treeview, TRUE);
	gtk_grid_attach(GTK_GRID(grid), scrolled_win, 0, 0, 1, 1);
	
	
	GtkWidget * button = gtk_button_new_from_icon_name("system-run", GTK_ICON_SIZE_BUTTON);
	gtk_header_bar_pack_start(GTK_HEADER_BAR(header_bar), button);
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(run_test), shell);
	g_signal_connect_swapped(window, "destroy", G_CALLBACK(shell_stop), shell);
	
	return shell;
}

int shell_run(shell_context_t * shell)
{
	gtk_widget_show_all(shell->window);
	gtk_main();
	return 0;
}

int shell_stop(shell_context_t * shell)
{
	if(!shell->quit)
	{
		shell->quit = 1;
		gtk_main_quit();
	}
	return 0;
}

void shell_cleanup(shell_context_t * shell)
{
	shell_stop(shell);
	return;
}


// initialize test dataset

#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include "utils.h"

extern const uint256_t g_genesis_block_hash[1];
extern const struct satoshi_block_header g_genesis_block_hdr[1];

#define MAX_HEIGHT (100)
static uint256_t s_block_hashes[1 + MAX_HEIGHT];
static struct satoshi_block_header s_block_hdrs[1 + MAX_HEIGHT];

static int init_dataset(void)
{
	uint32_t seed = 10000;
	memcpy(&s_block_hashes[0], g_genesis_block_hash, 32);
	
	unsigned char hash[32];
	for(int i = 1; i <= MAX_HEIGHT; ++i)
	{
		struct satoshi_block_header * hdr = &s_block_hdrs[i];
		memcpy(hdr->prev_hash, &s_block_hashes[i - 1], 32);
		hdr->timestamp = i;
		hdr->bits = 0x1d00ffff;
		hdr->nonce = seed++;
		hash256(hdr, sizeof(*hdr), (unsigned char *)&s_block_hashes[i]);
	}
	return 0;
}

void refresh_main_chain(shell_context_t * shell, blockchain_t * main_chain)
{
	GtkListStore * store = gtk_list_store_new(main_chain_columns_count, 
		G_TYPE_INT, 
		G_TYPE_UINT, 
		G_TYPE_UINT,
		G_TYPE_INT64, 
		G_TYPE_UINT);
	GtkTreeView * treeview = GTK_TREE_VIEW(shell->main_chain);
	assert(treeview);
	
	// clear tree view
	gtk_tree_view_set_model(treeview, NULL);
	
	GtkTreeIter iter;
	
	const blockchain_heir_t * heirs = main_chain->heirs;
	for(int i = 0; i <= main_chain->height; ++i)
	{
		gtk_list_store_append(store, &iter);
		gtk_list_store_set(store, &iter, 
			main_chain_column_height, i,
			main_chain_column_bits, heirs[i].bits,
			main_chain_column_difficulty_accum, heirs[i].cumulative_difficulty.bits,
			main_chain_column_timestamp, heirs[i].timestamp,
			main_chain_column_nonce, s_block_hdrs[i].nonce,
			-1);
	}
	gtk_tree_view_set_model(treeview, GTK_TREE_MODEL(store));
}

int shell_init(shell_context_t * shell, void * jconfig)
{
	init_dataset();
	
	blockchain_t * main_chain = shell->user_data;
	assert(main_chain);
	
	for(int i = 1; i <= MAX_HEIGHT; ++i) {
		main_chain->add(main_chain, &s_block_hashes[i], &s_block_hdrs[i]);
	}
	
	for(int i = 1; i <= main_chain->height; ++i) {
		printf("-- heirs[%d]: timestamp=%d, diffculty_accum=0x%.8x\n", i, 
			(int)main_chain->heirs[i].timestamp,
			main_chain->heirs[i].cumulative_difficulty.bits
			);
	}
	
	char text[100];
	snprintf(text, sizeof(text), "blockchain height: %d", (int)main_chain->height);
	gtk_header_bar_set_subtitle(GTK_HEADER_BAR(shell->header_bar), text); 
	
	refresh_main_chain(shell, main_chain);
	
	
	return 0;
}


static int s_finished = 0;

typedef int (* test_module_func)(shell_context_t * shell, void * user_data);

#define MAX_TESTS (10)
static int test_index = 0;


static void randomize_indices(int indices[], ssize_t size)
{
	srand(time(NULL));
	assert(indices && size > 0);
	
	int * table = calloc(size, sizeof(*table));
	for(int i = 0; i < size; ++i) {
		table[i] = i;
	}
	
	int i = 0;
	while(size > 0)
	{
		int index = rand() % size;
		indices[i++] = table[index];
		table[index] = table[--size];
	}
	free(table);
}


block_info_t * blockchain_abandon_inheritances(blockchain_t * chain, blockchain_heir_t * parent);

#include <search.h>

typedef int (*compare_func)(const void *, const void *);
static const char white_chars[] = 
		"                                " "                                "
		"                                " "                                "
		"                                " "                                "
		"                                " "                                ";
		
static void dump_heir_info(const void * nodep, 
	const VISIT which,
	const int depth)
{
	blockchain_heir_t * info;
	switch(which)
	{
	case preorder: case endorder: break;
	case postorder: case leaf:
		info = *(blockchain_heir_t **)nodep;
	//	printf("depth: %d, id = %d\n", depth, info->id);
		printf("%.*s (%d)\n", depth * 4, white_chars, (int)info->timestamp);
		break; 
	}
}


static void dump_block_info(const void * nodep, 
	const VISIT which,
	const int depth)
{
	block_info_t * info;
	switch(which)
	{
	case preorder: case endorder: break;
	case postorder: case leaf:
		info = *(block_info_t **)nodep;
	//	printf("depth: %d, id = %d\n", depth, info->id);
		printf("%.*s (%d)\n", depth * 4, white_chars, info->hdr?info->hdr->nonce:-1);
		break; 
	}
} 


void block_info_dump_BFS(block_info_t * root);
static int test_random_adding(shell_context_t * shell, void * user_data)
{
	assert(shell && user_data);
	blockchain_t * chain = user_data;
	
	blockchain_abandon_inheritances(chain, &chain->heirs[0]);
	assert(0 == chain->height);
	
	active_chain_list_t * list = chain->candidates_list;
	active_chain_list_cleanup(list);
	
	debug_printf("current height: %d\n", (int)chain->height);
	
	printf("-- chain->search-root: %p\n", chain->search_root);
	if(chain->search_root) twalk(chain->search_root, dump_heir_info);
	
	printf("-- chain->search-root: %p\n", list->search_root);
	if(list->search_root) twalk(list->search_root, dump_block_info);
	
	assert(NULL == list->search_root);
	
	printf("============ %s() ======================\n", __FUNCTION__);
	
	int indices[MAX_HEIGHT] = {0};
	randomize_indices(indices, MAX_HEIGHT);
	
	for(int i = 0; i < MAX_HEIGHT; ++i)
	{
		int index = indices[i] + 1;
		printf("\t add blocks[%d] ...\n", index);
		
		chain->add(chain, &s_block_hashes[index], &s_block_hdrs[index]);
		
		for(ssize_t ii = 0; ii < list->count; ++ii)
		{
			active_chain_t * active = list->chains[ii];
			
			printf("---- chain %Zd ----: \n", ii);
			block_info_dump_BFS(active->head);
		}
	}
	
	
	printf("==> block height: %d, list.count=%d\n", 
		(int)chain->height,
		(int)chain->candidates_list->count
		);
	return 0;
}

static int test_add_duplicates(shell_context_t * shell, void * user_data)
{
	return 0;
}

static int test_reorg(shell_context_t * shell, void * user_data)
{
	
}

static test_module_func tests[MAX_TESTS] = {
	[0] = test_random_adding,
	[1] = test_add_duplicates,
	[2] = test_reorg,
	
};


static gboolean on_timer(shell_context_t * shell)
{
	if(shell->quit) {
		s_finished = 1;
	}
	if(s_finished == 1) {
		
		refresh_main_chain(shell, g_main_chain);
		
		char text[100] = "";
		snprintf(text, sizeof(text), "blockchain height:  %d", (int)g_main_chain->height);
		gtk_header_bar_set_subtitle(GTK_HEADER_BAR(shell->header_bar), text);
		gdk_window_set_cursor(gtk_widget_get_window(shell->window), 
		gdk_cursor_new_from_name(gtk_widget_get_display(shell->window), "default"));
		
		return G_SOURCE_REMOVE;
	}
	// display messages
	// ...
	
	return G_SOURCE_CONTINUE;
}


static void * do_test(void * user_data)
{
	shell_context_t * shell = user_data;
	assert(shell);
	
	///< @todo
	/// ...
	test_module_func func = tests[test_index++];
	test_index %= MAX_TESTS;
	
	if(func) func(shell, g_main_chain);
	
	s_finished = 1;
	pthread_exit((void *)(long)0);
}

static void run_test(shell_context_t * shell)
{
	GtkWidget * header_bar = shell->header_bar;
	GtkWidget * statusbar = shell->statusbar;
	assert(header_bar && statusbar);
	
	if(s_finished) return; // is busy
	
	s_finished = 0;
	guint timer_id = g_timeout_add(100, (GSourceFunc)on_timer, shell);
	gtk_header_bar_set_subtitle(GTK_HEADER_BAR(header_bar), "testing ...");
	
	gdk_window_set_cursor(gtk_widget_get_window(shell->window), 
		gdk_cursor_new_from_name(gtk_widget_get_display(shell->window), "wait"));
		
	// do_test()
	pthread_t th;
	int rc = pthread_create(&th, NULL, do_test, shell);
	assert(0 == rc);
	
	pthread_detach(th);

	return;
}

