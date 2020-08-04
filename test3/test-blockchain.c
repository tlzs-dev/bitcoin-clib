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
#include <math.h>

#include "chains.h"
#include <gtk/gtk.h>



#include "utils.h"

#include <pthread.h>

#include <locale.h>
#include <libintl.h>
#ifndef _
#define _(str) gettext(str)
#endif

#include "da_panel.h"


#define MAX_HEIGHT (100)
typedef struct shell_context
{
	void * user_data;
	void * priv;
	
	int quit;
	
	GtkWidget * window;
	GtkWidget * header_bar;
	GtkWidget * content_area;
	GtkWidget * statusbar;
	
	//~ GtkWidget * switcher;
	//~ GtkWidget * stack;
	
	GtkWidget * notebook;
	GtkWidget * logview;
	
	GtkWidget * main_chain;	// the BLOCKCHAIN
	
	ssize_t num_active_chains;
	GtkWidget ** active_chains;

	// struct da_panel
	struct da_panel panels[1];
	
	int indices_selected[MAX_HEIGHT];
	int last_indice;
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
	main_chain_column_hash,
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
	unsigned char * hash = NULL;
	int cb = 0;
	
	char * p = text;
	switch(index)
	{
	case main_chain_column_hash:
		gtk_tree_model_get(model, iter, index, &hash, -1);
		cb = bin2hex(hash, 32, &p);
		assert(cb > 0);
		break;
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
	col = gtk_tree_view_column_new_with_attributes("hash", cr, 
	//	"text", main_chain_column_hash, 
		NULL);
	gtk_tree_view_column_set_resizable(col, TRUE);
	gtk_tree_view_column_set_cell_data_func(col, cr, on_cell_data, 
		GINT_TO_POINTER(main_chain_column_hash), 
		NULL);
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
		G_TYPE_POINTER,
		G_TYPE_UINT, 
		G_TYPE_UINT,
		G_TYPE_INT64, 
		G_TYPE_UINT);
	gtk_tree_view_set_model(main_chain, GTK_TREE_MODEL(store));
	return;
}

static void run_test(shell_context_t * shell);
static void draw_summary(shell_context_t * shell);

static int init_windows(shell_context_t * shell)
{
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
	
	gtk_widget_set_size_request(scrolled_win, 300, 180);
	shell->main_chain = treeview;
	
	init_treeview_main_chain(GTK_TREE_VIEW(treeview));
	//~ gtk_widget_set_hexpand(treeview, TRUE);
	//~ gtk_widget_set_vexpand(treeview, TRUE);
	gtk_grid_attach(GTK_GRID(grid), scrolled_win, 0, 0, 1, 2);
	
	//~ GtkWidget * switcher = gtk_stack_switcher_new();
	//~ GtkWidget * stack = gtk_stack_new();
	
	//~ shell->switcher = switcher;
	//~ shell->stack = stack;

	//~ gtk_grid_attach(GTK_GRID(grid), switcher, 1, 0, 1, 1);
	//~ gtk_grid_attach(GTK_GRID(grid), stack, 1, 1, 1, 1);
	//~ gtk_widget_set_hexpand(stack, TRUE);
	//~ gtk_widget_set_vexpand(stack, TRUE);
	
	//~ gtk_widget_set_size_request(switcher, 300, -1);
	
	GtkWidget * notebook = gtk_notebook_new();
	gtk_notebook_set_scrollable(GTK_NOTEBOOK(notebook), TRUE);
	shell->notebook = notebook;
	
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	GtkWidget * logview = gtk_text_view_new();
	gtk_container_add(GTK_CONTAINER(scrolled_win), logview);
	gtk_widget_set_hexpand(scrolled_win, TRUE);
	gtk_widget_set_vexpand(scrolled_win, TRUE);
	
	//~ gtk_stack_add_titled(GTK_STACK(stack), scrolled_win, "summary", "summary");
	//~ gtk_stack_switcher_set_stack(GTK_STACK_SWITCHER(switcher), GTK_STACK(stack));
	shell->logview = logview;
	
	
	
	GtkCssProvider * css = gtk_css_provider_new();
	GError * gerr = NULL;
	gtk_css_provider_load_from_data(css, ".logview { font: 16px monospace;}", -1, &gerr);
	if(gerr)
	{
		g_printerr("gtk_css_provider_load_from_data() failed: %s\n", gerr->message);
		g_error_free(gerr);
		abort();
	}
	GtkStyleContext * style = gtk_widget_get_style_context(logview);
	gtk_widget_set_name(logview, "logview");
	
	gtk_style_context_add_provider(style, GTK_STYLE_PROVIDER(css), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	gtk_style_context_add_class(style, "logview");
	
	GtkWidget * vpaned = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
	gtk_paned_add1(GTK_PANED(vpaned), scrolled_win);
	
	struct da_panel * panel = da_panel_init(&shell->panels[0], 1000, 800, shell);
	assert(panel);
	
	gtk_paned_add2(GTK_PANED(vpaned), panel->frame);
	gtk_paned_set_position(GTK_PANED(vpaned), 180);
	
	GtkWidget * label = gtk_label_new("Summary");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), vpaned, label);
	
	gtk_grid_attach(GTK_GRID(grid), notebook, 1, 0, 1, 2);
	
	
	GtkWidget * button = gtk_button_new_from_icon_name("go-next", GTK_ICON_SIZE_BUTTON);
	gtk_header_bar_pack_start(GTK_HEADER_BAR(header_bar), button);
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(run_test), shell);
	g_signal_connect_swapped(window, "destroy", G_CALLBACK(shell_stop), shell);
	
	return 0;
}
shell_context_t * shell_new(int argc, char ** argv, void * user_data)
{
	gtk_init(&argc, &argv);
	shell_context_t * shell = g_shell;
	shell->user_data = user_data;
	
	init_windows(shell);
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
		hdr->timestamp = i;	// use timestamp as index just for testing
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
		G_TYPE_POINTER,
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
			main_chain_column_hash, (gpointer)&heirs[i].hash,
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


static int s_finished = 1;

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

static void no_free(void *p)
{
	
}
static int test_random_adding(shell_context_t * shell, void * user_data)
{
	assert(shell && user_data);
	blockchain_t * chain = user_data;
	static int last_index = -1;
	static int indices[MAX_HEIGHT] = {0};
	
	++last_index;
	if(last_index >= MAX_HEIGHT) last_index = 0;
	
	
	if(last_index == 0)	// reset dataset
	{
		randomize_indices(indices, MAX_HEIGHT);
		memset(shell->indices_selected, 0, sizeof(shell->indices_selected));
		
		block_info_t * blockchain_abandon_inheritances(blockchain_t * chain, blockchain_heir_t * parent);
		blockchain_abandon_inheritances(chain, &chain->heirs[0]);
		assert(0 == chain->height);
		
		active_chain_list_t * list = chain->candidates_list;
		active_chain_list_cleanup(list);
		
		debug_printf("current height: %d\n", (int)chain->height);
		
		printf("-- chain->search-root: %p\n", chain->search_root);
		if(chain->search_root) {
			//	twalk(chain->search_root, dump_heir_info);
		}
		
		printf("-- list->search-root: %p\n", list->search_root);
		if(list->search_root) {
		//	twalk(list->search_root, dump_block_info);
			tdestroy(list->search_root, no_free);
		}
		list->search_root = NULL;
	//	assert(NULL == list->search_root);
	}
	
	shell->indices_selected[indices[last_index]] = 1;
	
	int index = indices[last_index] + 1;
	shell->last_indice = index;
	
	printf("============ %s() ======================\n", __FUNCTION__);
	printf("\t add blocks[%d] ...\n", index);
	
	int rc = chain->add(chain, &s_block_hashes[index], &s_block_hdrs[index]);
	assert(0 == rc);
	
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

static void write_buffer(block_info_t * info, VISIT which, int depth, 
	GtkTextBuffer * buffer, GtkTextIter * iter)
{
	if(NULL == info) return;
	if(which == leaf || which == preorder)
	{
		char text[200] = "";
		int cb = snprintf(text, sizeof(text), "%.*s(%.3d)\n", 
			depth * 4, white_chars,
			info->hdr?info->hdr->nonce:-1);
		gtk_text_buffer_insert(buffer, iter, text, cb);
	}
}

void traverse_chain(block_info_t * info, int depth, GtkTextBuffer * buffer, GtkTextIter * iter)
{
	if(NULL == info) return;
	
	if(info->first_child == NULL && info->next_sibling == NULL){	// leaf
		write_buffer(info, leaf, depth, buffer, iter);
	}else
	{
		write_buffer(info, preorder, depth, buffer, iter);
		traverse_chain(info->first_child, depth + 1, buffer, iter);
		
		write_buffer(info, postorder, depth, buffer, iter);
		traverse_chain(info->next_sibling, depth, buffer, iter);
		
		write_buffer(info, endorder, depth, buffer, iter);
	}
}

static void dump_active_chain_info(GtkWidget * textview, active_chain_t * chain)
{
	char text[4096] = "";
	int cb = 0;
	GtkTextBuffer * buffer = gtk_text_buffer_new(NULL);
	GtkTextIter iter;
	
	gtk_text_buffer_get_start_iter(buffer, &iter);
	block_info_t * head = chain->head;
	cb = snprintf(text, sizeof(text), "parent (head->hash): "); 
	gtk_text_buffer_insert(buffer, &iter, text, cb);
	char * hex = text;
	cb = bin2hex(&head->hash, 32, &hex);
	gtk_text_buffer_insert(buffer, &iter, text, cb);
	gtk_text_buffer_insert(buffer, &iter, "\n", 1);
	 
	traverse_chain(head, 0, buffer, &iter);
	
	gtk_text_view_set_buffer(GTK_TEXT_VIEW(textview), buffer);
	return;
}

struct twalk_action_param
{
	GtkTextBuffer * buffer;
	GtkTextIter * iter;
};

static struct twalk_action_param s_action_param;

static void search_tree_node_on_write(const void * nodep, const VISIT which, const int depth)
{
	if(which == leaf || which == postorder)
	{
		block_info_t * info = *(block_info_t **)nodep;
		if(NULL == info) return;
		
		char text[200] = "";
		int cb = 0;
		if(info->hdr) {
			cb = snprintf(text, sizeof(text), "%.*s----(%.3d)\n", 
				depth * 8, white_chars,
				info->hdr->nonce);
		} else {
			char * p = text;
			char * p_end = p + sizeof(text);
			cb = snprintf(p, p_end - p, "%.*s--<b>[", depth * 8, white_chars);
			assert(cb > 0);
			p += cb;
			cb = bin2hex(&info->hash, 32, &p);
			assert(cb == 64);
			
			p += 6; // output first 3-bytes only
			cb = snprintf(p, p_end - p, "]</b>\n");
			assert(cb > 0);
			p += cb;
			
			cb = p - text;
		}
		assert(cb > 0 && cb < 200);
		gtk_text_buffer_insert_markup(s_action_param.buffer, s_action_param.iter, text, cb);
	}
}


static void on_summary(shell_context_t * shell, blockchain_t * main_chain)
{
	char summary[4096] = "";
	GtkTextBuffer * buffer = gtk_text_buffer_new(NULL);
	GtkTextIter iter;
	gtk_text_buffer_get_start_iter(buffer, &iter);
	
	int cb = snprintf(summary, sizeof(summary), "blockchain height: %d\n"
		"active_chains count: %d\n",
		(int)g_main_chain->height, 
		(int)g_main_chain->candidates_list->count);
	gtk_text_buffer_insert(buffer, &iter, summary, cb);
	
	s_action_param.buffer = buffer;
	s_action_param.iter = &iter;
	
	active_chain_list_t * list = main_chain->candidates_list;
	twalk(list->search_root, search_tree_node_on_write);
	gtk_text_view_set_buffer(GTK_TEXT_VIEW(shell->logview), buffer);
	
	s_action_param.buffer = NULL;
	s_action_param.iter = NULL;
	
	if(list->count < shell->num_active_chains)
	{
		for(int i = list->count; i <= shell->num_active_chains; ++i)
		{
			gtk_notebook_remove_page(GTK_NOTEBOOK(shell->notebook), i + 1);
		}
	}
	
	
	if(shell->num_active_chains <= list->count)
	{
		char name[100] = "";
		shell->active_chains = realloc(shell->active_chains, list->count * sizeof(*shell->active_chains));
		assert(shell->active_chains);
		
		for(int i = 0; i < list->count; ++i)
		{
			if(i >= shell->num_active_chains)
			{
				snprintf(name, sizeof(name), "chain %d", i);
				GtkWidget * scrolled_win = gtk_scrolled_window_new(NULL, NULL);
				shell->active_chains[i] = gtk_text_view_new();
				gtk_container_add(GTK_CONTAINER(scrolled_win), shell->active_chains[i]);
				gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_win), GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
				gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_win), GTK_SHADOW_ETCHED_IN);
				
				gtk_widget_show_all(scrolled_win);
				gtk_notebook_append_page(GTK_NOTEBOOK(shell->notebook), scrolled_win, gtk_label_new(name));
			}
			
			dump_active_chain_info(shell->active_chains[i], list->chains[i]);
			
		}
	}
	shell->num_active_chains = list->count;
	
	draw_summary(shell);
}


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
		
		on_summary(shell, g_main_chain);
		
		
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
	test_module_func func = tests[test_index];
	
	if(func) func(shell, g_main_chain);
	
	s_finished = 1;
	pthread_exit((void *)(long)0);
}

static void run_test(shell_context_t * shell)
{
	GtkWidget * header_bar = shell->header_bar;
	GtkWidget * statusbar = shell->statusbar;
	assert(header_bar && statusbar);
	
	if(!s_finished) return; // is busy
	
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





/*******************************************************
 * draw summary graph
******************************************************/
static void draw_summary(shell_context_t * shell)
{
	struct da_panel * panel = &shell->panels[0];
	assert(panel && panel->image_width > 1 && panel->image_height > 1);
	
	panel->clear(panel);

	blockchain_t * main_chain = g_main_chain;
	active_chain_list_t * list = main_chain->candidates_list;

	int * indices_selected = shell->indices_selected;
	
	cairo_t * cr = cairo_create(panel->surface);
	cairo_set_line_width(cr, 2);
	
	// draw main_chain
	int x = 0;
	int y = 0; 
	int item_size = 10;
	
	struct {
		double r, g, b, a;
	}colors[] = {
		[0] = {0, 1, 0, 1}, // green, means 'not selected'
		[1] = {1, 0, 0, 1}, // red, means 'selected'
		
		[2] = {1, 1, 1, 1}, // white, border color
		[3] = {0.5, 0.5, 0.5, 1}, // gray, means already in the BLOCKCHAIN
	};
	
	for(int i = 0; i < MAX_HEIGHT; ++i)
	{
		x = i * item_size;
		int state = indices_selected[i];
		if((i + 1) <= main_chain->height) {
			cairo_set_source_rgba(cr, colors[3].r,  colors[3].g,  colors[3].b,  colors[3].a);
		}else
		{
			cairo_set_source_rgba(cr, colors[state].r,  colors[state].g,  colors[state].b,  colors[state].a);
		}
		cairo_rectangle(cr, x, y, item_size, item_size);
		cairo_fill_preserve(cr);
		
		cairo_set_source_rgba(cr, colors[2].r,  colors[2].g,  colors[2].b,  colors[2].a);
		cairo_stroke(cr);
	}
	
	// draw active_chains
	
	int radius = item_size / 2 - 2;
	if(radius < 1) radius = 1;
	
	for(int i = 0; i < list->count; ++i)
	{
		y += item_size * 2;
		active_chain_t * chain = list->chains[i];
		block_info_t * child = chain->head->first_child;
		
		// clear current region
		cairo_set_source_rgb(cr, 0, 0, 0);
		cairo_rectangle(cr, 0, y, panel->image_width, item_size * 2);
		cairo_fill(cr);
		
		// draw first-child only
		cairo_set_dash(cr, NULL, 0, 0);
		
		int has_newly_added_node = 0;
		while(child)
		{
			assert(child->hdr);
			int indice = (int)child->hdr->timestamp - 1;
			
			if((indice + 1) == shell->last_indice){
				has_newly_added_node = 1;
			}
			
		
			if(has_newly_added_node)
			{
				cairo_set_line_width(cr, 3);
				cairo_set_source_rgb(cr, 1, 1, 0);	// set to yellow for newly added item
			}
			else {
				cairo_set_line_width(cr, 1);
				cairo_set_source_rgba(cr, 0, 1, 1, 1); // cyan for other chain's nodes
			}
			x = indice * item_size;
			cairo_arc(cr, x + radius, y + radius, radius, 0, M_PI * 2.0);
			
			child = child->first_child;
		}
		cairo_stroke(cr);
		
		// draw a line for separation
		
		double dashes[1] = {2.0};
		cairo_set_line_width(cr, 2);
		cairo_set_dash(cr, dashes, 1, 0);
		cairo_set_source_rgb(cr, 0.8, 0.8, 0.8);
		cairo_move_to(cr, 0, y + item_size + item_size / 2);
		cairo_line_to(cr, panel->image_width, y + item_size + item_size / 2);
		cairo_stroke(cr);
	}
	
	cairo_destroy(cr);
	gtk_widget_queue_draw(panel->da);
	return;
}



#undef MAX_HEIGHT 
