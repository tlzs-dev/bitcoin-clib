/*
 * shell.c
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

#include "shell.h"
#include <gtk/gtk.h>
#include <json-c/json.h>
#include <vte/vte.h>

#include "utils.h"

#ifndef _BLOCKS_DB_H_
#include "satoshi-types.h"
struct db_record_block
{
	struct satoshi_block_header hdr;
	
	int32_t height;
	int32_t is_orphan;

	// blk(nnnnn).dat file info
	int64_t file_index;
	int64_t start_pos;		// the begining of the block_data (just after block_file_hdr{magic, size} )
	
	// used to verify block_file_hdr : assert( start_pos >= 8 && (*(uint32_t *)(start-8) == magic)  && (*(uint32_t *)(start-4) == block_size) );
	uint32_t magic;
	uint32_t block_size;
}__attribute__((packed));
#endif

typedef struct shell_private
{
	shell_context_t * shell;
	json_object * jconfig;
	char * working_path;
	
	GtkWidget * window;
	GtkWidget * header_bar;
	union {
		GtkWidget * treeview[2];
		struct {
			GtkWidget * blocks_tree;
			GtkWidget * utxoes_tree;
		};
	};
	GtkWidget * vte;	// pseudo-terminal
	
	int page_size;		// default: 1000 records per page
	int blocks_page;	// page index
	int blocks_pages_count;
	uint256_t * hashes;
	struct db_record_block * blocks;
	
	int utxoes_page;	// page index
	int utxoes_pages_count;
	
	
	
	guint timer_id;
	double fps;
	
	int quit;
	int is_running;
}shell_private_t;

shell_private_t * shell_private_new(shell_context_t * shell) 
{
	shell_private_t * priv = calloc(1, sizeof(*priv));
	priv->shell = shell;
	shell->priv = priv;
	priv->fps = 5;
	priv->page_size = 1000;
	
	priv->hashes = calloc(priv->page_size, sizeof(*priv->hashes));
	priv->blocks = calloc(priv->page_size, sizeof(*priv->blocks));
	
	assert(priv->hashes && priv->blocks);
	return priv;
}
void shell_private_free(shell_private_t * priv)
{
	if(NULL == priv) return;
	if(priv->timer_id) {
		g_source_remove(priv->timer_id);
		priv->quit = 1;
		priv->timer_id = 0;
	}
	return;
}

static void init_windows(shell_context_t * shell);
static int load_data(shell_context_t * shell);

static int shell_init(struct shell_context * shell, void * config) {
	json_object * jconfig = config;
	if(jconfig) {
		
	}
	
	init_windows(shell);
	load_data(shell);
	return 0;
}

static gboolean on_shell_timeout(shell_context_t * shell);
static int shell_run(struct shell_context * shell)
{
	shell_private_t * priv = shell->priv;
	assert(priv);
	
	if(priv->is_running) return 0;

	priv->is_running = 1;
	
	if(priv->fps > 0.01 && priv->fps < 1000) {
		priv->timer_id = g_timeout_add((guint)(1000.0 / priv->fps), (GSourceFunc)on_shell_timeout, shell);
	}
	gtk_main();
	return 0;
}
static int shell_stop(struct shell_context * shell)
{
	shell_private_t * priv = shell->priv;
	if(!priv->quit) {
		priv->is_running = 0;
		priv->quit = 1;
		gtk_main_quit();
	}
	return 0;
}


static shell_context_t g_shell[1] = {{
	.init = shell_init,
	.run = shell_run,
	.stop = shell_stop,
}};

shell_context_t * shell_context_init(shell_context_t * shell, int argc, char ** argv, void * user_data)
{
	gtk_init(&argc, &argv);
	if(NULL == shell) shell = g_shell;
	else {
		shell->init = shell_init;
		shell->run = shell_run;
		shell->stop = shell_stop;
	}
	
	shell->user_data = user_data;
	shell_private_t * priv = shell_private_new(shell);
	assert(priv && priv == shell->priv);
	return shell;
}

void shell_context_cleanup(shell_context_t * shell)
{
	if(NULL == shell) return;
	shell_private_t * priv = shell->priv;
	assert(priv);
	
	if(!priv->quit) {
		priv->quit = 1;
		gtk_main_quit();
	}
	if(shell->on_cleanup) shell->on_cleanup(shell);
	shell_private_free(priv);
	return;
}


static gboolean on_shell_timeout(shell_context_t * shell) 
{
	assert(shell && shell->priv);
	shell_private_t * priv = shell->priv;
	if(priv->quit) {
		priv->timer_id = 0;
		return G_SOURCE_REMOVE;
	}
	
	int rc = 0;
	if(shell->on_timeout) rc = shell->on_timeout(shell); 
	
	if(rc) {
		priv->timer_id = 0;
		return G_SOURCE_REMOVE;
	}
	return G_SOURCE_CONTINUE;
}

static void init_blocks_treeview(GtkTreeView * tree);
static void init_utxoes_treeview(GtkTreeView * tree);
static void init_windows(shell_context_t * shell)
{
	assert(shell && shell->priv);
	shell_private_t * priv = shell->priv;
	GtkWidget * window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	GtkWidget * header_bar = gtk_header_bar_new();
	GtkWidget * grid = gtk_grid_new();
	gtk_container_add(GTK_CONTAINER(window), grid);
	gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);
	gtk_window_set_titlebar(GTK_WINDOW(window), header_bar);
	gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header_bar), TRUE);
	gtk_header_bar_set_title(GTK_HEADER_BAR(header_bar), "DB Viewer");
	
	GtkWidget * vpaned = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
	gtk_widget_set_vexpand(vpaned, TRUE);
	
	GtkWidget * hpaned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
	gtk_widget_set_size_request(hpaned, -1, 480);
	
	GtkWidget * vte = vte_terminal_new();
	GtkWidget * scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_win), 
		GTK_POLICY_AUTOMATIC, 
		GTK_POLICY_ALWAYS);
	gtk_container_add(GTK_CONTAINER(scrolled_win), vte);
	gtk_paned_add1(GTK_PANED(vpaned), hpaned);
	gtk_paned_add2(GTK_PANED(vpaned), scrolled_win);
	gtk_widget_set_hexpand(scrolled_win, TRUE);
	gtk_widget_set_size_request(scrolled_win, -1, 120);
	
	gtk_paned_set_position(GTK_PANED(vpaned), 480);
	gtk_grid_attach(GTK_GRID(grid), vpaned, 0, 0, 1, 1);
	
	GtkWidget * stack = gtk_stack_new();
	gtk_paned_add1(GTK_PANED(hpaned), stack);
	
	GtkWidget * stack_switcher = gtk_stack_switcher_new();
	gtk_stack_switcher_set_stack(GTK_STACK_SWITCHER(stack_switcher), GTK_STACK(stack));
	gtk_grid_attach(GTK_GRID(grid), stack_switcher, 0, 1, 1, 1);

	char *argv[] = {
		"/bin/bash",
		NULL
	};
	vte_terminal_spawn_async(VTE_TERMINAL(vte), VTE_PTY_DEFAULT,
		priv->working_path,
		argv, 
		NULL, 
		G_SPAWN_DEFAULT, 
		NULL, NULL,
		NULL, -1,
		NULL, NULL, NULL);
	
	
	priv->window = window;
	priv->header_bar = header_bar;
	priv->vte = vte;
	GtkWidget * treeview = NULL;
	
	treeview = gtk_tree_view_new();
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(scrolled_win), treeview);
	gtk_widget_set_hexpand(scrolled_win, TRUE);
	gtk_widget_set_vexpand(scrolled_win, TRUE);
	gtk_stack_add_titled(GTK_STACK(stack), scrolled_win, "blocks_db", "blocks_db");
	priv->blocks_tree = treeview;
	init_blocks_treeview(GTK_TREE_VIEW(treeview));
	
	treeview = gtk_tree_view_new();
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(scrolled_win), treeview);
	gtk_widget_set_hexpand(scrolled_win, TRUE);
	gtk_widget_set_vexpand(scrolled_win, TRUE);
	gtk_stack_add_titled(GTK_STACK(stack), scrolled_win, "utxoes_db", "utxoes_db");
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_win), GTK_SHADOW_ETCHED_IN);
	priv->utxoes_tree = treeview;
	init_utxoes_treeview(GTK_TREE_VIEW(treeview));
	
	
	
	g_signal_connect_swapped(window, "destroy", G_CALLBACK(shell->stop), shell); 
	gtk_widget_show_all(window);
	return;
}



enum {
	BLOCKS_COLUMN_HEIGHT,
	BLOCKS_COLUMN_HASH,
	BLOCKS_COLUMN_HDR,
	BLOCKS_COLUMN_DATA_PTR,
	
	BLOCKS_COLUMNS_COUNT,
};

enum {
	UTXOES_COLUMN_OUTPOINT,
	UTXOES_COLUMN_VALUE,
	UTXOES_COLUMN_SCRIPTS,
	UTXOES_COLUMN_DATA_PTR,
	UTXOES_COLUMNS_COUNT,
};

int load_blocks(GtkTreeView * tree, db_manager_t * db_mgr, shell_private_t * priv);
int load_utxoes(GtkTreeView * tree, db_manager_t * db_mgr, shell_private_t * priv);

static int load_data(shell_context_t * shell)
{
	assert(shell && shell->priv);
	shell_private_t * priv = shell->priv;
	
	db_manager_t * db_mgr = shell->user_data;
	assert(db_mgr);
	
	load_blocks(GTK_TREE_VIEW(priv->blocks_tree), db_mgr, priv);
	load_utxoes(GTK_TREE_VIEW(priv->utxoes_tree), db_mgr, priv);
	
	return 0;
}

static void on_set_block_hash(GtkTreeViewColumn *col,
	GtkCellRenderer *cell,
	GtkTreeModel *tree_model,
	GtkTreeIter *iter,
	gpointer data);
static void on_set_block_hdr(GtkTreeViewColumn *col,
	GtkCellRenderer *cell,
	GtkTreeModel *tree_model,
	GtkTreeIter *iter,
	gpointer data);
	
static void init_blocks_treeview(GtkTreeView * tree)
{
	GtkCellRenderer * cr = gtk_cell_renderer_text_new();
	GtkTreeViewColumn * col = gtk_tree_view_column_new_with_attributes(
		"height",  cr, 
		"text", BLOCKS_COLUMN_HEIGHT,
		NULL);
	gtk_tree_view_append_column(tree, col);
	gtk_tree_view_column_set_resizable(col, TRUE);
	
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes(
		"hash",  cr, 
		NULL);
	gtk_tree_view_append_column(tree, col);
	gtk_tree_view_column_set_cell_data_func(col, cr, on_set_block_hash, NULL, NULL);
	gtk_tree_view_column_set_resizable(col, TRUE);
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes(
		"hdr",  cr, 
		NULL);
	gtk_tree_view_append_column(tree, col);
	gtk_tree_view_column_set_cell_data_func(col, cr, on_set_block_hdr, NULL, NULL);
	gtk_tree_view_column_set_resizable(col, TRUE);
	
	
	GtkListStore * store = gtk_list_store_new(BLOCKS_COLUMNS_COUNT, 
		G_TYPE_INT, 
		G_TYPE_POINTER,
		G_TYPE_POINTER,
		G_TYPE_POINTER);
	gtk_tree_view_set_model(tree, GTK_TREE_MODEL(store));
	
	gtk_tree_view_set_grid_lines(tree, GTK_TREE_VIEW_GRID_LINES_BOTH);
	
	gtk_widget_set_size_request(GTK_WIDGET(tree), 300, 200);
	return;
}
static void init_utxoes_treeview(GtkTreeView * tree)
{
	return;
}



static void on_set_block_hash(GtkTreeViewColumn *col,
	GtkCellRenderer *cr,
	GtkTreeModel *model,
	GtkTreeIter *iter,
	gpointer data)
{
	unsigned char * hash = NULL;
	gtk_tree_model_get(model, iter, BLOCKS_COLUMN_HASH, &hash, -1);
	if(hash) {
		char * hex = NULL;
		ssize_t cb = bin2hex(hash, 32, &hex);
		assert(cb == 64 && hex);
		
		strcpy(hex + 8, "...");	// display the first 4 bytes only
		
		g_object_set(cr, "text", hex, NULL);
		free(hex);
	}
	return;
}
static void on_set_block_hdr(GtkTreeViewColumn *col,
	GtkCellRenderer *cr,
	GtkTreeModel *model,
	GtkTreeIter *iter,
	gpointer data)
{
	struct satoshi_block_header * hdr = NULL;
	gtk_tree_model_get(model, iter, BLOCKS_COLUMN_HDR, &hdr, -1);
	if(hdr) {
		char buffer[4096] = "";
		snprintf(buffer, sizeof(buffer), 
			"version: %d, prev_hash: 0x%.8x..., merkle_root: 0x%.8x...",
			hdr->version, 
			be32toh(*(uint32_t *)hdr->prev_hash),
			be32toh(*(uint32_t *)hdr->merkle_root));
		g_object_set(cr, "text", buffer, NULL);
	}
	
	return;
}







int load_blocks(GtkTreeView * tree, db_manager_t * db_mgr, shell_private_t * priv)
{
	int32_t height = -1;
	struct db_record_block block[1];
	memset(block, 0, sizeof(block));
	unsigned char hash[32] = { 0 };
	
	int rc = 0;
	GtkListStore * store = gtk_list_store_new(BLOCKS_COLUMNS_COUNT, 
		G_TYPE_INT, 
		G_TYPE_POINTER,
		G_TYPE_POINTER,
		G_TYPE_POINTER);
	
	
	gtk_list_store_clear(store);
	
	GtkTreeIter iter;
	
	int count = 0;
	db_cursor_t * cursor = db_mgr->blocks_cursor;
	if(NULL == cursor ) {
		cursor = db_cursor_init(NULL, db_mgr->heights_db, NULL, 0);
		assert(cursor);
		db_mgr->blocks_cursor = cursor;
		
		cursor->skey->data = &height;
		cursor->skey->size = sizeof(height);
		
		cursor->key->data = hash;
		cursor->key->size = sizeof(hash);
		
		cursor->value->data = block;
		cursor->value->size = sizeof(block);
		
		rc =cursor->first(cursor);
		assert(0 == rc);
		
		
		memcpy(&priv->blocks[0], block, sizeof(priv->blocks[0]));
		memcpy(&priv->hashes[0], hash, sizeof(priv->hashes[0]));
		
		gtk_list_store_append(store, &iter);
		gtk_list_store_set(store, &iter, 
			BLOCKS_COLUMN_HEIGHT, height,
			BLOCKS_COLUMN_HASH, &priv->hashes[0],
			BLOCKS_COLUMN_HDR, &priv->blocks[0].hdr,
			BLOCKS_COLUMN_DATA_PTR, &priv->blocks[0],
			-1);
		++count;
	}
	for(; count < priv->page_size; ++count) {
		rc = cursor->next(cursor);
		if(rc) break;
		
		memcpy(&priv->blocks[count], block, sizeof(priv->blocks[count]));
		memcpy(&priv->hashes[count], hash, sizeof(priv->hashes[count]));
		
		gtk_list_store_append(store, &iter);
		gtk_list_store_set(store, &iter, 
			BLOCKS_COLUMN_HEIGHT, height,
			BLOCKS_COLUMN_HASH, &priv->hashes[count],
			BLOCKS_COLUMN_HDR, &priv->blocks[count].hdr,
			BLOCKS_COLUMN_DATA_PTR, &priv->blocks[count],
			-1);
	}
	
	gtk_tree_view_set_model(tree, GTK_TREE_MODEL(store));
	return 0;
}

int load_utxoes(GtkTreeView * tree, db_manager_t * db_mgr, shell_private_t * priv)
{
	return 0;
}
