/*
 * test-utxoes_db.c
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

#include <stdint.h>
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils.h"
#include "blocks_db.h"
#include "utxoes_db.h"
#include "satoshi-types.h"
#include "db_engine.h"

#include "avl_tree.h"
#include "chains.h"

typedef struct memcache_block_info
{
	uint256_t hash;
	db_record_block_t data;
	satoshi_block_t * block;
}memcache_block_info_t;

memcache_block_info_t * memcache_block_info_new(const uint256_t * hash, 
	const struct satoshi_block_header * hdr, 
	int64_t file_index, int64_t file_offset, 
	satoshi_block_t * block)
{
	memcache_block_info_t * binfo = calloc(1, sizeof(*binfo));
	assert(binfo);
	binfo->hash = *hash;
	binfo->data.hdr = * hdr;
	binfo->data.file_index = file_index;
	binfo->data.start_pos = file_offset;
	binfo->block = block;
	return binfo;
}
void memcache_block_info_set(memcache_block_info_t * dst, const memcache_block_info_t * src) 
{
	if(dst->block) { satoshi_block_cleanup(dst->block); dst->block = NULL; };
	*dst = *src;
	return;
}

void memcache_block_info_free(memcache_block_info_t * binfo)
{
	if(NULL == binfo) return;
	if(binfo->block) {
		satoshi_block_cleanup(binfo->block);
		free(binfo->block);
		binfo->block = NULL;
	}
	free(binfo);
}

static int memcache_block_info_compare(const void * a, const void * b) 
{
	return uint256_compare(a, b);
}


// db_context
typedef struct db_manager
{
	db_engine_t * engine;
	void * user_data;	// shell context
	
	const char * db_home;
	
	blocks_db_t block_db[1];
	utxoes_db_t utxo_db[1];
	
}db_manager_t;
db_manager_t * db_manager_new(const char * home_dir, void * user_data);
void db_manager_cleanup(db_manager_t * db_mgr);


// blockchain
typedef struct bitcoin_blockchain
{
	void * priv;
	void * user_data;	// shell
	
	const char * blocks_data_path;
	blockchain_t * chain;
	avl_tree_t * mem_db;
	db_manager_t * db_mgr;
	
	FILE * fp;
	int file_index;
	int64_t offset;
	
	int (* on_add_block)(struct blockchain * chain, const uint256_t * hash, const int height, void * user_data);
	int (* on_remove_block)(struct blockchain * chain, const uint256_t * hash, int height, void * user_data);
}bitcoin_blockchain_t;
bitcoin_blockchain_t * bitcoin_blockchain_init(bitcoin_blockchain_t * bchain, void * user_data);
void bitcoin_blockchain_cleanup(bitcoin_blockchain_t * bchain);

// ui
#include <gtk/gtk.h>

struct utxo_data
{
	satoshi_outpoint_t outpoint;
	db_record_utxo_t utxo;
};

typedef struct shell_context
{
	void * user_data;
	GtkWidget * window;
	GtkWidget * header_bar;
	
	GtkWidget * utxo_tree;
	GtkWidget * logview;
	GtkWidget * statusbar;
	
	GtkWidget * summary;
	GtkWidget * blocks_height;
	
	bitcoin_blockchain_t btc_chain[1];
	
	// Circular buffer
	ssize_t page_size;
	ssize_t cur_pos;
	ssize_t count;
	ssize_t start_index;
	struct utxo_data * utxoes; 
	
	int manual_confirm;
	int quit;
}shell_context_t;

shell_context_t * shell_init(shell_context_t * shell, int argc, char ** argv, void * user_data);
int shell_run(shell_context_t * shell);
int shell_stop(shell_context_t * shell);
void shell_cleanup(shell_context_t * shell);
void shell_log_printf(shell_context_t * shell, const char * fmt, ...);
void shell_log_write(shell_context_t * shell, const char * prefix, const void * data, ssize_t length);

static int load_next_block(shell_context_t * shell);
int main(int argc, char **argv)
{
	shell_context_t * shell = shell_init(NULL, argc, argv, NULL);
	assert(shell);
	
	shell_run(shell);
	shell_cleanup(shell);
	return 0;
}

/**
 * shell context
**/
static shell_context_t g_shell[1] = {{
	.manual_confirm = 1,
	.quit = 0,
}};
static void init_windows(shell_context_t * shell);
shell_context_t * shell_init(shell_context_t * shell, int argc, char ** argv, void * user_data)
{
	gtk_init(&argc, &argv);
	if(NULL == shell) shell = g_shell;
	
	shell->user_data = user_data;
	
	bitcoin_blockchain_t * bchain = bitcoin_blockchain_init(shell->btc_chain, shell);
	assert(bchain);
	
	shell->page_size = 1000;
	struct utxo_data * utxoes = calloc(shell->page_size, sizeof(*utxoes));
	assert(utxoes);
	shell->utxoes = utxoes;
	
	init_windows(shell);
	return shell;
}

int shell_run(shell_context_t * shell)
{
	load_next_block(shell);	// load genesis block
	gtk_main();
	return 0;
}
int shell_stop(shell_context_t * shell)
{
	if(!shell->quit) {
		shell->quit = 1;
		gtk_main_quit();
	}
	return 0;
}
void shell_cleanup(shell_context_t * shell)
{
	if(NULL == shell) return;
	shell_stop(shell);
	
	bitcoin_blockchain_cleanup(shell->btc_chain);
	return;
}

static void on_load_next(GtkButton * button, shell_context_t * shell)
{
	int rc = load_next_block(shell);
	assert(0 == rc);
	return;
}

static void init_utxo_tree(GtkWidget * treeview, shell_context_t * shell);
static void init_windows(shell_context_t * shell)
{
	GtkWidget * window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	GtkWidget * header_bar = gtk_header_bar_new();
	GtkWidget * grid = gtk_grid_new();
	gtk_container_add(GTK_CONTAINER(window), grid);
	gtk_window_set_titlebar(GTK_WINDOW(window), header_bar);
	gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header_bar), TRUE);
	gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);
	
	GtkWidget * vpaned = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
	GtkWidget * hpaned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
	
	GtkWidget * scrolled_win = NULL;
	GtkWidget * utxo_tree = gtk_tree_view_new();
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(scrolled_win), utxo_tree);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_win), GTK_SHADOW_ETCHED_IN);
	gtk_widget_set_size_request(scrolled_win, 600, 400);
	gtk_widget_set_hexpand(scrolled_win, TRUE);
	gtk_widget_set_vexpand(scrolled_win, TRUE);
	gtk_paned_add1(GTK_PANED(hpaned), scrolled_win);
	
	GtkWidget * summary = gtk_text_view_new();
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(scrolled_win), summary);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_win), GTK_SHADOW_ETCHED_IN);
	gtk_paned_add2(GTK_PANED(hpaned), scrolled_win);
	
	gtk_paned_add1(GTK_PANED(vpaned), hpaned);
	
	GtkWidget * logview = gtk_text_view_new();
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(scrolled_win), logview);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_win), GTK_SHADOW_ETCHED_IN);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_win), GTK_POLICY_NEVER, GTK_POLICY_ALWAYS);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(logview), GTK_WRAP_WORD_CHAR);
	gtk_paned_add2(GTK_PANED(vpaned), scrolled_win);
	
	GtkWidget * statusbar = gtk_statusbar_new();
	GtkWidget * hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_grid_attach(GTK_GRID(grid), hbox, 0, 0, 1, 1);
	gtk_grid_attach(GTK_GRID(grid), vpaned, 0, 1, 1, 1);
	gtk_grid_attach(GTK_GRID(grid), statusbar, 0, 2, 1, 1);
	
	
	GtkWidget * go_next = gtk_button_new_from_icon_name("go-next", GTK_ICON_SIZE_BUTTON);
	g_signal_connect(go_next, "clicked", G_CALLBACK(on_load_next), shell);
	
	GtkWidget * blocks_height = gtk_label_new(NULL);
	gtk_widget_set_size_request(blocks_height, 120, -1);
	gtk_box_pack_start(GTK_BOX(hbox), go_next, FALSE, TRUE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), blocks_height, FALSE, TRUE, 0);
	
	shell->window = window;
	shell->header_bar = header_bar;
	shell->utxo_tree = utxo_tree;
	shell->logview = logview;
	shell->summary = summary;
	shell->blocks_height = blocks_height;
	
	
	init_utxo_tree(utxo_tree, shell);
	
	g_signal_connect_swapped(window, "destroy", G_CALLBACK(shell_stop), shell);
	gtk_widget_show_all(window);
	return;
}

enum UTXO_TREE_COLUMN
{
	UTXO_TREE_COLUMN_BLOCK_HASH,
	UTXO_TREE_COLUMN_OUTPOINT,
	UTXO_TREE_COLUMN_VALUE,
	UTXO_TREE_COLUMN_SCRIPTS,
	UTXO_TREE_COLUMN_DATA_PTR,
	
	UTXO_TREE_COLUMNS_COUNT,
};

static void on_set_utxo_cell_data(GtkTreeViewColumn * col,
	GtkCellRenderer *cr,
	GtkTreeModel *model,
	GtkTreeIter *iter,
	gpointer user_data)
{
	shell_context_t * shell = user_data;
	if(!gtk_tree_store_iter_is_valid(GTK_TREE_STORE(model), iter)) return;
		
	gint col_id = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(col), "col_id"));
	
	struct utxo_data * udata = NULL;
	gtk_tree_model_get(model, iter, UTXO_TREE_COLUMN_DATA_PTR, &udata, -1);

	char sz_text[200] = "";
	char sz_hash[65] = "";
	char * p_hex = sz_text;
	char * p_sz_hash = sz_hash;
	ssize_t cb = 0;
	if(!udata) {	// parent item
		unsigned char * hash = NULL;
		gtk_tree_model_get(model, iter, UTXO_TREE_COLUMN_BLOCK_HASH, &hash, -1);
		assert(hash);
		if(col_id == UTXO_TREE_COLUMN_BLOCK_HASH) {
			cb = bin2hex(hash, 32, &p_hex);
			assert(cb == 64);
			g_object_set(cr, "text", sz_text, NULL);
		}else g_object_set(cr, "text", "", NULL);
		
	}else {
		db_record_utxo_t * utxo = &udata->utxo;
		switch(col_id) {
		case UTXO_TREE_COLUMN_BLOCK_HASH: 
	//	case UTXO_TREE_COLUMN_OUTPOINT:
			cb = bin2hex(udata->outpoint.prev_hash, 32, &p_sz_hash);
			cb = snprintf(sz_text, sizeof(sz_text), 
				"(%.*s...) %d",
				8, sz_hash,
				udata->outpoint.index);
			break;
		case UTXO_TREE_COLUMN_VALUE:
			snprintf(sz_text, sizeof(sz_text), "%.8f BTC", 
				(double)udata->utxo.value / 100000000.0);
			g_object_set(cr, "text", sz_text, NULL);
			break;
		case UTXO_TREE_COLUMN_SCRIPTS:
			cb = bin2hex(&udata->utxo.scripts, udata->utxo.scripts[0], &p_hex);
			assert(cb >= 0 && cb <= (UTXOES_DB_MAX_SCRIPT_LENGTH * 2));
			break;
		default:
			return;
		}
		g_object_set(cr, "text", sz_text, NULL);
	}
	
	
	return;
}

static void init_utxo_tree(GtkWidget * treeview, shell_context_t * shell)
{
	GtkCellRenderer * cr = NULL;
	GtkTreeViewColumn * col = NULL;
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes("block_hash", cr, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), col);
	gtk_tree_view_column_set_cell_data_func(col, cr, 
		(GtkTreeCellDataFunc)on_set_utxo_cell_data, shell, NULL);
	g_object_set_data(G_OBJECT(col), "col_id", GINT_TO_POINTER(UTXO_TREE_COLUMN_BLOCK_HASH));
	gtk_tree_view_column_set_resizable(col, TRUE);
	gtk_tree_view_column_set_fixed_width(col, 180);
		
	//~ cr = gtk_cell_renderer_text_new();
	//~ col = gtk_tree_view_column_new_with_attributes("outpoint", cr, NULL);
	//~ gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), col);
	//~ gtk_tree_view_column_set_cell_data_func(col, cr, 
		//~ (GtkTreeCellDataFunc)on_set_utxo_cell_data, shell, NULL);
	//~ g_object_set_data(G_OBJECT(col), "col_id", GINT_TO_POINTER(UTXO_TREE_COLUMN_OUTPOINT));
	//~ gtk_tree_view_column_set_resizable(col, TRUE);
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes("value", cr, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), col);
	gtk_tree_view_column_set_cell_data_func(col, cr, 
		(GtkTreeCellDataFunc)on_set_utxo_cell_data, shell, NULL);
	g_object_set_data(G_OBJECT(col), "col_id", GINT_TO_POINTER(UTXO_TREE_COLUMN_VALUE));
	gtk_tree_view_column_set_resizable(col, TRUE);
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes("scripts", cr, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), col);
	gtk_tree_view_column_set_cell_data_func(col, cr, 
		(GtkTreeCellDataFunc)on_set_utxo_cell_data, shell, NULL);
	g_object_set_data(G_OBJECT(col), "col_id", GINT_TO_POINTER(UTXO_TREE_COLUMN_SCRIPTS));
	gtk_tree_view_column_set_resizable(col, TRUE);
	
	GtkTreeStore * store = gtk_tree_store_new(UTXO_TREE_COLUMNS_COUNT, 
		G_TYPE_POINTER,
		G_TYPE_POINTER,
		G_TYPE_INT64,
		G_TYPE_POINTER,
		G_TYPE_POINTER);
	gtk_tree_view_set_model(GTK_TREE_VIEW(treeview), GTK_TREE_MODEL(store));
	gtk_tree_view_set_grid_lines(GTK_TREE_VIEW(treeview), GTK_TREE_VIEW_GRID_LINES_BOTH);
	return;
}

static inline int find_parent(GtkTreeStore * store, GtkTreeIter * parent, uint256_t * prev_hash, const struct utxo_data * udata) 
{
	gboolean ok = FALSE;
	do {
		if(!gtk_tree_store_iter_is_valid(store, parent)) break;
		uint256_t * p_hash = NULL;
		gtk_tree_model_get(GTK_TREE_MODEL(store), parent, UTXO_TREE_COLUMN_BLOCK_HASH, &p_hash, -1);
		assert(p_hash);
		if(memcmp(p_hash, prev_hash, sizeof(*prev_hash)) == 0 ) break;
	} while((ok = gtk_tree_model_iter_next(GTK_TREE_MODEL(store), parent)));
	
	if(!ok) {
		gtk_tree_store_append(store, parent, NULL);
		gtk_tree_store_set(store, parent, UTXO_TREE_COLUMN_BLOCK_HASH, (void *)&udata->utxo.block_hash, -1);
		memcpy(prev_hash, &udata->utxo.block_hash, sizeof(*prev_hash));
	}
	return 0;
}

static int update_utxo_tree(GtkWidget * treeview, shell_context_t * shell, ssize_t count, const struct utxo_data * utxoes) 
{
	int rc = 0;
	if(count <= 0) return -1;
	assert(utxoes);
	
	GtkTreeStore * store = GTK_TREE_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(treeview)));
	uint256_t prev_hash[1];
	//~ memcpy(prev_hash, &utxoes[0].utxo.block_hash, sizeof(prev_hash));
 
	GtkTreeIter parent, iter;
	gboolean ok = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &parent);
	
	for(ssize_t i = 0; i < count; ++i) 
	{
		rc = find_parent(store, &parent, prev_hash, &utxoes[i]);
		assert(0 == rc);
		
		gtk_tree_store_append(store, &iter, &parent);
		gtk_tree_store_set(store, &iter, UTXO_TREE_COLUMN_DATA_PTR, (void *)&utxoes[0], -1);
	}
	
	GtkTreePath * path = gtk_tree_model_get_path(GTK_TREE_MODEL(store), &parent);
	if(path) {
		gtk_tree_view_expand_row(GTK_TREE_VIEW(treeview), path, TRUE);
		gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW(treeview), path, 0, TRUE, 0, 0.5);
		
		gtk_tree_selection_select_path(gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview)), path);
		gtk_tree_path_free(path);
	}
	gtk_tree_view_set_model(GTK_TREE_VIEW(treeview), GTK_TREE_MODEL(store));
	return rc;
}

static int shell_add_utxo(shell_context_t * shell, const struct utxo_data * udata)
{
	debug_printf("add utxo: txid=(0x%.8x...), index=%d, block_hash=(0x%.8x...)",
		be32toh(*(uint32_t *)udata->outpoint.prev_hash),
		udata->outpoint.index,
		be32toh(*(uint32_t *)&udata->utxo.block_hash));
	struct utxo_data * utxoes = shell->utxoes;
	assert(utxoes);
	
	ssize_t cur_pos = shell->cur_pos++;
	if(shell->cur_pos >= shell->page_size) {
		shell->cur_pos = 0;
		++shell->start_index;
		if(shell->start_index >= shell->page_size) {
			shell->start_index = 0;
		}
	}
	
	memcpy(&utxoes[cur_pos], udata, sizeof(*udata));
	if(shell->count < shell->page_size) ++shell->count;
	
	return 0;
}


static int shell_update_utxo_tree(shell_context_t * shell, ssize_t pos, ssize_t count)
{
	assert(pos >= 0);
	if(count <= 0 || count > shell->count ) count = shell->count;
	if(count == 0) return -1;
	
	GtkWidget * treeview = shell->utxo_tree;
	struct utxo_data * utxoes = shell->utxoes;
	assert(utxoes);
	
	ssize_t length = shell->page_size - pos;
	assert(length > 0);
	if(length > count) length = count;
	
	update_utxo_tree(treeview, shell, length, &shell->utxoes[pos]);
	
	if(length < count) {
		update_utxo_tree(treeview, shell, (count - length), shell->utxoes);
	}
	
	return 0;
}

#define BUF_SIZE 4096
void shell_log_printf(shell_context_t * shell, const char * fmt, ...)
{
	GtkTextBuffer * buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(shell->logview));
	char sz_text[BUF_SIZE * 2 + 1] = "";
	ssize_t cb = 0;
	va_list args;
	va_start(args, fmt);
	cb = vsnprintf(sz_text, sizeof(sz_text), fmt, args);
	va_end(args);
	
	GtkTextIter iter;
	gtk_text_buffer_get_end_iter(buffer, &iter);
	gtk_text_buffer_insert(buffer, &iter, sz_text, cb);
	
	gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(shell->logview), &iter, 0, TRUE, 0, 1.0);
	
	return;
}

void shell_log_write(shell_context_t * shell, const char * prefix, const void * data, ssize_t length)
{
	char sz_text[BUF_SIZE * 2 + 1] = "";
	char * p_hex = sz_text;
	
	GtkTextBuffer * buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(shell->logview));
	GtkTextIter iter;
	gtk_text_buffer_get_end_iter(buffer, &iter);
	if(prefix) {
		gtk_text_buffer_insert(buffer, &iter, prefix, strlen(prefix));
	}
	
	ssize_t cb = 0;
	ssize_t cb_total = 0;
	const unsigned char * src = data;
	while(length > 0) {
		ssize_t size = (length < BUF_SIZE)?length:BUF_SIZE;
		cb = bin2hex(src, size, &p_hex);
		assert(cb > 0);
		
		length -= size;
		cb_total += cb;
		
		gtk_text_buffer_insert(buffer, &iter, sz_text, cb);
	}
	gtk_text_buffer_insert(buffer, &iter, "\r\n", 2);
	gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(shell->logview), &iter, 0, TRUE, 0, 1.0);
	
	guint msg_id = gtk_statusbar_get_context_id(GTK_STATUSBAR(shell->statusbar), "log");
	
	cb = snprintf(sz_text, sizeof(sz_text), "total length: %Zd", cb_total);
	gtk_statusbar_push(GTK_STATUSBAR(shell->statusbar), msg_id, sz_text);
	
	return;
}
#undef BUF_SIZE

/**
 * db manager
**/
db_manager_t * db_manager_new(const char * home_dir, void * user_data)
{
	db_manager_t * db_mgr = calloc(1, sizeof(*db_mgr));
	assert(db_mgr);
	db_mgr->user_data = user_data;
	db_mgr->db_home = home_dir;
	db_engine_t * engine = db_engine_init(NULL, home_dir, db_mgr);
	assert(engine);
	
	db_mgr->engine = engine;
	blocks_db_t * block_db = blocks_db_init(db_mgr->block_db, engine, "blocks", db_mgr);
	utxoes_db_t * utxo_db = utxoes_db_init(db_mgr->utxo_db, engine, "utxo", db_mgr); 
	assert(block_db && utxo_db);
	
	return db_mgr;
}
void db_manager_cleanup(db_manager_t * db_mgr)
{
	if(NULL == db_mgr) return;
	blocks_db_cleanup(db_mgr->block_db);
	utxoes_db_cleanup(db_mgr->utxo_db);
	db_engine_cleanup(db_mgr->engine);
	return;
}


/**
 * blockchain
**/
static int block_hash_compare(const void * a, const void * b) 
{
	return uint256_compare(a, b);
}

static int on_add_block(struct blockchain * chain, const uint256_t * hash, const int height, void * user_data)
{
	shell_context_t * shell = user_data;
	assert(shell);
	
	bitcoin_blockchain_t * bchain = shell->btc_chain;
	assert(bchain);
	
	struct avl_node * node = avl_tree_find(bchain->mem_db, hash, block_hash_compare);
	assert(node);
	
	struct memcache_block_info * binfo = (struct memcache_block_info *)node->key;
	assert(binfo && binfo->block);
	
	satoshi_block_t * block = binfo->block;
	db_engine_t * engine = bchain->db_mgr->engine;
	utxoes_db_t * utxo_db = bchain->db_mgr->utxo_db;
	assert(utxo_db);
	
	ssize_t txn_count = block->txn_count;
	ssize_t cur_pos = shell->cur_pos;
	ssize_t utxoes_count = 0;
	db_engine_txn_t * db_txn = engine->txn_new(engine, NULL);
	for(ssize_t i = 0; i < txn_count; ++i)
	{
		satoshi_tx_t * tx = &block->txns[i];
		int coinbase_flag = 0;
		if(i == 0) { // add coinbase tx
			
			struct satoshi_outpoint outpoint;
			satoshi_tx_t * tx = &block->txns[0];
			for(ssize_t ii = 0; ii < tx->txin_count; ++ii) {
				if(memcmp(tx->txins[ii].outpoint.prev_hash, uint256_zero, 32) == 0) {
					assert(coinbase_flag == 0);
					coinbase_flag = 1;
				}else utxo_db->remove(utxo_db, db_txn, &tx->txins[ii].outpoint);
			}
		}
		
		struct satoshi_outpoint outpoint;
		memcpy(outpoint.prev_hash, &tx->txid, 32);
		for(ssize_t ii = 0; ii < tx->txout_count; ++ii) {
			satoshi_txout_t * txout = &tx->txouts[ii];
			memcpy(&outpoint.prev_hash, tx->txid, 32);
			outpoint.index = (int32_t)ii;
			utxo_db->add(utxo_db, db_txn, &outpoint, txout, hash);
			
			struct utxo_data udata = {
				.outpoint = outpoint, 
				.utxo = {
					.value = txout->value,
					.block_hash = *hash,
				}
			};
			ssize_t cb_scripts = varstr_size(txout->scripts);
			assert(cb_scripts <= UTXOES_DB_MAX_SCRIPT_LENGTH);
			memcpy(udata.utxo.scripts, txout->scripts, cb_scripts);
			
			shell_log_printf(shell, "on_add_utxo: (%.8x...) - %.4d\n", 
				be32toh(*(uint32_t *)outpoint.prev_hash),
				outpoint.index);
			shell_log_write(shell, NULL, &udata, sizeof(udata));
			
			shell_add_utxo(shell, &udata);
			++utxoes_count;
		}
	}
	db_txn->commit(db_txn, 0);
	
	
	avl_tree_del(bchain->mem_db, hash, block_hash_compare);
	memcache_block_info_free(binfo);
	
	shell_update_utxo_tree(shell, cur_pos, utxoes_count);
	
	
	return 0;
}

static int on_remove_block(struct blockchain * chain, const uint256_t * hash, int height, void * user_data)
{
	shell_context_t * shell = user_data;
	assert(shell);
	
	fprintf(stderr, "remove block @(height=%d): ", height);
	dump2(stderr, hash, 32);
	fprintf(stderr, "\n");
	
	shell_stop(shell);
	return 0;
}

bitcoin_blockchain_t * bitcoin_blockchain_init(bitcoin_blockchain_t * bchain, void * user_data)
{
	if(NULL == bchain) bchain = calloc(1, sizeof(*bchain));
	assert(bchain);
	
	bchain->mem_db = avl_tree_init(NULL, bchain);
	bchain->user_data = user_data;
	bchain->chain = blockchain_init(NULL, NULL, NULL, user_data);
	
	blockchain_t * chain = bchain->chain;
	chain->on_add_block = on_add_block;
	chain->on_remove_block = on_remove_block;
	
	bchain->blocks_data_path = "blocks";
	bchain->file_index = -1;
	db_manager_t * db_mgr = db_manager_new("data", user_data);
	assert(db_mgr);
	bchain->db_mgr = db_mgr;
	return bchain;
}
void bitcoin_blockchain_cleanup(bitcoin_blockchain_t * bchain)
{
	if(NULL == bchain) return;
	
	if(bchain->fp) {
		fclose(bchain->fp);
		bchain->fp = NULL;
	}
	
	db_manager_cleanup(bchain->db_mgr);
	free(bchain->db_mgr);
	
	avl_tree_cleanup(bchain->mem_db);
	return;
}

/**
 * TEST
**/
struct block_file_header
{
	uint32_t magic;
	uint32_t length;
};

static int load_next_block(shell_context_t * shell) 
{
	bitcoin_blockchain_t * bchain = shell->btc_chain;
	db_manager_t * db_mgr = bchain->db_mgr;
	const char * blocks_data_path = bchain->blocks_data_path;
	assert(blocks_data_path && blocks_data_path[0]);
	
	char path_name[4096] = "";
	
	FILE * fp = bchain->fp;
	if(NULL == fp) {
		if(bchain->file_index >= 0) return -1;
		
		++bchain->file_index;
		snprintf(path_name, sizeof(path_name), "%s/blk%.5d.dat", blocks_data_path, bchain->file_index);
		fp = fopen(path_name, "rb");
		if(NULL == fp) return -1;
		
		bchain->fp = fp;
		bchain->offset = 0;
	}
	
	assert(fp);
	struct block_file_header file_hdr[1];
	ssize_t cb = 0;
	
	cb = fread(file_hdr, sizeof(file_hdr), 1, fp);
	if(cb < 1) {
		fclose(fp);
		bchain->fp = NULL;
		return load_next_block(shell);
	}
	bchain->offset += sizeof(file_hdr);
	assert(file_hdr->length > 0);
	
	unsigned char * buf = malloc(file_hdr->length);
	assert(buf);
	cb = fread(buf, 1, file_hdr->length, fp);
	if(cb < (ssize_t)file_hdr->length) {
		fclose(fp);
		bchain->fp = NULL;
		return -1;
	}
	satoshi_block_t * block = calloc(1, sizeof(*block));
	cb = satoshi_block_parse(block, file_hdr->length, buf);
	free(buf);
	assert(cb == file_hdr->length);
	
	memcache_block_info_t * binfo = memcache_block_info_new(&block->hash, &block->hdr, 
		bchain->file_index, bchain->offset, 
		block); 
	avl_tree_add(bchain->mem_db, binfo, memcache_block_info_compare);
	bchain->offset += cb;
	
	enum blockchain_error err_code = bchain->chain->add(bchain->chain, &binfo->hash, &binfo->data.hdr);
	assert(err_code != blockchain_error_failed);
	
	return 0;
} 
