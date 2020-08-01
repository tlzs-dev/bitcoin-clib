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
#include <ctype.h>

#include <json-c/json.h>

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

#ifndef _UTXOES_DB_H_

#define UTXOES_DB_MAX_SCRIPT_LENGTH	(80)	// only scripts with a length less than 80 bytes are included in the db
typedef struct db_record_utxo db_record_utxo_t;
struct db_record_utxo
{
	int64_t value;
	uint8_t scripts[UTXOES_DB_MAX_SCRIPT_LENGTH];
	uint256_t block_hash;
	uint16_t is_witness;
	uint16_t p2sh_flags;	// p2sh to p2wpkh or p2wsh
}__attribute__((packed));

#endif


enum {
	BLOCKS_COLUMN_HEIGHT,
	BLOCKS_COLUMN_HASH,
	BLOCKS_COLUMN_HDR,
	BLOCKS_COLUMN_DATA_PTR,
	
	BLOCKS_COLUMNS_COUNT,
};
static const char * s_blocks_colnames[BLOCKS_COLUMNS_COUNT] = {
	"height",
	"hash",
	"hdr",
};

static inline int blocks_colname_to_col_id(const char * col_name) {
	if(NULL == col_name) return -1;
	for(int i = 0; i < BLOCKS_COLUMNS_COUNT; ++i) {
		if(NULL == s_blocks_colnames[i]) return -1;
		if(strcmp(col_name, s_blocks_colnames[i]) == 0) return i;
	}
	return -1;
}

enum {
	UTXOES_COLUMN_OUTPOINT,
	UTXOES_COLUMN_VALUE,
	UTXOES_COLUMN_SCRIPTS,
	UTXOES_COLUMN_BLOCK_HASH,
	UTXOES_COLUMN_DATA_PTR,
	UTXOES_COLUMN_INDEX,
	UTXOES_COLUMNS_COUNT,
	
};
static const char * s_utxoes_colnames[UTXOES_COLUMNS_COUNT] = {
	"outpoint",
	"value",
	"scripts",
	"block_hash",
};

static inline int utxoes_colname_to_col_id(const char * col_name) {
	if(NULL == col_name) return -1;
	for(int i = 0; i < UTXOES_COLUMNS_COUNT; ++i) {
		if(NULL == s_utxoes_colnames[i]) return -1;
		if(strcmp(col_name, s_utxoes_colnames[i]) == 0) return i;
	}
	return -1;
}

typedef struct shell_private
{
	shell_context_t * shell;
	json_object * jconfig;
	char * working_path;
	
	GtkWidget * window;
	GtkWidget * header_bar;
	GtkWidget * stack;
	union {
		GtkWidget * treeview[2];
		struct {
			GtkWidget * blocks_tree;
			GtkWidget * utxoes_tree;
		};
	};
	const char * tree_names[2];
	
	GtkWidget * search_entry;
	GtkWidget * vte;	// pseudo-terminal
	
	int page_size;		// default: 1000 records per page
	int blocks_page;	// page index
	int blocks_pages_count;
	uint256_t * hashes;
	struct db_record_block * blocks;
	
	struct satoshi_outpoint * outpoints;
	struct db_record_utxo * utxoes;
	
	int utxoes_page;	// page index
	int utxoes_pages_count;
	
	guint timer_id;
	double fps;
	
	int quit;
	int is_running;
	
	/**
	 * Context Menu
	 */
	GtkWidget * context_menu;
	GtkTreePath * tree_path;
	GtkWidget * target_treeview;
	int col_id;
	
}shell_private_t;

shell_private_t * shell_private_new(shell_context_t * shell) 
{
	shell_private_t * priv = calloc(1, sizeof(*priv));
	priv->shell = shell;
	shell->priv = priv;
	priv->fps = 5;
	priv->page_size = 100;
	
	priv->hashes = calloc(priv->page_size, sizeof(*priv->hashes));
	priv->blocks = calloc(priv->page_size, sizeof(*priv->blocks));
	
	priv->outpoints = calloc(priv->page_size, sizeof(*priv->outpoints));
	priv->utxoes = calloc(priv->page_size, sizeof(*priv->utxoes));
	
	priv->tree_names[0] = "blocks";
	priv->tree_names[1] = "utxoes";
	
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
static void on_stack_visiable_child_changed(GObject * stack, GParamSpec * spec, shell_private_t * priv);
static void move_first(GtkWidget * button, shell_private_t * priv);
static void move_prev(GtkWidget * button, shell_private_t * priv);
static void move_next(GtkWidget * button, shell_private_t * priv);
static void move_last(GtkWidget * button, shell_private_t * priv);
static void move_to(GtkWidget * button, shell_private_t * priv);


struct context_menu_data
{
	shell_private_t * priv;
	GtkWidget * treeview;
	GdkEventButton * event;
	GtkTreeModel * model;
	GtkTreePath * path;
	const char * col_name;
};

static void on_copy_column(GtkMenuItem * menu_item, shell_private_t * priv)
{
	assert(priv);
	GtkWidget * treeview = priv->target_treeview;
	GtkTreePath * path = priv->tree_path;
	assert(path && treeview);
	
	int col_index = priv->col_id;
	assert(col_index >= 0 && col_index < BLOCKS_COLUMNS_COUNT);
	
	char sz_text[4096] = "";
	json_object * jobj = json_object_new_object();
	
	char * p_hex = sz_text;
	ssize_t cb = -1;
	
	GtkTreeIter iter;
	GtkTreeModel * model = gtk_tree_view_get_model(GTK_TREE_VIEW(treeview));
		
	gboolean ok = FALSE;
	ok = gtk_tree_model_get_iter(model, &iter, path);
	assert(ok);

	if(treeview == priv->blocks_tree) 
	{
		gint height = -1;
		struct db_record_block * block = NULL;
		unsigned char * hash = NULL;
		json_object_object_add(jobj, "type", json_object_new_string("blocks::column"));
		
		gtk_tree_model_get(model, &iter, 
			BLOCKS_COLUMN_HEIGHT, &height,
			BLOCKS_COLUMN_HASH, &hash,
			BLOCKS_COLUMN_DATA_PTR, &block,
			-1
			);
		assert(block && height >= 0);
		
		switch(col_index)
		{
		case BLOCKS_COLUMN_HEIGHT: 
			json_object_object_add(jobj, "height", json_object_new_int(height)); 
			break;
		case BLOCKS_COLUMN_HASH:
			assert(hash);
			cb = bin2hex(hash, 32, &p_hex);
			json_object_object_add(jobj, "hash", json_object_new_string(sz_text));
			break;
		case BLOCKS_COLUMN_HDR:
			assert(hash);
			cb = bin2hex(&block->hdr, sizeof(block->hdr), &p_hex);
			json_object_object_add(jobj, "hdr", json_object_new_string(sz_text));
			break;
		default:
			break;
		}
	}else if(treeview == priv->utxoes_tree)
	{
		struct satoshi_outpoint * outpoint = NULL;
		struct db_record_utxo * utxo = NULL;
		
		gtk_tree_model_get(model, &iter, 
			UTXOES_COLUMN_OUTPOINT, &outpoint,
			UTXOES_COLUMN_DATA_PTR, &utxo,
			-1
			);
		assert(outpoint && utxo);
		json_object_object_add(jobj, "type", json_object_new_string("utxoes::column"));
		
		switch(col_index)
		{
		case UTXOES_COLUMN_OUTPOINT: 
			assert(outpoint);
			cb = bin2hex(outpoint, sizeof(*outpoint), &p_hex);
			json_object_object_add(jobj, "outpoint", json_object_new_string(sz_text));
			assert(cb > 0);
			break;
		case UTXOES_COLUMN_VALUE:
			assert(utxo);
			json_object_object_add(jobj, "value", json_object_new_int64(utxo->value));
			break;
		case UTXOES_COLUMN_SCRIPTS:
			assert(utxo);
			cb = bin2hex(&utxo->scripts, utxo->scripts[0] + 1, &p_hex);
			json_object_object_add(jobj, "scripts", json_object_new_string(sz_text));
			break;
		case UTXOES_COLUMN_BLOCK_HASH: 
			assert(utxo);
			cb = bin2hex(&utxo->block_hash, sizeof(utxo->block_hash), &p_hex);
			json_object_object_add(jobj, "block_hash", json_object_new_string(sz_text));
			break;
		default:
			break;
		}
	}
	
	GtkClipboard * clipboard = gtk_clipboard_get_for_display(
		gtk_widget_get_display(treeview), 
		GDK_SELECTION_CLIPBOARD);
	
	const char * output = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN);
	gtk_clipboard_set_text(clipboard, output, strlen(output));
	json_object_put(jobj);
	
	return;
	
}

static void on_copy_row(GtkMenuItem * menu_item, shell_private_t * priv)
{
	assert(priv);
	GtkWidget * treeview = priv->target_treeview;
	GtkTreePath * path = priv->tree_path;
	assert(path && treeview);
	
	char sz_text[4096] = "";
	json_object * jobj = json_object_new_object();
	
	char * p_hex = sz_text;
	ssize_t cb = -1;
	
	GtkTreeIter iter;
	GtkTreeModel * model = gtk_tree_view_get_model(GTK_TREE_VIEW(treeview));
		
	gboolean ok = FALSE;
	ok = gtk_tree_model_get_iter(model, &iter, path);
	assert(ok);
	
	if(treeview == priv->blocks_tree) 
	{
		gint height = -1;
		struct db_record_block * block = NULL;
		
		gtk_tree_model_get(model, &iter, 
			BLOCKS_COLUMN_HEIGHT, &height,
			BLOCKS_COLUMN_DATA_PTR, &block,
			-1
			);
		assert(block && height >= 0);
		json_object_object_add(jobj, "type", json_object_new_string("blocks::row"));
		json_object_object_add(jobj, "height", json_object_new_int(height));
		cb = bin2hex(block, sizeof(*block), &p_hex);
		assert(cb > 0);
		json_object_object_add(jobj, "block", json_object_new_string(sz_text));
		
	}else if(treeview == priv->utxoes_tree)
	{
		struct satoshi_outpoint * outpoint = NULL;
		struct db_record_utxo * utxo = NULL;
		
		gtk_tree_model_get(model, &iter, 
			UTXOES_COLUMN_OUTPOINT, &outpoint,
			UTXOES_COLUMN_DATA_PTR, &utxo,
			-1
			);
		assert(outpoint && utxo);
		
		json_object_object_add(jobj, "type", json_object_new_string("utxoes::row"));
		
		char * p_hex = sz_text;
		ssize_t cb = bin2hex(outpoint, sizeof(*outpoint), &p_hex);
		assert(cb > 0);
		json_object_object_add(jobj, "outpoint", json_object_new_string(sz_text));
		
		
		cb = bin2hex(utxo, sizeof(*utxo), &p_hex);
		assert(cb > 0);
		json_object_object_add(jobj, "utxo", json_object_new_string(sz_text));
	}
	
	
	GtkClipboard * clipboard = gtk_clipboard_get_for_display(
		gtk_widget_get_display(treeview), 
		GDK_SELECTION_CLIPBOARD);
	
	const char * output = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN);
	gtk_clipboard_set_text(clipboard, output, strlen(output));
	json_object_put(jobj);
	
	return;
	
}

static void popup_menu(GtkWidget * treeview, GdkEventButton * event, shell_private_t * priv)
{
	/**
	 * prepares data for context_menu action
	 */
	GtkTreePath * path = NULL;
	GtkTreeViewColumn * col = NULL;
	gboolean ok = gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(treeview), 
		event->x, event->y,
		&path, &col, NULL, NULL);
	if(ok && path) {
		GtkTreeSelection * selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));
		gtk_tree_selection_unselect_all(selection);
        gtk_tree_selection_select_path(selection, path);
		
	}
	priv->target_treeview = treeview;
	if(priv->tree_path) gtk_tree_path_free(priv->tree_path);
	priv->tree_path = path;
	if(col) {
		const char * col_name = gtk_tree_view_column_get_title(col);
		if(treeview == priv->blocks_tree) priv->col_id = blocks_colname_to_col_id(col_name);
		else priv->col_id = utxoes_colname_to_col_id(col_name);
	}
	
	// show context_menu
	gtk_menu_popup_at_pointer(GTK_MENU(priv->context_menu), (GdkEvent *)event);
	return;

}
static gboolean on_tree_view_button_pressed(GtkWidget * treeview, GdkEventButton * event, shell_private_t * priv)
{
	if(event->type != GDK_BUTTON_PRESS) return FALSE;
	if(event->button != 3) return FALSE;
	
	popup_menu(treeview, event, priv);
	return FALSE;
}

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
	gtk_grid_attach(GTK_GRID(grid), vpaned, 0, 0, 3, 1);
	
	GtkWidget * stack = gtk_stack_new();
	gtk_paned_add1(GTK_PANED(hpaned), stack);
	
	GtkWidget * stack_switcher = gtk_stack_switcher_new();
	gtk_stack_switcher_set_stack(GTK_STACK_SWITCHER(stack_switcher), GTK_STACK(stack));
	//~ gtk_grid_attach(GTK_GRID(grid), stack_switcher, 0, 0, 3, 1);
	gtk_header_bar_pack_start(GTK_HEADER_BAR(header_bar), stack_switcher);

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
	priv->stack = stack;
	
	static const char css_data[] = 
	//	"treeview.view { background-image: -gtk-gradient(linear, left top, left bottom, from(#654ea3), color-stop (0.5, darker(#654ea3)), to (#eaafc8)); }\n"
		"treeview.view { background-image: -gtk-gradient(linear, left top, left bottom, from(#3c3b3f), to (#605c3c)); }\n"
		"treeview:hover { background-color: cyan; } \n"
		"treeview.view button { background-color: silver; color: black;} \n"
		"treeview:selected { color: yellow; } \n"
		"treeview header { background-color: gray; } \n"
		"";
	
	GError * gerr = NULL;
	GtkCssProvider * css = gtk_css_provider_new();
	gboolean ok = gtk_css_provider_load_from_data(css, css_data, sizeof(css_data) - 1, &gerr);
	if(gerr) {
		fprintf(stderr, "%s\n", gerr->message);
		
	}
	assert(ok && !gerr);
	
	gtk_style_context_add_provider_for_screen(gtk_window_get_screen(GTK_WINDOW(window)), 
		GTK_STYLE_PROVIDER(css), 
		GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
		
	GtkWidget * treeview = NULL;
	
	treeview = gtk_tree_view_new();
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(scrolled_win), treeview);
	gtk_widget_set_hexpand(scrolled_win, TRUE);
	gtk_widget_set_vexpand(scrolled_win, TRUE);
	gtk_stack_add_titled(GTK_STACK(stack), scrolled_win, priv->tree_names[0], "blocks_db");
	priv->blocks_tree = treeview;
	init_blocks_treeview(GTK_TREE_VIEW(treeview));
	g_signal_connect(treeview, "button-press-event", G_CALLBACK(on_tree_view_button_pressed), priv);
	

	treeview = gtk_tree_view_new();
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(scrolled_win), treeview);
	gtk_widget_set_hexpand(scrolled_win, TRUE);
	gtk_widget_set_vexpand(scrolled_win, TRUE);
	gtk_stack_add_titled(GTK_STACK(stack), scrolled_win, priv->tree_names[1], "utxoes_db");
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_win), GTK_SHADOW_ETCHED_IN);
	priv->utxoes_tree = treeview;
	init_utxoes_treeview(GTK_TREE_VIEW(treeview));
	g_signal_connect(treeview, "button-press-event", G_CALLBACK(on_tree_view_button_pressed), priv);
	
	g_signal_connect(stack, "notify::visible-child", G_CALLBACK(on_stack_visiable_child_changed), priv);
	
	// navigation bar
	GtkWidget * nav_bar = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);
	GtkWidget * go_first = gtk_button_new_from_icon_name("go-first", GTK_ICON_SIZE_BUTTON);
	GtkWidget * go_previous = gtk_button_new_from_icon_name("go-previous", GTK_ICON_SIZE_BUTTON);
	GtkWidget * go_next = gtk_button_new_from_icon_name("go-next", GTK_ICON_SIZE_BUTTON);
	GtkWidget * go_last = gtk_button_new_from_icon_name("go-last", GTK_ICON_SIZE_BUTTON);
	GtkWidget * go_jump = gtk_button_new_from_icon_name("go-jump", GTK_ICON_SIZE_BUTTON);
	
	gtk_container_add(GTK_CONTAINER(nav_bar), go_first);
	gtk_container_add(GTK_CONTAINER(nav_bar), go_previous);
	gtk_container_add(GTK_CONTAINER(nav_bar), go_next);
	gtk_container_add(GTK_CONTAINER(nav_bar), go_last);
	
	gtk_grid_attach(GTK_GRID(grid), nav_bar, 0, 1, 1, 1);
	GtkWidget * search_entry = gtk_entry_new();
	gtk_widget_set_hexpand(search_entry, TRUE);
	gtk_grid_attach(GTK_GRID(grid), search_entry, 1, 1, 1, 1);
	gtk_grid_attach(GTK_GRID(grid), go_jump, 2, 1, 1, 1);
	
	priv->search_entry = search_entry;
	
	g_signal_connect(go_first, "clicked", G_CALLBACK(move_first), priv);
	g_signal_connect(go_previous, "clicked", G_CALLBACK(move_prev), priv);
	g_signal_connect(go_next, "clicked", G_CALLBACK(move_next), priv);
	g_signal_connect(go_last, "clicked", G_CALLBACK(move_last), priv);
	g_signal_connect(go_jump, "clicked", G_CALLBACK(move_to), priv);
	
	g_signal_connect(search_entry, "activate", G_CALLBACK(move_to), priv);
	
	
	GtkWidget * menu = NULL, *menu_item = NULL;
	menu = gtk_menu_new();
	menu_item = gtk_menu_item_new_with_mnemonic("Copy _Column");	
	g_signal_connect(menu_item, "activate", G_CALLBACK(on_copy_column), priv);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menu_item);
	
	menu_item = gtk_menu_item_new_with_mnemonic("Copy _Row");	
	g_signal_connect(menu_item, "activate", G_CALLBACK(on_copy_row), priv);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menu_item);
	gtk_widget_show_all(menu);
	priv->context_menu = menu;
	
	g_signal_connect_swapped(window, "destroy", G_CALLBACK(shell->stop), shell); 
	gtk_widget_show_all(window);
	return;
}

static void on_stack_visiable_child_changed(GObject * stack, GParamSpec * spec, shell_private_t * priv)
{
	if(gtk_widget_in_destruction(GTK_WIDGET(stack))) return;
	const char * title = gtk_stack_get_visible_child_name(GTK_STACK(stack));
	if(title) {
		gtk_header_bar_set_subtitle(GTK_HEADER_BAR(priv->header_bar), title);
	}
	return;
}

enum db_cursor_move_direction 
{
	db_cursor_move_direction_first,
	db_cursor_move_direction_prev,
	db_cursor_move_direction_next,
	db_cursor_move_direction_last,
	db_cursor_move_direction_goto,
};
int load_blocks(GtkTreeView * tree, db_manager_t * db_mgr, shell_private_t * priv, enum db_cursor_move_direction direction);
int load_utxoes(GtkTreeView * tree, db_manager_t * db_mgr, shell_private_t * priv, enum db_cursor_move_direction direction);

static int load_data(shell_context_t * shell)
{
	assert(shell && shell->priv);
	shell_private_t * priv = shell->priv;
	
	db_manager_t * db_mgr = shell->user_data;
	assert(db_mgr);
	
	load_blocks(GTK_TREE_VIEW(priv->blocks_tree), db_mgr, priv, db_cursor_move_direction_first);
	load_utxoes(GTK_TREE_VIEW(priv->utxoes_tree), db_mgr, priv, db_cursor_move_direction_first);
	
	return 0;
}

/**************************************************************
 * BLOCKS DB
 *************************************************************/

static void on_set_block_height(GtkTreeViewColumn *col,
	GtkCellRenderer *cell,
	GtkTreeModel *tree_model,
	GtkTreeIter *iter,
	gpointer data);
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
	GtkTreeSelection * selection = gtk_tree_view_get_selection(tree);
	
	GtkCellRenderer * cr = gtk_cell_renderer_text_new();
	GtkTreeViewColumn * col = gtk_tree_view_column_new_with_attributes(
		s_blocks_colnames[BLOCKS_COLUMN_HEIGHT],  cr, 
		"text", BLOCKS_COLUMN_HEIGHT,
		NULL);
	gtk_tree_view_append_column(tree, col);
	gtk_tree_view_column_set_resizable(col, TRUE);
	gtk_tree_view_column_set_cell_data_func(col, cr, on_set_block_height, selection, NULL);
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes(
		s_blocks_colnames[BLOCKS_COLUMN_HASH],  cr, 
		NULL);
	gtk_tree_view_append_column(tree, col);
	gtk_tree_view_column_set_cell_data_func(col, cr, on_set_block_hash, selection, NULL);
	gtk_tree_view_column_set_resizable(col, TRUE);
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes(
		s_blocks_colnames[BLOCKS_COLUMN_HDR],  cr, 
		NULL);
	gtk_tree_view_append_column(tree, col);
	gtk_tree_view_column_set_cell_data_func(col, cr, on_set_block_hdr, selection, NULL);
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


static void on_set_block_height(GtkTreeViewColumn *col,
	GtkCellRenderer *cr,
	GtkTreeModel *model,
	GtkTreeIter *iter,
	gpointer user_data)
{
	struct db_record_block * block = NULL;
	
	GtkTreeSelection * selection = user_data;
	gboolean is_selected = gtk_tree_selection_iter_is_selected(selection, iter);
	
	gint height = -1;
	gtk_tree_model_get(model, iter, 
		BLOCKS_COLUMN_HEIGHT, &height,
		BLOCKS_COLUMN_DATA_PTR, &block,
		-1);
	if(height >= 0 && block) {
		char sz_height[100] = "";
		snprintf(sz_height, sizeof(sz_height), "%d", height);

		if(!is_selected) {
			g_object_set(cr, "text", sz_height, 
				"alignment", PANGO_ALIGN_CENTER,
				"background", (block->height % 2)?"lightgray":"white",
				"family", "Monospace",
				NULL);
		}else {
			g_object_set(cr, "text", sz_height, NULL);
		}
	}
	return;
}

static void on_set_block_hash(GtkTreeViewColumn *col,
	GtkCellRenderer *cr,
	GtkTreeModel *model,
	GtkTreeIter *iter,
	gpointer user_data)
{
	unsigned char * hash = NULL;
	struct db_record_block * block = NULL;
	
	GtkTreeSelection * selection = user_data;
	gboolean is_selected = gtk_tree_selection_iter_is_selected(selection, iter);
	
	
	gtk_tree_model_get(model, iter, 
		BLOCKS_COLUMN_HASH, &hash, 
		BLOCKS_COLUMN_DATA_PTR, &block,
		-1);
	if(hash && block) {
		char * hex = NULL;
		ssize_t cb = bin2hex(hash, 32, &hex);
		assert(cb == 64 && hex);
		
		strcpy(hex + 8, "...");	// display the first 4 bytes only
		
		if(!is_selected) {
			g_object_set(cr, "text", hex, 
				"background", (block->height % 2)?"lightgray":"white",
				"family", "Monospace",
				NULL);
		}else {
			g_object_set(cr, "text", hex, NULL);
		}
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
	struct db_record_block * block = NULL;
	gtk_tree_model_get(model, iter, BLOCKS_COLUMN_DATA_PTR, &block, -1);
	if(block) {
		char buffer[4096] = "";
		snprintf(buffer, sizeof(buffer), 
			"version: %d, prev_hash: 0x%.8x..., merkle_root: 0x%.8x...",
			block->hdr.version, 
			be32toh(*(uint32_t *)block->hdr.prev_hash),
			be32toh(*(uint32_t *)block->hdr.merkle_root));
		g_object_set(cr, 
			"text", buffer, 
			"background", (block->height % 2)?"lightgray":"white",
			"family", "Monospace",
			NULL);
	}
	
	return;
}

int load_blocks(GtkTreeView * tree, db_manager_t * db_mgr, shell_private_t * priv, enum db_cursor_move_direction direction)
{
	GtkWidget * search_entry = priv->search_entry;
	int32_t height = -1;
	int rc = 0;
	
	if(direction == db_cursor_move_direction_goto)
	{
		const char * sz_height = gtk_entry_get_text(GTK_ENTRY(search_entry));
		if(NULL == sz_height || !sz_height[0] || !isdigit(sz_height[0])) return -1;
		height = atoi(sz_height);
		if(height < 0) return -1;
		
		gtk_entry_set_text(GTK_ENTRY(search_entry), "");	// clean text
		
	}
	
	GtkListStore * store = gtk_list_store_new(BLOCKS_COLUMNS_COUNT, 
		G_TYPE_INT, 
		G_TYPE_POINTER,
		G_TYPE_POINTER,
		G_TYPE_POINTER);
	GtkTreeIter iter;
	
	int count = 0;
	db_cursor_t * cursor = db_mgr->blocks_cursor;
	if(NULL == cursor) {
		cursor = db_cursor_init(NULL, db_mgr->heights_db, NULL, 0);
		assert(cursor);
		db_mgr->blocks_cursor = cursor;
	}
	cursor->skey->data = &height;
	cursor->skey->size = sizeof(height);
	
	cursor->key->data = &priv->hashes[0];
	cursor->key->size = sizeof(priv->hashes[0]);
	
	cursor->value->data = &priv->blocks[0];
	cursor->value->size = sizeof(priv->blocks[0]);

	switch(direction) 
	{
		case db_cursor_move_direction_first:
		case db_cursor_move_direction_last:
		case db_cursor_move_direction_goto:
			if(direction == db_cursor_move_direction_first) {
				rc =cursor->first(cursor);
				gtk_list_store_insert_after(store, &iter, NULL);
			}else if (direction == db_cursor_move_direction_last) {
				rc =cursor->last(cursor);
				gtk_list_store_insert_before(store, &iter, NULL);
			}else {
				rc = cursor->move_to(cursor, cursor->skey);
				gtk_list_store_insert_after(store, &iter, NULL);
			}
			
			if(rc) {
				g_object_unref(store);
				return -1;
			}
			gtk_list_store_set(store, &iter, 
				BLOCKS_COLUMN_HEIGHT, height,
				BLOCKS_COLUMN_HASH, &priv->hashes[0],
				BLOCKS_COLUMN_HDR, &priv->blocks[0].hdr,
				BLOCKS_COLUMN_DATA_PTR, &priv->blocks[0],
				-1);
			++count;
			break;
		
		default:
			break;
	}
	
	if(direction == db_cursor_move_direction_last || direction == db_cursor_move_direction_prev)
	{
		for(; count < priv->page_size; ++count) {
			
			cursor->key->data = &priv->hashes[count];
			cursor->key->size = sizeof(priv->hashes[0]);
			
			cursor->value->data = &priv->blocks[count];
			cursor->value->size = sizeof(priv->blocks[0]);
			
			rc = cursor->prev(cursor);
			if(rc) break;

			gtk_list_store_prepend(store, &iter);
			gtk_list_store_set(store, &iter, 
				BLOCKS_COLUMN_HEIGHT, height,
				BLOCKS_COLUMN_HASH, &priv->hashes[count],
				BLOCKS_COLUMN_HDR, &priv->blocks[count].hdr,
				BLOCKS_COLUMN_DATA_PTR, &priv->blocks[count],
				-1);
		}
	}else {
		for(; count < priv->page_size; ++count) {
			
			cursor->key->data = &priv->hashes[count];
			cursor->key->size = sizeof(priv->hashes[0]);
			
			cursor->value->data = &priv->blocks[count];
			cursor->value->size = sizeof(priv->blocks[0]);
			
			rc = cursor->next(cursor);
			if(rc) break;

			gtk_list_store_append(store, &iter);
			gtk_list_store_set(store, &iter, 
				BLOCKS_COLUMN_HEIGHT, height,
				BLOCKS_COLUMN_HASH, &priv->hashes[count],
				BLOCKS_COLUMN_HDR, &priv->blocks[count].hdr,
				BLOCKS_COLUMN_DATA_PTR, &priv->blocks[count],
				-1);
		}
	}
	
	gtk_tree_view_set_model(tree, GTK_TREE_MODEL(store));
	return 0;
}

/**************************************************************
 * UTXOES DB
 *************************************************************/



static void on_set_utxo_outpoint(GtkTreeViewColumn *col,
	GtkCellRenderer *cr,
	GtkTreeModel *model,
	GtkTreeIter *iter,
	gpointer user_data)
{
	struct satoshi_outpoint * outpoint = NULL;
	gint index = -1;
	
	GtkTreeSelection * selection = user_data;
	gboolean is_selected = gtk_tree_selection_iter_is_selected(selection, iter);

	gtk_tree_model_get(model, iter, 
		UTXOES_COLUMN_OUTPOINT, &outpoint,
		UTXOES_COLUMN_INDEX, &index,
		-1);
	if(outpoint){
		char sz_text[100] = "";
		snprintf(sz_text, sizeof(sz_text), "[%.8x...](%d)", 
			be32toh(*(uint32_t *)outpoint->prev_hash),
			outpoint->index);

		if(!is_selected) {
			g_object_set(cr, "text", sz_text, 
				"family", "Monospace",
				"background", (index % 2)?"lightgray":"white",
				NULL);
		}else {
			g_object_set(cr, "text", sz_text, NULL);
		}
	}
	return;
}

#include <inttypes.h>
static void on_set_utxo_value(GtkTreeViewColumn *col,
	GtkCellRenderer *cr,
	GtkTreeModel *model,
	GtkTreeIter *iter,
	gpointer user_data)
{
	gint64 value = -1;
	gint index = -1;
	
	GtkTreeSelection * selection = user_data;
	gboolean is_selected = gtk_tree_selection_iter_is_selected(selection, iter);

	gtk_tree_model_get(model, iter, 
		UTXOES_COLUMN_VALUE, &value,
		UTXOES_COLUMN_INDEX, &index,
		-1);
	if(index >= 0){
		char sz_text[100] = "";
		snprintf(sz_text, sizeof(sz_text), "%" PRIi64 "(0x%.16" PRIx64 ")", 
			value, value);

		if(!is_selected) {
			g_object_set(cr, "text", sz_text, 
				"family", "Monospace",
				"background", (index % 2)?"lightgray":"white",
				NULL);
		}else {
			g_object_set(cr, "text", sz_text, NULL);
		}
	}
	return;
}

static void on_set_utxo_scripts(GtkTreeViewColumn *col,
	GtkCellRenderer *cr,
	GtkTreeModel *model,
	GtkTreeIter *iter,
	gpointer user_data)
{
	unsigned char * vscripts;
	gint index = -1;
	
	GtkTreeSelection * selection = user_data;
	gboolean is_selected = gtk_tree_selection_iter_is_selected(selection, iter);

	gtk_tree_model_get(model, iter, 
		UTXOES_COLUMN_SCRIPTS, &vscripts,
		UTXOES_COLUMN_INDEX, &index,
		-1);
	if(index >= 0){
		char * sz_text = NULL;
		ssize_t cb_scripts = vscripts[0] + 1;
		ssize_t cb = bin2hex(vscripts, cb_scripts, &sz_text);
		assert(sz_text && cb > 0);
		
		if(!is_selected) {
			g_object_set(cr, "text", sz_text, 
				"family", "Monospace",
				"background", (index % 2)?"lightgray":"white",
				NULL);
		}else {
			g_object_set(cr, "text", sz_text, NULL);
		}
		free(sz_text);
	}
	return;
}

static void on_set_utxo_block_hash(GtkTreeViewColumn *col,
	GtkCellRenderer *cr,
	GtkTreeModel *model,
	GtkTreeIter *iter,
	gpointer user_data)
{
	unsigned char * hash = NULL;
	gint index = -1;
	
	GtkTreeSelection * selection = user_data;
	gboolean is_selected = gtk_tree_selection_iter_is_selected(selection, iter);

	gtk_tree_model_get(model, iter, 
		UTXOES_COLUMN_BLOCK_HASH, &hash,
		UTXOES_COLUMN_INDEX, &index,
		-1);
	assert(hash);
	if(index >= 0){
		char * sz_text = NULL;
		ssize_t cb = bin2hex(hash, 32, &sz_text);
		assert(sz_text && cb > 0);
		
		if(!is_selected) {
			g_object_set(cr, "text", sz_text, 
				"family", "Monospace",
				"background", (index % 2)?"lightgray":"white",
				NULL);
		}else {
			g_object_set(cr, "text", sz_text, NULL);
		}
		free(sz_text);
	}
	return;
}

static void init_utxoes_treeview(GtkTreeView * tree)
{
	GtkTreeSelection * selection = gtk_tree_view_get_selection(tree);
	GtkCellRenderer * cr = NULL;
	GtkTreeViewColumn * col = NULL;
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes(
		s_utxoes_colnames[UTXOES_COLUMN_OUTPOINT],  cr, 
		NULL);
	gtk_tree_view_append_column(tree, col);
	gtk_tree_view_column_set_resizable(col, TRUE);
	gtk_tree_view_column_set_cell_data_func(col, cr, on_set_utxo_outpoint, selection, NULL);
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes(
		s_utxoes_colnames[UTXOES_COLUMN_VALUE],  cr, 
		NULL);
	gtk_tree_view_append_column(tree, col);
	gtk_tree_view_column_set_cell_data_func(col, cr, on_set_utxo_value, selection, NULL);
	gtk_tree_view_column_set_resizable(col, TRUE);
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes(
		s_utxoes_colnames[UTXOES_COLUMN_SCRIPTS],  cr, 
		NULL);
	gtk_tree_view_append_column(tree, col);
	gtk_tree_view_column_set_cell_data_func(col, cr, on_set_utxo_scripts, selection, NULL);
	gtk_tree_view_column_set_resizable(col, TRUE);
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes(
		s_utxoes_colnames[UTXOES_COLUMN_BLOCK_HASH],  cr,  
		NULL);
	gtk_tree_view_append_column(tree, col);
	gtk_tree_view_column_set_resizable(col, TRUE);
	gtk_tree_view_column_set_cell_data_func(col, cr, on_set_utxo_block_hash, selection, NULL);
	
	
	GtkListStore * store = gtk_list_store_new(UTXOES_COLUMNS_COUNT, 
		G_TYPE_POINTER,
		G_TYPE_INT64, 
		G_TYPE_POINTER,
		G_TYPE_POINTER,
		G_TYPE_POINTER,
		G_TYPE_INT
		);
	gtk_tree_view_set_model(tree, GTK_TREE_MODEL(store));
	
	gtk_tree_view_set_grid_lines(tree, GTK_TREE_VIEW_GRID_LINES_BOTH);
	gtk_widget_set_size_request(GTK_WIDGET(tree), 300, 200);
	return;
}


int load_utxoes(GtkTreeView * tree, db_manager_t * db_mgr, shell_private_t * priv, enum db_cursor_move_direction direction)
{
	GtkWidget * search_entry = priv->search_entry;
	int rc = 0;
	
	if(direction == db_cursor_move_direction_goto)
	{
		const char * sz_outpoint = gtk_entry_get_text(GTK_ENTRY(search_entry));
		if(NULL == sz_outpoint || !sz_outpoint[0] || strlen(sz_outpoint) != (sizeof(satoshi_outpoint_t) * 2)) return -1;
		
		void * p = &priv->outpoints[0];
		ssize_t cb = hex2bin(sz_outpoint, -1, &p);
		assert(cb == sizeof(satoshi_outpoint_t));
		gtk_entry_set_text(GTK_ENTRY(search_entry), "");	// clean text
		
	}
	
	GtkListStore * store = gtk_list_store_new(UTXOES_COLUMNS_COUNT, 
		G_TYPE_POINTER,
		G_TYPE_INT64, 
		G_TYPE_POINTER,
		G_TYPE_POINTER,
		G_TYPE_POINTER,
		G_TYPE_INT
		);
	GtkTreeIter iter;
	
	int count = 0;
	db_cursor_t * cursor = db_mgr->utxoes_cursor;
	if(NULL == cursor) {
		cursor = db_cursor_init(NULL, db_mgr->utxo_db, NULL, 0);
		assert(cursor);
		db_mgr->utxoes_cursor = cursor;
	}
	
	cursor->key->data = &priv->outpoints[0];
	cursor->key->size = sizeof(priv->outpoints[0]);
	
	cursor->value->data = &priv->utxoes[0];
	cursor->value->size = sizeof(priv->utxoes[0]);

	switch(direction) 
	{
		case db_cursor_move_direction_first:
		case db_cursor_move_direction_last:
		case db_cursor_move_direction_goto:
			if(direction == db_cursor_move_direction_first) {
				rc =cursor->first(cursor);
				gtk_list_store_insert_after(store, &iter, NULL);
			}else if (direction == db_cursor_move_direction_last) {
				rc =cursor->last(cursor);
				gtk_list_store_insert_before(store, &iter, NULL);
			}else {
				rc = cursor->move_to(cursor, cursor->skey);
				gtk_list_store_insert_after(store, &iter, NULL);
			}
			
			if(rc) {
				g_object_unref(store);
				return -1;
			}
			gtk_list_store_set(store, &iter, 
				UTXOES_COLUMN_OUTPOINT, &priv->outpoints[0],
				UTXOES_COLUMN_VALUE, priv->utxoes[0].value,
				UTXOES_COLUMN_SCRIPTS, &priv->utxoes[0].scripts,
				UTXOES_COLUMN_BLOCK_HASH, &priv->utxoes[0].block_hash,
				UTXOES_COLUMN_DATA_PTR, &priv->utxoes[0],
				UTXOES_COLUMN_INDEX, count,
				-1);
			++count;
			break;
		
		default:
			break;
	}
	
	if(direction == db_cursor_move_direction_last || direction == db_cursor_move_direction_prev)
	{
		for(; count < priv->page_size; ++count) {
			
			cursor->key->data = &priv->outpoints[count];
			cursor->key->size = sizeof(priv->outpoints[count]);
			
			cursor->value->data = &priv->utxoes[count];
			cursor->value->size = sizeof(priv->utxoes[count]);

			rc = cursor->prev(cursor);
			if(rc) break;

			gtk_list_store_prepend(store, &iter);
			gtk_list_store_set(store, &iter, 
				UTXOES_COLUMN_OUTPOINT, &priv->outpoints[count],
				UTXOES_COLUMN_VALUE, priv->utxoes[count].value,
				UTXOES_COLUMN_SCRIPTS, &priv->utxoes[count].scripts,
				UTXOES_COLUMN_BLOCK_HASH, &priv->utxoes[count].block_hash,
				UTXOES_COLUMN_DATA_PTR, &priv->utxoes[count],
				UTXOES_COLUMN_INDEX, count,
				-1);
		}
	}else {
		for(; count < priv->page_size; ++count) {
			
			cursor->key->data = &priv->outpoints[count];
			cursor->key->size = sizeof(priv->outpoints[count]);
			
			cursor->value->data = &priv->utxoes[count];
			cursor->value->size = sizeof(priv->utxoes[count]);
			
			rc = cursor->next(cursor);
			if(rc) break;

			gtk_list_store_append(store, &iter);
			gtk_list_store_set(store, &iter, 
				UTXOES_COLUMN_OUTPOINT, &priv->outpoints[count],
				UTXOES_COLUMN_VALUE, priv->utxoes[count].value,
				UTXOES_COLUMN_SCRIPTS, &priv->utxoes[count].scripts,
				UTXOES_COLUMN_BLOCK_HASH, &priv->utxoes[count].block_hash,
				UTXOES_COLUMN_DATA_PTR, &priv->utxoes[count],
				UTXOES_COLUMN_INDEX, count,
				-1);
		}
	}
	
	gtk_tree_view_set_model(tree, GTK_TREE_MODEL(store));
	
	return 0;
}



/**************************************************************
 * Navigator
 *************************************************************/
static void move_first(GtkWidget * button, shell_private_t * priv)
{
	shell_context_t * shell = priv->shell;
	db_manager_t * db_mgr = shell->user_data;
	
	const char * name = gtk_stack_get_visible_child_name(GTK_STACK(priv->stack));
	if(NULL == name || !name[0]) return;
	
	if(strcasecmp(name, priv->tree_names[0]) == 0) {
		load_blocks(GTK_TREE_VIEW(priv->blocks_tree), db_mgr, priv, db_cursor_move_direction_first);
	}
	else if(strcasecmp(name, priv->tree_names[1]) == 0) {
	}
	
}
static void move_prev(GtkWidget * button, shell_private_t * priv)
{
	shell_context_t * shell = priv->shell;
	db_manager_t * db_mgr = shell->user_data;
	
	const char * name = gtk_stack_get_visible_child_name(GTK_STACK(priv->stack));
	if(NULL == name || !name[0]) return;
	
	if(strcasecmp(name, priv->tree_names[0]) == 0) {
		load_blocks(GTK_TREE_VIEW(priv->blocks_tree), db_mgr, priv, db_cursor_move_direction_prev);
	}else if(strcasecmp(name, priv->tree_names[1]) == 0) {
		
	}
}
static void move_next(GtkWidget * button, shell_private_t * priv)
{
	shell_context_t * shell = priv->shell;
	db_manager_t * db_mgr = shell->user_data;
	
	const char * name = gtk_stack_get_visible_child_name(GTK_STACK(priv->stack));
	if(NULL == name || !name[0]) return;
	if(strcasecmp(name, priv->tree_names[0]) == 0) {
		load_blocks(GTK_TREE_VIEW(priv->blocks_tree), db_mgr, priv, db_cursor_move_direction_next);
	}else if(strcasecmp(name, priv->tree_names[1]) == 0) {
		
	}
}
static void move_last(GtkWidget * button, shell_private_t * priv)
{
	shell_context_t * shell = priv->shell;
	db_manager_t * db_mgr = shell->user_data;
	
	const char * name = gtk_stack_get_visible_child_name(GTK_STACK(priv->stack));
	if(NULL == name || !name[0]) return;
	if(strcasecmp(name, priv->tree_names[0]) == 0) {
		load_blocks(GTK_TREE_VIEW(priv->blocks_tree), db_mgr, priv, db_cursor_move_direction_last);
	}else if(strcasecmp(name, priv->tree_names[1]) == 0) {
		
	}
}
static void move_to(GtkWidget * button, shell_private_t * priv)
{
	shell_context_t * shell = priv->shell;
	db_manager_t * db_mgr = shell->user_data;
	
	const char * name = gtk_stack_get_visible_child_name(GTK_STACK(priv->stack));
	if(NULL == name || !name[0]) return;
	if(strcasecmp(name, priv->tree_names[0]) == 0) {
		load_blocks(GTK_TREE_VIEW(priv->blocks_tree), db_mgr, priv, db_cursor_move_direction_goto);
	}else if(strcasecmp(name, priv->tree_names[1]) == 0) {
		
	}
}
