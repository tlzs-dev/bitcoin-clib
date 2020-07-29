#ifndef _TOOLS_SHELL_H_
#define _TOOLS_SHELL_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include "db_engine.h"
typedef struct db_manager
{
	db_engine_t * engine;
	void * user_data;
	char * db_home;
	
	db_handle_t * block_db;
	db_handle_t * heights_db;
	db_handle_t * utxo_db;
	
	db_cursor_t * blocks_cursor;
	db_cursor_t * utxoes_cursor;
}db_manager_t;

db_manager_t * db_manager_init(db_manager_t * db_mgr, const char * db_home, void * user_data);
void db_manager_cleanup(db_manager_t * db_mgr);

typedef struct shell_context
{
	void * priv;
	void * user_data;
	
	int (* init)(struct shell_context * shell, void * jconfig);
	int (* run)(struct shell_context * shell);
	int (* stop)(struct shell_context * shell);
	
	int (* on_timeout)(struct shell_context * shell);
	void (* on_cleanup)(struct shell_context * shell);
}shell_context_t;
shell_context_t * shell_context_init(shell_context_t * shell, int argc, char ** argv, void * user_data);
void shell_context_cleanup(shell_context_t * shell);

#ifdef __cplusplus
}
#endif
#endif
