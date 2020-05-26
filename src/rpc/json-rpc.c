/*
 * json-rpc.c
 * 
 * Copyright 2020 Che Hongwei <htc.chehw@gmail.com>
 * 
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person 
 * obtaining a copy of this software and associated documentation 
 * files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, 
 * publish, distribute, sublicense, and/or sell copies of the Software, 
 * and to permit persons to whom the Software is furnished to do so, 
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 *  in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR 
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <unistd.h>
#include <curl/curl.h>

#include <limits.h>
#include <uuid/uuid.h>

#include <pthread.h>
#include <search.h>

#include "json-rpc.h"


#if _VERBOSE >= 1
#include <stdarg.h>
#define log_printf(fmt, ...) do {											\
		fprintf(stderr, "\e33m" "[INFO]::%s@%d::%s(): " fmt "\e[39m" "\n",	\
			__FILE__, __LINE__, __FUNCTION__, 								\
			##__VA_ARGS__);													\
	}while(0)
#else
#define log_printf(fmt, ...) do { } while(0)
#endif


#define AUTO_UNLOCK_MUTEX_PTR(p_mutex) __attribute__((cleanup(auto_unlock_ptr))) \
		pthread_mutex_t * _m_ = p_mutex;	\
		do { if(_m_) pthread_mutex_lock(_m_); } while(0)
		
static void auto_unlock_ptr(void * ptr)
{
	pthread_mutex_t * mutex = *(pthread_mutex_t **)ptr;
	if(mutex) {
		pthread_mutex_unlock(mutex);
		*(pthread_mutex_t **)ptr = NULL;
	}
}
#define json_set_value(jobj, key, type, value) \
			json_object_object_add(jobj, \
				key, \
				json_object_new_##type(value))


static pthread_once_t s_once_key = PTHREAD_ONCE_INIT;
static void init_curl_context(void)
{
	curl_global_init(CURL_GLOBAL_DEFAULT);
	return;
}


#define priv_lock() 	do { (void)pthread_mutex_lock(&priv->mutex); } while(0)
#define priv_unlock() 	do { (void)pthread_mutex_unlock(&priv->mutex); } while(0)

#define curl_check_error(ret) do {	\
		if(ret != CURLE_OK) {		\
			fprintf(stderr, "[ERROR]::%s@%d::%s(): %s\n", 	\
				__FILE__, __LINE__, __FUNCTION__, 			\
				curl_easy_strerror(ret));					\
			exit(1);										\
		}													\
	}while(0)


typedef struct json_rpc_request_data
{
	// request data
	char id[100];
	char command[200];
	json_object * jparams;
	
	// meta data
	long sequence;
	
	// private data
	int index;		// history's array_index
}json_rpc_request_data_t;

#define JSON_RPC_REQUESTS_MAX_HISTORY (100)

typedef struct bitcoin_cli_context_private
{
	bitcoin_cli_context_t * ctx;
	
	char username[PATH_MAX];
	char password[PATH_MAX];
	CURL * curl;
	json_tokener * jtok;
	json_object * jresponse;
	
	pthread_mutex_t mutex;
	pthread_cond_t cond;			///< @todo
	pthread_t th;					///< @todo
	enum json_tokener_error jerr;
	
	void * requests_root;
	json_rpc_request_data_t * history[JSON_RPC_REQUESTS_MAX_HISTORY];
	long max_history;
	long count;
	long sequence;
	
	int is_busy;
}bitcoin_cli_context_private_t;
bitcoin_cli_context_private_t * bitcoin_cli_context_private_new(bitcoin_cli_context_t * ctx)
{
	int rc = 0;
	
	rc = pthread_once(&s_once_key, init_curl_context);
	assert(0 == rc);
	
	bitcoin_cli_context_private_t * priv = calloc(1, sizeof(*priv));
	assert(priv);
	
	rc = pthread_mutex_init(&priv->mutex, NULL);
	assert(0 == rc);
	
	priv->jtok = json_tokener_new();
	assert(priv->jtok);
	
	CURL * curl = curl_easy_init();
	if(NULL == curl) {
		fprintf(stderr, "[ERROR]::%s(%d)::%s: curl_easy_init() failed.\n",
			__FILE__, __LINE__, __FUNCTION__);
		exit(1);
	}
	
	priv->curl = curl;
	ctx->priv = priv;
	priv->ctx = ctx;
	
	return priv;
}

static void set_userpass(struct bitcoin_cli_context * cli, const char * username, const char * password)
{
	bitcoin_cli_context_private_t * priv = cli->priv;
	assert(priv);
	
	if(username) strncpy(priv->username, username, sizeof(priv->username) -1);
	if(password) strncpy(priv->password, password, sizeof(priv->password) -1);
	return;
}

static int set_url(struct bitcoin_cli_context * cli, const char * url)
{
	if(NULL == url) return -1;
	bitcoin_cli_context_private_t * priv = cli->priv;
	assert(priv);
	CURL * curl = priv->curl;
	
	priv_lock();
	if(curl)
	{
		curl_easy_reset(curl);
	}else
	{
		curl = curl_easy_init();
		assert(curl);
	}
	
	CURLcode ret = curl_easy_setopt(curl, CURLOPT_URL, url);
	if(ret != CURLE_OK)
	{
		fprintf(stderr, "[ERROR]::%s() failed: %s\n", 
			__FUNCTION__, 
			curl_easy_strerror(ret));
		priv_unlock();
		return -1;
	}
	
	strncpy(cli->url, url, sizeof(cli->url) -1);
	priv_unlock();
	return 0;
}

static size_t on_write_data(void * ptr, size_t size, size_t n, struct bitcoin_cli_context * cli)
{
	struct bitcoin_cli_context_private * priv = cli->priv;
	assert(priv);
	
	size_t cb = size * n;
	if(!cb) return 0;
	
	json_tokener * jtok = priv->jtok;
	enum json_tokener_error jerr;
	
	assert(jtok);
	json_object * jresponse = json_tokener_parse_ex(jtok, ptr, cb);
	jerr = json_tokener_get_error(jtok);
	
	priv->jerr = jerr;
	if(jerr == json_tokener_continue || jerr == json_tokener_success) 
	{
		if(jerr == json_tokener_success)
		{
			if(priv->jresponse) json_object_put(priv->jresponse);
			priv->jresponse  = jresponse;
			if(cli->async_mode){
				if(cli->on_response) cli->on_response(cli, jresponse);
				else {
					fprintf(stderr, "\e[32m" "<<<Async MODE>>>: sequence=%ld" "\e[39m" "\n", (long)priv->sequence);
					printf("%s\n", json_object_to_json_string_ext(jresponse, JSON_C_TO_STRING_PRETTY));
				}
			}
			json_tokener_reset(jtok);
		}
		return cb;
	}
	else
	{
		fprintf(stderr, "[ERROR]::%s@%d::%s(): invalid json format: %s\n",
			__FILE__, __LINE__, __FUNCTION__,
			json_tokener_error_desc(jerr));
		json_object_put(jresponse);
		json_tokener_reset(jtok);
	}
	return 0;
} 

static int json_rpc_request_data_compare(const void * _a, const void * _b)
{
	const json_rpc_request_data_t * a = _a;
	const json_rpc_request_data_t * b = _b;
	assert(a && b);
	return strncasecmp(a->id, b->id, sizeof(a->id));
}
static void json_rpc_request_data_free(json_rpc_request_data_t * req)
{
	if(NULL == req) return;
	
	if(req->jparams) {
		json_object_put(req->jparams);
		req->jparams = NULL;
	}
	free(req);
	return;
}

static json_rpc_request_data_t * json_rpc_request_data_new(struct bitcoin_cli_context_private *priv, const char * id, const char * command, json_object * jparams)
{
	assert(command);
	
	json_rpc_request_data_t * req = calloc(1, sizeof(*req));
	assert(req);
	
	if(id && id[0]) {
		strncpy(req->id, id, sizeof(req->id));
	}
	else
	{
		uuid_t uuid;
		uuid_generate(uuid);
		uuid_unparse(uuid, req->id);
	}
	
	json_rpc_request_data_t ** p_node = tsearch(req, &priv->requests_root, json_rpc_request_data_compare);
	assert(p_node);
	
	if(*p_node != req)
	{
		json_rpc_request_data_free(req);
		req = *p_node;
	}else
	{
		if(0 == priv->max_history) priv->max_history = JSON_RPC_REQUESTS_MAX_HISTORY;
		
		long index = ++priv->count;
		index %= priv->max_history;
		
		if(priv->history[index]) json_rpc_request_data_free(priv->history[index]);
		req->index = index;
		priv->history[index] = req;
	}
	
	req->sequence = ++priv->sequence;
	strncpy(req->command, command, sizeof(req->command));
	if(jparams)
	{
		req->jparams = json_object_get(jparams);
	}
	return req;
}

static int request(struct bitcoin_cli_context * cli, 
	const char * request_id, 
	const char * command, 
	const json_object * jparams,
	json_object ** p_jresponse)
{
	if(NULL == command) command = "help";
	bitcoin_cli_context_private_t * priv = cli->priv;
	assert(priv);
	
	AUTO_UNLOCK_MUTEX_PTR(&priv->mutex);

	const char * url = cli->url;
	if(!url[0]) url = "http://127.0.0.1:18332";
	
	json_rpc_request_data_t * req = json_rpc_request_data_new(priv, request_id, command, (json_object *)jparams);
	if(NULL == req) return -1;
	
	/* JSON RPC request format:
		{ 
			"jsonrpc": "1.0",
			"id": "<req.id(nullable)>",
			"method": "<req.command>",
			"params": []
		 }
	*/  
	json_object * jrequest = json_object_new_object();
	if(NULL == jrequest) return -1;
	
	if(cli->rpc_version) json_set_value(jrequest, "jsonrpc", string, cli->rpc_version);
	json_set_value(jrequest, "id", string, req->id);
	json_set_value(jrequest, "method", string, req->command);
	if(req->jparams) json_object_object_add(jrequest, "params", req->jparams);
	
	const char * json_cmd = json_object_to_json_string_ext(jrequest, JSON_C_TO_STRING_PLAIN);
	
	
	// debug messages
	fprintf(stderr, "\e[34m" "request: %s" "\e[39m" "\n", json_cmd);
	

	/* Send HTTP request:
	 *  method: POST 
	 * 	content-type: application/json 
	 * 	data: json_string
	 */
	CURLcode ret = 0;
	CURL * curl = priv->curl;
	assert(curl);
	
	/* HTTP BASIC Auth */
	ret = curl_easy_setopt(curl, CURLOPT_USERNAME, priv->username);	curl_check_error(ret);
	ret = curl_easy_setopt(curl, CURLOPT_PASSWORD, priv->password);	curl_check_error(ret);
	ret = curl_easy_setopt(curl, CURLOPT_URL, url);					curl_check_error(ret);
	ret = curl_easy_setopt(curl, CURLOPT_POST, 1); 					curl_check_error(ret);
	
	/* content type */
	struct curl_slist * headers = NULL;
	headers = curl_slist_append(headers, "Content-Type: application/json");
	ret = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);		curl_check_error(ret);
	
	/* data */
	ret = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_cmd);	curl_check_error(ret);
	
	/* set callback function */
	ret = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_write_data);	curl_check_error(ret);
	ret = curl_easy_setopt(curl, CURLOPT_WRITEDATA, cli);				curl_check_error(ret);
	
	/* clear previous result */
	json_tokener_reset(priv->jtok);
	if(priv->jresponse)
	{
		json_object_put(priv->jresponse);
		priv->jresponse = NULL;
	}
	
	/* send request */
	ret = curl_easy_perform(curl);
	
	/* cleanup */
	json_object_put(jrequest);
	curl_slist_free_all(headers);		
	
	
	/* check error and set outputs */
	if(ret != CURLE_OK)
	{
		log_printf("%s", curl_easy_strerror(ret)); 
		return -1;
	}
	
	if(p_jresponse) {
		*p_jresponse = json_object_get(priv->jresponse);	// add_ref
	}
	else
	{
		if(!cli->async_mode)
		{
			if(cli->on_response) {
				cli->on_response(cli, priv->jresponse);	// if callback function exists
			}else {
				fprintf(stderr, "\e[32m" "<<<Async MODE>>>: sequence=%ld" "\e[39m" "\n", (long)priv->sequence);
				printf("%s\n", json_object_to_json_string_ext(priv->jresponse, JSON_C_TO_STRING_PRETTY));
			}
		}
	}
	return 0;
}

bitcoin_cli_context_t * bitcoin_cli_context_new(
	const char * rpc_version,
	enum bitcoin_network_type network, 
	int use_ssl,
	int async_mode, void * user_data)
{
	bitcoin_cli_context_t * ctx = calloc(1, sizeof(*ctx));
	assert(ctx);
	
	if(NULL == rpc_version) rpc_version = BITCOIN_JSON_RPC_VERSION;
	if(network == bitcoin_network_default) network = bitcoin_network_mainnet;
	
	assert(rpc_version);
	ctx->rpc_version = strdup(rpc_version);
	ctx->user_data = user_data;
	ctx->network = network;
	ctx->use_ssl = use_ssl;
	ctx->async_mode = async_mode;
	
	ctx->set_url = set_url;
	ctx->set_userpass = set_userpass;
	ctx->request = request;
	
	bitcoin_cli_context_private_t * priv = bitcoin_cli_context_private_new(ctx);
	assert(priv && ctx->priv == priv);
	
	return ctx;
}

void bitcoin_cli_context_private_free(bitcoin_cli_context_private_t * priv)
{
	pthread_mutex_lock(&priv->mutex);
	
	tdestroy(priv->requests_root, (void (*)(void *))json_rpc_request_data_free);
	priv->requests_root = NULL;
	priv->count = 0;

	if(priv->curl)
	{
		curl_easy_cleanup(priv->curl);
		priv->curl = NULL;
	}
	
	if(priv->jtok)
	{
		json_tokener_free(priv->jtok);
		priv->jtok = NULL;
	}
	if(priv->jresponse)
	{
		json_object_put(priv->jresponse);
		priv->jresponse = NULL;
	}
	
	pthread_mutex_unlock(&priv->mutex);
	
	pthread_mutex_destroy(&priv->mutex);

	
	free(priv);
	return;
}

void bitcoin_cli_context_free(bitcoin_cli_context_t * ctx)
{
	if(ctx->reset)
	{
		ctx->reset(ctx);
	}
	bitcoin_cli_context_private_free(ctx->priv);
	if(ctx->cert_file) free(ctx->cert_file);
	if(ctx->ca_file) free(ctx->ca_file);
	if(ctx->rpc_version) free(ctx->rpc_version);
	
	ctx->cert_file = NULL;
	ctx->ca_file = NULL;
	free(ctx);
	return;
}


/*****************************************************************************
 * TEST
 ****************************************************************************/
#if defined(_TEST) && defined(_STAND_ALONE)
#include "../.private/credentials.c.impl"	// get_username(); / get_password();
int main(int argc, char ** argv)
{
	const char * url = "http://127.0.0.1:18332";
	const char * username = get_username();
	const char * password = get_password();
	
	enum bitcoin_network_type net = bitcoin_network_testnet;
	bitcoin_cli_context_t * cli = bitcoin_cli_context_new(NULL, net, 0, 0, NULL);
	
	int rc = 0;
	
	cli->async_mode = 1;
	rc = cli->set_url(cli, url);
	assert(0 == rc);
	
	cli->set_userpass(cli, username, password);	
	
	
	rc = cli->request(cli, NULL, "getblockchaininfo", NULL, NULL);	assert(0 == rc);
	rc = cli->request(cli, NULL, "getwalletinfo", NULL, NULL);		assert(0 == rc);
	
	json_object * jresponse = NULL;
	rc = cli->request(cli, NULL, "help", NULL, &jresponse);				assert(0 == rc);
	
	if(jresponse)
	{
		json_object_put(jresponse);
	}
	
	bitcoin_cli_context_free(cli);
	
	curl_global_cleanup();
	return 0;
}
#endif
