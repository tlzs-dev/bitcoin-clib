#ifndef _BITCOIN_NETWORK_H_
#define _BITCOIN_NETWORK_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/epoll.h>

#include "satoshi-types.h"
#include "auto_buffer.h"

#ifndef FALSE
#define FALSE 0
#define TRUE (!FALSE)
#endif

struct bitcoin_node;
typedef struct peer_info
{
	int fd;
	struct sockaddr_storage addr;
	socklen_t addr_len;
	
	struct bitcoin_node * bnode;
	void * priv;
	int quit;
	
	int status;	// 0: handshaking; 1: msg::version exchanged; 2: msg::addr exchanged
	
	// public methods
	int (* send_msg)(struct peer_info * peer, const struct bitcoin_message_header * msg_hdr, const void * payload);	// relay messages

	// virtual callbacks
	int (* on_read )(struct peer_info * peer, struct epoll_event * ev);
	int (* on_write)(struct peer_info * peer, struct epoll_event * ev);
	int (* on_error)(struct peer_info * peer, struct epoll_event * ev);
	
	int (* on_parse_msg)(struct peer_info * peer, const struct bitcoin_message_header * msg_hdr, const void * payload);
}peer_info_t;
peer_info_t * peer_info_new(int fd, void * server_ctx, const struct addrinfo * addr);
void peer_info_free(peer_info_t * peer);

#define BITCOIN_NODE_MAX_LISTENING_FDS (8)
typedef struct bitcoin_node
{
	void * priv;
	void * user_data;
	int async_mode; 

	pthread_t th;
	int quit;
	
	pthread_mutex_t mutex;
	pthread_t peers_th;
	
	int listening_efd;
	int peers_efd;
	
	int server_fds[BITCOIN_NODE_MAX_LISTENING_FDS];
	int fds_count;
	
	struct addrinfo addrs[BITCOIN_NODE_MAX_LISTENING_FDS];
	char hosts[BITCOIN_NODE_MAX_LISTENING_FDS][NI_MAXHOST];
	char servs[BITCOIN_NODE_MAX_LISTENING_FDS][NI_MAXSERV];
	
	peer_info_t ** peers;
	ssize_t max_size;
	ssize_t peers_count;
	
	peer_info_t ** relay_peers;
	ssize_t max_relay_size;
	ssize_t relay_peers_count;
	
	struct bitcoin_message_version * version;
	ssize_t cb_version;
	
	// callbacks
	int (* on_accept)(struct bitcoin_node * bnode, struct epoll_event * ev);
	int (* on_error)(struct bitcoin_node * bnode, struct epoll_event * ev);
	
	// utils
	int (* add_peer)(struct bitcoin_node * bnode, struct peer_info * peer);
	int (* remove_peer)(struct bitcoin_node * bnode, struct peer_info * peer);
	
	int (* set_writable)(struct bitcoin_node * bnode, struct peer_info * peer, int f_enabled);
	
}bitcoin_node_t;
bitcoin_node_t * bitcoin_node_new(size_t max_size, void * user_data);
void bitcoin_node_free(bitcoin_node_t * bnode);
int bitcoin_node_run(bitcoin_node_t * bnode, const char * serv_name, const char * port, int async_mode);
void bitcoin_node_terminate(void);

#ifdef __cplusplus
}
#endif
#endif
