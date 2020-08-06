#ifndef _BITCOIN_NETWORK_H_
#define _BITCOIN_NETWORK_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/epoll.h>

#include "satoshi-types.h"
#include "auto_buffer.h"

typedef struct peer_info
{
	int fd;
	struct sockaddr_storage addr;
	socklen_t addr_len;
	
	void * server_ctx;
	void * priv;
	
	int quit;
	
	struct bitcoin_message_header in_hdr;
	auto_buffer_t in_buf[1];
	
	struct bitcoin_message_header out_hdr;
	auto_buffer_t out_buf[1];
	
	int (* read)(struct peer_info * peer);
	int (* write)(struct peer_info * peer);
	
	// callback
	int (* on_read)(struct peer_info * peer, struct epoll_event * ev);
	int (* on_write)(struct peer_info * peer, struct epoll_event * ev);
	int (* on_error)(struct peer_info * peer, struct epoll_event * ev);
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
	
	int (* on_accept)(struct bitcoin_node * bnode, struct epoll_event * ev);
	int (* on_error)(struct bitcoin_node * bnode, struct epoll_event * ev);
	
}bitcoin_node_t;
bitcoin_node_t * bitcoin_node_new(size_t max_size, void * user_data);
void bitcoin_node_free(bitcoin_node_t * bnode);
int bitcoin_node_run(bitcoin_node_t * bnode, const char * serv_name, const char * port, int async_mode);
void bitcoin_node_terminate(void);

#ifdef __cplusplus
}
#endif
#endif
