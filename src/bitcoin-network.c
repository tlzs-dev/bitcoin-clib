/*
 * bitcoin-network.c
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

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>

#include <sys/socket.h>
#include <netdb.h>

#include <sys/epoll.h>
#include <poll.h>

#include "utils.h"
#include "satoshi-types.h"
#include "bitcoin-consensus.h"
#include "crypto.h"
#include "satoshi-script.h"
#include "auto_buffer.h"

#include <errno.h>
#include <signal.h>

#include "bitcoin-network.h"

volatile int s_quit = 0;
void bitcoin_node_terminate(void)
{
	s_quit = 1;
}

/******************************************************************
 * peer_info
******************************************************************/

static int peer_read(struct peer_info * peer);
static int peer_write(struct peer_info * peer);
static int peer_on_read(struct peer_info * peer, struct epoll_event * ev);
static int peer_on_write(struct peer_info * peer, struct epoll_event * ev);
static int peer_on_error(struct peer_info * peer, struct epoll_event * ev);
peer_info_t * peer_info_new(int fd, void * server_ctx, const struct addrinfo * addr)
{
	peer_info_t * peer = calloc(1, sizeof(*peer));
	assert(peer);
	
	peer->fd = fd;
	peer->server_ctx = server_ctx;
	
	if(addr) memcpy(&peer->addr, addr->ai_addr, addr->ai_addrlen);
	peer->addr_len = addr->ai_addrlen;
	
	auto_buffer_init(peer->in_buf, 0);
	auto_buffer_init(peer->out_buf, 0);
	
	peer->on_read = peer_on_read;
	peer->on_write = peer_on_write;
	peer->on_error = peer_on_error;
	
	peer->read = peer_read;
	peer->write = peer_write;
	
	return peer;
}

void peer_info_free(peer_info_t * peer)
{
	if(NULL == peer) return;
	debug_printf("peer=%p, fd=%d", peer, peer->fd);
	
	if(peer->fd > 0) {
		close(peer->fd);
		peer->fd = -1;
	}
	auto_buffer_cleanup(peer->in_buf);
	auto_buffer_cleanup(peer->out_buf);
	free(peer);
	return;
}

static int peer_read(struct peer_info * peer)
{
	return 0;
}
static int peer_write(struct peer_info * peer)
{
	return 0;
}

static int peer_on_read(struct peer_info * peer, struct epoll_event * ev)
{
	debug_printf("peer_fd = %d", peer->fd);
	assert(ev->data.ptr == (void *)peer);
	
	return 0;
}

static int peer_on_write(struct peer_info * peer, struct epoll_event * ev)
{
	debug_printf("peer_fd = %d", peer->fd);
	assert(ev->data.ptr == (void *)peer);
	
	return 0;
}

static int peer_on_error(struct peer_info * peer, struct epoll_event * ev)
{
	debug_printf("peer_fd = %d", peer->fd);
	
	assert(ev->data.ptr == (void *)peer);
	
	return 0;
}

/******************************************************************
 * bitcoin network
 * 
 * Thread safety for epoll/libaio:  
 *     https://lkml.org/lkml/2006/2/28/367
******************************************************************/
static void * peers_thread(void * user_data);
#define BITCOIN_NODE_PEERS_ALLOC_SIZE (4096)

static int bitcoin_node_add_peer(bitcoin_node_t * bnode, peer_info_t * peer);
static int bitcoin_node_remove_peer(bitcoin_node_t * bnode, peer_info_t * peer);
static int bitcoin_node_on_accept(struct bitcoin_node * bnode, struct epoll_event * ev);
static int bitcoin_node_on_error(struct bitcoin_node * bnode, struct epoll_event * ev);
bitcoin_node_t * bitcoin_node_new(size_t max_size, void * user_data)
{
	int listening_efd = epoll_create1(0);
	int peers_efd = epoll_create1(0);
	
	if(listening_efd == -1 || peers_efd == -1) {
		perror("bitcoin_node_new::epoll_create1() failed");
		return NULL;
	}

	bitcoin_node_t * bnode = calloc(1, sizeof(*bnode));
	assert(bnode);

	bnode->user_data = user_data;
	if(max_size == 0) max_size = BITCOIN_NODE_PEERS_ALLOC_SIZE;
	peer_info_t ** peers = calloc(max_size, sizeof(*peers));
	assert(peers);
	
	bnode->peers = peers;
	bnode->max_size = max_size; 
	
	bnode->listening_efd = listening_efd;
	bnode->peers_efd = peers_efd;
	
	bnode->on_accept = bitcoin_node_on_accept;
	bnode->on_error = bitcoin_node_on_error;
	
	int rc = pthread_mutex_init(&bnode->mutex, NULL);
	assert(0 == rc);
	
	return bnode;
}

void bitcoin_node_free(bitcoin_node_t * bnode)
{
	bnode->quit = 1;

	if(bnode->async_mode && bnode->th) {
		void * exit_code = NULL;
		int rc = pthread_join(bnode->th, &exit_code);
		assert(0 == rc);
		(void)(exit_code);
		
		bnode->th = (pthread_t)0;
	}
	
	if(bnode->peers_th) {
		void * exit_code = NULL;
		int rc = pthread_join(bnode->peers_th, &exit_code);
		assert(0 == rc);
		(void)(exit_code);
		
		bnode->peers_th = (pthread_t)0;
	}
	
	if(bnode->peers) {
		for(ssize_t i = 0; i < bnode->peers_count; ++i) {
			peer_info_free(bnode->peers[i]);
		}
		free(bnode->peers);
		bnode->peers = NULL;
	}
	
	for(int i = 0; i < bnode->fds_count; ++i) {
		if(bnode->server_fds[i] > 0) {
			close(bnode->server_fds[i]);
			bnode->server_fds[i] = -1;
		}
	}
	
	if(bnode->listening_efd > 0) {
		close(bnode->listening_efd);
		bnode->listening_efd = -1;
	}
	
	if(bnode->peers_efd > 0) {
		close(bnode->peers_efd);
		bnode->listening_efd = -1;
	}
	
	free(bnode);
	return;
}

static void * bitcoin_node_listen_all(void * user_data);
int bitcoin_node_run(bitcoin_node_t * bnode, const char * serv_name, const char * port, int async_mode)
{
	int rc = 0;
	int server_fd = -1;
	int efd = bnode->listening_efd;
	assert(efd > 0);
	
	// start peers_thread
	rc = pthread_create(&bnode->peers_th, NULL, peers_thread, bnode);
	assert(0 == rc);
	
	struct addrinfo hints, * serv_info = NULL, *p;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	
	if(NULL == port) port = "8333";
	rc = getaddrinfo(serv_name, port, &hints, &serv_info);
	if(rc) {
		fprintf(stderr, "bitcoin_node_run::getaddrinfo() failed: %s\n",
			gai_strerror(rc));
		return -1;
	}
	
	int count = 0;
	for(p = serv_info; p; p = p->ai_next) {
		server_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if(server_fd <= 0) continue;
		
		char * hbuf = bnode->hosts[count];
		char * sbuf = bnode->servs[count];
		
		rc = getnameinfo(p->ai_addr, p->ai_addrlen, 
			hbuf, NI_MAXHOST, 
			sbuf, NI_MAXSERV,
			NI_NUMERICHOST | NI_NUMERICSERV);
		assert(0 == rc);
		fprintf(stderr, "listening on: %s:%s\n", hbuf, sbuf);
		
		rc = setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
		if(rc) {
			perror( "bitcoin_node_run::setsockopt(SO_REUSEADDR) failed");
			close(server_fd);
			server_fd = -1;
			continue;
		}
		
		rc = bind(server_fd, p->ai_addr, p->ai_addrlen);
		if(rc) {
			perror( "bitcoin_node_run::bind() failed");
			close(server_fd);
			server_fd = -1;
			continue;
		}
	
		
		rc = listen(server_fd, 16);
		assert(0 == rc);
		
		rc = make_nonblock(server_fd);
		assert(0 == rc);
		
		bnode->server_fds[count] = server_fd;
		memcpy(&bnode->addrs[count], p, sizeof(*p));
		
		++count;
		if(count >= BITCOIN_NODE_MAX_LISTENING_FDS) break;
	}
	
//	freeaddrinfo(serv_info);
	if(count == 0) return -1;
	
	struct epoll_event ev[1];
	memset(ev, 0, sizeof(ev));
	
	ev->events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
	for(int i = 0; i < count; ++i)
	{
		ev->data.fd = bnode->server_fds[i];
		rc = epoll_ctl(efd, EPOLL_CTL_ADD, ev->data.fd, ev);
		assert(0 == rc);
	}
	
	bnode->async_mode = async_mode;
	if(async_mode) {
		rc = pthread_create(&bnode->th, NULL, bitcoin_node_listen_all, bnode);
		return rc;
	}
	
	void * exit_code =  bitcoin_node_listen_all(bnode);
	return (int)(long)exit_code;
}

static int bitcoin_node_on_accept(struct bitcoin_node * bnode, struct epoll_event * ev)
{
	debug_printf("on_accept(): server_fd = %d", ev->data.fd);
	
	int server_fd = ev->data.fd;
	assert(server_fd > 0);
	struct addrinfo addr;
	memset(&addr, 0, sizeof(addr));
	
	addr.ai_addr = calloc(1, sizeof(struct sockaddr_storage));
	assert(addr.ai_addr);
	addr.ai_addrlen =  sizeof(struct sockaddr_storage);

	int fd = accept(server_fd, addr.ai_addr, &addr.ai_addrlen);
	if(fd < 0) {
		perror("bitcoin_node_on_accept::accept() failed");
		free(addr.ai_addr);
		return -1;
	}
	
	make_nonblock(fd);
	peer_info_t * peer = peer_info_new(fd, bnode, &addr);
	assert(peer);

	bitcoin_node_add_peer(bnode, peer);
	

	free(addr.ai_addr);
	return 0;
}

static int bitcoin_node_on_error(struct bitcoin_node * bnode, struct epoll_event * ev)
{
	debug_printf("fd=%d", ev->data.fd);
	return 0;
}

#define MAX_EVENTS (64)
static void * bitcoin_node_listen_all(void * user_data)
{
	bitcoin_node_t * bnode = user_data;
	assert(bnode);
	assert(bnode->on_accept && bnode->on_error);
	
	int rc = 0;
	int async_mode = bnode->async_mode;
	
	struct epoll_event events[MAX_EVENTS];
	memset(events, 0, sizeof(events));
	
	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGPIPE);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGCHLD);
	sigaddset(&sigs, SIGCONT);
	sigaddset(&sigs, SIGSTOP);

	int timeout = 1000;
	int efd = bnode->listening_efd;
	assert(efd > 0);
	
	while(!bnode->quit) {
		if(s_quit) {
			bnode->quit = 1;
			break;
		}
		
		rc = 0;
		int n = epoll_pwait(efd, events, MAX_EVENTS, timeout, &sigs);
		if(bnode->quit) break;
		
		if(n == 0) continue;	// timeout
		if(n < 0) {
			rc = errno;
			perror("epoll_pwait");
			break;
		}
		rc = 0;
		for(int i = 0; i < n; ++i) {
			if(events[i].events & EPOLLIN) {	// new connection
				bnode->on_accept(bnode, &events[i]);
				continue;
			}else {	// error
				bnode->on_error(bnode, &events[i]);
				rc = -1;
				break;
			}
		}
		
		if(rc) break;
	}

	if(async_mode) {
		debug_printf("thread %p exited with code %d\n", (void *)pthread_self(), rc);
		pthread_exit((void *)(long)rc);
	}else
	{
		debug_printf("%s() exited with code %d\n", __FUNCTION__, rc);
	}
	return (void *)(long)rc;
}


static int bitcoin_node_add_peer(bitcoin_node_t * bnode, peer_info_t * peer)
{
	debug_printf("peer = %p, fd = %d\n", peer, peer->fd);
	if(bnode->peers_count >= bnode->max_size) {
		ssize_t new_size = bnode->max_size + BITCOIN_NODE_PEERS_ALLOC_SIZE;
		peer_info_t ** peers = realloc(bnode->peers, new_size * sizeof(*peers));
		assert(peers);
		
		memset(peers, 0, (new_size - bnode->max_size) * sizeof(*peers));
		bnode->peers = peers;
	}
	
	bnode->peers[bnode->peers_count++] = peer;
	
	struct epoll_event ev[1];
	memset(ev, 0, sizeof(ev));
	ev->events = EPOLLIN | EPOLLET;
	ev->data.ptr = peer;
	
	int rc = epoll_ctl(bnode->peers_efd, EPOLL_CTL_ADD, peer->fd, ev);
	assert(0 == rc);
	
	return rc;
}

static int bitcoin_node_remove_peer(bitcoin_node_t * bnode, peer_info_t * peer)
{
	debug_printf("peer = %p, fd = %d\n", peer, peer->fd);
	for(int i = 0; i < bnode->peers_count; ++i) {
		if(bnode->peers[i] == peer) {
			if(peer->fd > 0) {
				struct epoll_event ev[1];
				memset(ev, 0, sizeof(ev));
				int rc = epoll_ctl(bnode->peers_efd, EPOLL_CTL_DEL, peer->fd, ev);
				assert(0 == rc);
			}
			
			peer_info_free(peer);
			bnode->peers[i] = bnode->peers[--bnode->peers_count];
			bnode->peers[bnode->peers_count] = NULL;
		}
	}
	return 0;
}

static void * peers_thread(void * user_data)
{
	int rc = 0;
	bitcoin_node_t * bnode = user_data;
	assert(bnode);
	
	struct epoll_event events[MAX_EVENTS];
	memset(events, 0, sizeof(events));
	
	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGPIPE);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGCHLD);
	sigaddset(&sigs, SIGCONT);
	sigaddset(&sigs, SIGSTOP);

	int timeout = 1000;
	int efd = bnode->peers_efd;
	assert(efd > 0);
	
	while(!bnode->quit) {
		if(s_quit) {
			bnode->quit = 1;
			break;
		}
		
		rc = 0;
		int n = epoll_pwait(efd, events, MAX_EVENTS, timeout, &sigs);
		if(bnode->quit) break;
		
		if(n == 0) continue;	// timeout
		if(n < 0) {
			rc = errno;
			perror("epoll_pwait");
			break;
		}
		for(int i = 0; i < n; ++i) {
			peer_info_t * peer = events[i].data.ptr;
			assert(peer);
				
			if( (events[i].events & EPOLLIN) || (events[i].events & EPOLLOUT) ) {	
				 assert(peer->on_read && peer->on_write);
				
				if(events[i].events & EPOLLIN) peer->on_read(peer, &events[i]);
				else peer->on_write(peer, &events[i]);
				
			} else {	// error
				assert(peer->on_error);
				
				peer->on_error(peer, &events[i]);
				bitcoin_node_remove_peer(bnode, peer);
			}
		}
		if(rc) break;
	}

	debug_printf("thread %p exited with code %d\n", (void *)pthread_self(), rc);
	pthread_exit((void *)(long)rc);
}
#undef MAX_EVENTS

#if defined(_TEST_BITCOIN_NETWORK) && defined(_STAND_ALONE)

void on_signal(int sig)
{
	switch(sig) 
	{
	case SIGINT:
	case SIGUSR1:
		bitcoin_node_terminate();
		close(0);	// close stdin
		break;
	default:
		abort();
	}
	return;
}

static int test_new_client()
{
	struct addrinfo hints, *serv_info = NULL, *p;
	memset(&hints, 0, sizeof(hints));
	
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	
	int rc = getaddrinfo("127.0.0.1", "8333", &hints, &serv_info);
	if(rc) {
		fprintf(stderr, "%s() failed: %s\n", __FUNCTION__, 
			gai_strerror(rc));
		exit(1);
	}
	
	int fd = -1;
	for(p = serv_info; p; p = p->ai_next) {
		fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if(fd < 0) {
			continue;
		}
		rc = connect(fd, p->ai_addr, p->ai_addrlen);
		if(rc) {
			perror("connect()");
			close(fd);
			fd = -1;
			continue;
		}
		make_nonblock(fd);
		break;
	}
	
	assert(fd > 0);
	
	///< @todo :...
	close(fd);
	return 0;
}


int main(int argc, char **argv)
{
	signal(SIGINT, on_signal);
	signal(SIGUSR1, on_signal);
	
	bitcoin_node_t * bnode = bitcoin_node_new(1024, NULL);
	assert(bnode);
	
	bitcoin_node_run(bnode, NULL, NULL, 1);
	
	char buf[4096] = "";
	char * line = NULL;
	
	while((line = fgets(buf, sizeof(buf) - 1, stdin))) {
		int cb = strlen(line);
		while(cb > 0 && line[cb - 1] == '\n') line[--cb] = '\0';
		if(cb == 0) continue;
		
		if(strcasecmp(line, "n") == 0) {
			test_new_client();
		}else if(line[0] == 'q' || line[0] == 'Q') {
			bnode->quit = 1;
			break;
		}
	}
	
	bitcoin_node_free(bnode);
	return 0;
}
#endif

