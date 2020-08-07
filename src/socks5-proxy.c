/*
 * socks5-proxy.c
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
/**
 * SOCKS Protocol Version 5
 *     https://tools.ietf.org/html/rfc1928
 *     https://en.wikipedia.org/wiki/SOCKS
 * 
 * Username/Password Authentication for SOCKS V5
 *     https://tools.ietf.org/html/rfc1929
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdarg.h>
#include <unistd.h>

#include "utils.h"
#include "socks5_proxy.h"

#define SOCKS5_MSG_BUFFER_SIZE 	(512 + 1)
#define SOCKS5_ADDR_BUFFER_SIZE (256 + 1)

/**************************************************
 * socks5_handshake: 
 *     struct socks5_query_auth    : CLIENT::query auth method
 *     struct socks5_auth          : SERVER::return chosen authentication method
 *     struct socks5_auth_user_pass: CLIENT::send Username/password for authentication
 *     struct socks5_auth_response : SERVER::return verification status
 * 
**************************************************/

enum socks5_auth_method
{
	socks5_auth_method_no_auth = 0,
	socks5_auth_method_gssapi = 0x01,
	socks5_auth_method_user_pass = 0x02,
	
	/*
	 * 0x03 ~ 0x7F: assigned by IANA
	 */
	socks5_auth_method_challenge_handshake = 0x03,
	socks5_auth_method_challenge_response = 0x05,
	// unassigned
	socks5_auth_method_challenge_ssl = 0x06,
	socks5_auth_method_nds = 0x07, // Novell Directory Service authentication
	socks5_auth_method_multifactor_auth = 0x08, 
	socks5_auth_method_json_parameter_block = 0x09, 
	// 0x0A-0x7F: unsasigned
	
	/*
	 * 0x80 ~ 0xFE: private use
	 */
	// ...
	
	socks5_auth_method_unavailable = 0xFF,
};

struct socks5_query_auth
{
	unsigned char version;	// 0x05
	unsigned char num_methods;
	unsigned char methods[];
}__attribute__((packed));
#define socks5_query_auth_size(query_auth) ( sizeof(*query_auth) + query_auth->num_methods )

struct socks5_query_auth * socks5_query_auth_init(void * buf, unsigned char num_methods, ...) 
{
	assert(num_methods > 0);
	struct socks5_query_auth * query_auth = buf;
	if(NULL == buf) {
		query_auth = calloc(1, sizeof(struct socks5_query_auth) + num_methods);
	}
	assert(query_auth);
	
	query_auth->version = 0x05;
	query_auth->num_methods = num_methods;
	
	va_list args;
	va_start(args, num_methods);
	for(unsigned char i = 0; i < num_methods; ++i) {
		query_auth->methods[i] = (unsigned char)va_arg(args, int);
	}
	return query_auth;
}

struct socks5_auth
{
	unsigned char verison; // 0x05
	unsigned char method;
}__attribute__((packed));

struct socks5_auth_user_pass
{
	unsigned char auth_ver;	// 0x01 for current version of username/password authentication
	unsigned char id_len;
	
	// variable length data
	unsigned char id[];	
	// unsigned char pw_len;
	// unsigned char pw[];
}__attribute__((packed));
#define socks5_auth_user_pass_size(user_pass)	\
	( sizeof(*user_pass) + user_pass->id_len + 1 + user_pass->id[user_pass->id_len] )
struct socks5_auth_user_pass * socks5_auth_user_pass_init(void * buf, const char * user_id, const char * password);

struct socks5_auth_user_pass * socks5_auth_user_pass_init(void * buf, const char * user_id, const char * password)
{
	struct socks5_auth_user_pass * user_pass = buf;
	if(NULL == user_pass) {
		user_pass = calloc(SOCKS5_MSG_BUFFER_SIZE, 1);
	}
	assert(user_pass);
	
	size_t cb_user = 0;
	size_t cb_pass = 0;
	
	if(user_id) 	cb_user = strlen(user_id);
	if(password) 	cb_pass = strlen(password);
	assert(cb_user <= 255 && cb_pass <= 255);
	
	user_pass->auth_ver = 0x01;
	user_pass->id_len = cb_user;
	unsigned char * p = user_pass->id;
	
	if(user_id) {
		memcpy(p, user_id, cb_user);
		p += cb_user;
	}
	
	*p++ = cb_pass;
	if(password) {
		memcpy(p, password, cb_pass);
	}
	return user_pass;
}

struct socks5_auth_response
{
	unsigned char auth_ver; // 0x01 for current version of username/password authentication
	unsigned char status;	// 0x00: success, otherwise failure.
}__attribute__((packed));


/**************************************************
 * socks5_address: dst address
**************************************************/
enum socks5_address_type
{
	socks5_address_type_ipv4 = 0x01,
	socks5_address_type_domain_name = 0x03,
	socks5_address_type_ipv6 = 0x04,
};
struct socks5_address
{
	unsigned char type;	// 0x01: ipv4,  0x03: domain name, 0x04: ipv6
	unsigned char data[];
}__attribute__((packed));
#define socks5_address_calc_data_size(type, data) ({ 		\
		size_t size = 0;									\
		switch(type) {										\
		case socks5_address_type_ipv4: size = 4; break;						\
		case socks5_address_type_domain_name: size = 1 + data[0]; break;	\
		case socks5_address_type_ipv6: size = 16; break;					\
		default: break;										\
		}													\
		size;												\
	})
#define socks5_address_size(addr) (sizeof(*addr) + socks5_address_calc_data_size(addr->type, addr->data))

struct socks5_address * socks5_address_init(void * buf, unsigned char type, const unsigned char * data)
{
	assert(data);
	size_t data_size = socks5_address_calc_data_size(type, data);
	assert(data_size > 0);

	struct socks5_address * addr = buf;
	if(NULL == buf) {
		addr = calloc(1, sizeof(*addr) + data_size);
	}
	assert(addr);
	
	addr->type = type;
	memcpy(addr->data, data, data_size); 
	return addr;
}

#include <arpa/inet.h>
int socks5_address_parse(const char * sz_addr, struct socks5_address ** p_addr)
{
	struct socks5_address * addr = *p_addr;
	if(NULL == addr) {
		addr = calloc(1, SOCKS5_ADDR_BUFFER_SIZE);
		assert(addr);
		*p_addr = addr;
	}
	
	unsigned char ip[16] = {0};
	int ok = inet_pton(PF_INET, sz_addr, ip);
	
	if(ok) {
		addr->type = socks5_address_type_ipv4;
		*(uint32_t *)addr->data = *(uint32_t *)ip;
		return 0;
	}
	
	ok =  inet_pton(PF_INET6, sz_addr, ip);
	if(ok) {
		addr->type = socks5_address_type_ipv6;
		memcpy(addr->data, ip, 16);
		return 0;
	}
	
	size_t cb = strlen(sz_addr);
	if(cb > 255) return -1;
	
	addr->type = socks5_address_type_domain_name;
	addr->data[0] = cb;
	memcpy(&addr->data[1], sz_addr, cb);
	return 0;
}


/**************************************************
 * socks5 request / response
**************************************************/

enum socks5_command
{
	socks5_command_tcp_connect = 0x01,
	socks5_command_tcp_binding = 0x02,
	socks5_command_udp = 0x03,
};

struct socks5_request_data
{
	unsigned char version;	// 0x05
	unsigned char command;	// 1: tcp connect, 2: tcp port binding, 3: associate a udp port
	unsigned char reserved;	// must be 0
	unsigned char dst_addr[];	// struct socks5_address
	// uint16_t dst_port;	// network byte order
}__attribute__((packed));
#define socks5_request_data_size(req) \
	( sizeof(*req) + socks5_address_size(((struct socks5_address *)req->dst_addr)) + sizeof(uint16_t) )
struct socks5_request_data * socks5_request_data_init(void * buf, unsigned char command, const struct socks5_address * dst_addr, uint16_t port);

struct socks5_request_data * socks5_request_data_init(void * buf, 
	unsigned char command, 
	const struct socks5_address * dst_addr, 
	uint16_t port)
{
	assert(dst_addr);
	size_t addr_size = socks5_address_size(dst_addr);
	struct socks5_request_data * req = buf;
	if(NULL == req) req = calloc(1, sizeof(*req) + addr_size + sizeof(uint16_t));
	assert(req);
	
	req->version = 0x05;
	req->command = command;
	req->reserved = 0;
	memcpy(req->dst_addr, dst_addr, addr_size);
	
	*(uint16_t *)(req->dst_addr + addr_size) = port;
	return req;
}

enum socks5_response_status
{
	socks5_response_status_ok = 0x00,	// succeeded
	socks5_response_status_failure = 0x01,
	socks5_response_status_not_allowed = 0x02,
	socks5_response_status_network_unreachable = 0x03,
	socks5_response_status_host_unreachable = 0x04,
	socks5_response_status_connection_refused = 0x05, 
	socks5_response_status_ttl_expired = 0x06,
	socks5_response_status_invalid_command = 0x07,
	socks5_response_status_invalid_address = 0x08,
};

struct socks5_response_data
{
	unsigned char version;	// 0x05
	unsigned char status;	// enum socks5_response_status
	unsigned char reserved;	// must be 0
	unsigned char bound_addr[];	// struct socks5_address
	// uint16_t bound_port;		// network byte order
}__attribute__((packed));
#define socks5_response_data_size(resp) \
	( sizeof(*resp) + socks5_address_size(((struct socks5_address *)resp->bound_addr)) + sizeof(uint16_t) )
struct socks5_response_data * socks5_response_data_init(void * buf, unsigned char status, const struct socks5_address * bound_addr, uint16_t port);
	
struct socks5_response_data * socks5_response_data_init(void * buf, 
	unsigned char status, 
	const struct socks5_address * bound_addr, 
	uint16_t port)
{
	assert(bound_addr);
	size_t addr_size = socks5_address_size(bound_addr);
	struct socks5_response_data * resp = buf;
	if(NULL == resp) resp = calloc(1, sizeof(*resp) + addr_size + sizeof(uint16_t));
	assert(resp);
	
	resp->version = 0x05;
	resp->status = status;
	resp->reserved = 0;
	memcpy(resp->bound_addr, bound_addr, addr_size);
	*(uint16_t *)(resp->bound_addr + addr_size) = port;
	return resp;
}


int socks5_proxy_init(const char * proxy_server, const char * proxy_port, const char * user_name, const char * password)
{
	struct addrinfo hints, *serv_info = NULL, *p;
	memset(&hints, 0, sizeof(hints));
	
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	int rc = getaddrinfo(proxy_server, proxy_port, &hints, &serv_info);
	
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
		break;
	}
	
	freeaddrinfo(serv_info);
	if(NULL == p || fd == -1) return -1;
	
	unsigned char buf[SOCKS5_MSG_BUFFER_SIZE] = { 0 };
	struct socks5_query_auth * query_auth = socks5_query_auth_init(buf, 
		//2, 
		1
		, socks5_auth_method_no_auth
		//~ , socks5_auth_method_user_pass
	);
	assert(query_auth);
	
	ssize_t length = socks5_query_auth_size(query_auth);
	ssize_t cb = write(fd, query_auth, length);
	assert(cb == length);
	
	memset(buf, 0, sizeof(buf));
	cb = read(fd, buf, sizeof(buf));
	assert(cb == sizeof(struct socks5_auth));
	
	struct socks5_auth * auth = (struct socks5_auth *)buf;
	debug_printf("auth_method: %d", (int)auth->method);
	if(auth->method == socks5_auth_method_user_pass) {
		memset(buf, 0, sizeof(buf));
		
		struct socks5_auth_user_pass * user_pass = socks5_auth_user_pass_init(buf, user_name, password);
		assert(user_pass);
		
		length = socks5_auth_user_pass_size(user_pass);
		cb = write(fd, user_pass, length);
		assert(cb == length);
		
		
		memset(buf, 0, sizeof(buf));
		cb = read(fd, buf, sizeof(buf));
		assert(cb == sizeof(struct socks5_auth_response));
		
		struct socks5_auth_response * auth_resp = (struct socks5_auth_response *)buf;
		assert(auth_resp->auth_ver == 1);
		
		if(auth_resp->status != 0) {
			close(fd);
			fd = -1;
		}
	}
	return fd;
}

int socks5_proxy_connect2(int proxy_fd, const char * dst_addr, uint16_t dst_port)
{
	unsigned char buf[SOCKS5_MSG_BUFFER_SIZE] = { 0 };
	unsigned char addr_buf[SOCKS5_ADDR_BUFFER_SIZE] = { 0 };
	
	struct socks5_address * addr = (struct socks5_address *)addr_buf;
	int rc = socks5_address_parse(dst_addr, &addr);
	assert(0 == rc);
	
	dst_port = htons(dst_port);
	struct socks5_request_data * req = (struct socks5_request_data *)socks5_request_data_init(
		buf, 
		socks5_command_tcp_connect, 
		addr, dst_port);
	
	ssize_t length = socks5_request_data_size(req);
	ssize_t cb = write(proxy_fd, req, length);
	assert(cb == length);
	
	
	memset(buf, 0, sizeof(buf));
	cb = read(proxy_fd, buf, sizeof(buf));
	
	struct socks5_response_data * resp = (struct socks5_response_data *)buf;
	assert(cb == socks5_response_data_size(resp));
	
	
#ifdef _DEBUG
	addr = (struct socks5_address *)resp->bound_addr;
	char * sz_addr = NULL;
	
	ssize_t cb_addr = socks5_address_size(addr);
	
	switch(addr->type)
	{
	case socks5_address_type_domain_name:
		sz_addr = (char *)addr_buf;
		strncpy(sz_addr, (char *)&addr->data[1], (int)addr->data[0]);
		break;
	case socks5_address_type_ipv4:
		for(int i = 0; i < 4; ++i) printf("%.2x ", addr->data[i]);
		printf("\n");
		sz_addr = (char *)inet_ntop(PF_INET, addr->data, (char *)addr_buf, 4);
		
		break;
	case socks5_address_type_ipv6:
		for(int i = 0; i < 16; ++i) printf("%.2x ", addr->data[i]);
		printf("\n");
		sz_addr = (char *)inet_ntop(PF_INET6, addr->data, (char *)addr_buf, 16);
		break;
	default:
		break;
	}
	
	printf("resp: status=%d, addr_type=%d, bounding to: %s, port=%hu\n", 
		resp->status, addr->type, sz_addr,
		ntohs(*(uint16_t *)(resp->bound_addr + cb_addr))
		);
#endif
	return 0;
}


#if defined(_TEST_SOCKS5_PROXY) && defined(_STAND_ALONE)
int main(int argc, char **argv)
{
	int fd = socks5_proxy_init("127.0.0.1", "9050", NULL, NULL);
	printf("proxy fd: %d\n", fd);
	assert(fd > 0);
	
	const char * serv_name = "118.8.95.149";
	uint32_t port = 8080;
	if(argc > 1) serv_name = argv[1];
	if(argc > 2) port = atoi(argv[2]);
	assert(port < 65536);
	
	
	int rc = socks5_proxy_connect2(fd, serv_name, port);
	printf("create tunnel: status=%d\n", rc);
	assert(0 == rc);
	
	static const char * http_req_fmt = "GET / HTTP/1.1\r\n"
		"Host: %s:%u\r\n"
		"User-Agent: bitcoin-clib/client-0.1alpha\r\n"
		"Accept: */*\r\n"
		"\r\n";
	char buf[4096] = "";
	int cb_request = snprintf(buf, sizeof(buf), 
		http_req_fmt, 
		serv_name, (unsigned int)port);
	
	ssize_t cb = write(fd, buf, cb_request);
	assert(cb == cb_request);
	
	memset(buf, 0, sizeof(buf));
	cb = read(fd, buf, sizeof(buf));
	
	printf("== http://%s:%u/\n", serv_name, (unsigned int)port);
	printf("response(cb=%d): %s"
		"--------------------\n", (int)cb, buf);

	close(fd);
	return 0;
}
#endif
