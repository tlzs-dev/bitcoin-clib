#ifndef _SOCKS5_PROXY_H_
#define _SOCKS5_PROXY_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#define SOCKS5_MSG_BUFFER_SIZE	(512 + 1)	// large enough to hold each variable length structure
#define SOCKS5_ADDR_BUFFER_SIZE	(256)

int socks5_proxy_init(const char * proxy_server, const char * proxy_port, const char * user_name, const char * password);
int socks5_proxy_connect2(int proxy_fd, const char * dst_addr, uint16_t dst_port);

#ifdef __cplusplus
}
#endif
#endif
