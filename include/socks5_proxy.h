#ifndef _SOCKS5_PROXY_H_
#define _SOCKS5_PROXY_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

/**
 * socks5_proxy_init():		
 * 	Handshake with socks5 proxy server 
 * 
 * 	@param proxy_server	    proxy server ip or domain name
 * 	@param proxy_port		proxy server listening port
 *  @param user_name		(nullable)
 *  @param password			(nullable)
 * 
 * @return socket_fd on success, -1 on error.
 */
int socks5_proxy_init(const char * proxy_server, const char * proxy_port, const char * user_name, const char * password);

/**
 * socks5_proxy_connect2():	
 * 	Connect to (dst_addr:dst_port) via socks5 proxy.
 *  if successful, the proxy_fd can be regarded as directly connected to the dst:port
 * 
 * 	@param proxy_fd	    	return from socks5_proxy_init() function
 * 	@param dst_addr			destination ip or domain name
 *  @param dst_port			destination port
 * 
 * @return 0 on success, non-zero on error.
 */
int socks5_proxy_connect2(int proxy_fd, const char * dst_addr, uint16_t dst_port);

#ifdef __cplusplus
}
#endif
#endif
