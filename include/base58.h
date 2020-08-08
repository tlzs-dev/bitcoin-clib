#ifndef _BASE58_H_
#define _BASE58_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

ssize_t base58_encode(const void * data, ssize_t length, char ** p_b58);
ssize_t base58_decode(const char * b58, ssize_t cb_b58, unsigned char ** p_dst);

#ifdef __cplusplus
}
#endif
#endif
