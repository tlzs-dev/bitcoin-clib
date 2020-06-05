#ifndef _SATOSHI_TX_H_
#define _SATOSHI_TX_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include "satoshi-types.h"
#include "sha.h"

/* 
 * satoshi_rawtx:
 * 	generate digest for sign / verify 
 */
typedef struct satoshi_rawtx 
{
	satoshi_tx_t * tx;
	struct scripts_data * backup;	// backup txins[] scripts for legacy-tx
	sha256_ctx_t sha[1]; // internal states: <-- sha(common_data)
	unsigned char txouts_hash[32]; // segwit_v0: generate preiamge step 8 
}satoshi_rawtx_t;
satoshi_rawtx_t * satoshi_rawtx_prepare(satoshi_rawtx_t * rawtx, satoshi_tx_t * tx);
void satoshi_rawtx_final(satoshi_rawtx_t * rawtx);

#ifdef __cplusplus
}
#endif
#endif
