#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include "sha.h"
#include "hmac.h"
#include "aes.h"
#include "ripemd.h"

enum crypto_backend_type
{
	crypto_backend_libsecp256,
	//~ crypto_backend_openssl,
	//~ crypto_backend_gnutls,	// need to add secp256k1 impl.
	//~ crypto_backend_libgmp,	// use arbitrary precision arithmetic library to calc directly
	//~ crypto_backend_custom,
};

typedef struct crypto_privkey crypto_privkey_t; 		// opaque data structure that holds a privkey.
typedef struct crypto_pubkey crypto_pubkey_t;			// opaque data structure that holds a pubkey.
typedef struct crypto_signature crypto_signature_t; 	// opaque data structure that holds a ecdsa signature.

typedef struct crypto_context
{
	void * user_data;
	void * priv;
	
	/**
	 * sign / verify: 
	 * 	@return 	0 on success, -1 on sign/verify failed or unknown error.
	 */
	int (* sign)(struct crypto_context * crypto, 
		const unsigned char * msg, size_t msg_len, 
		const crypto_privkey_t * privkey, 	/* INPUT */
		unsigned char ** p_signatuer_der, ssize_t * p_cb_sig_der	/* OUTPUT */
	);
	int (* verify)(struct crypto_context * crypto, 
		const unsigned char * msg, size_t msg_len,
		const crypto_pubkey_t * pubkey, 
		const unsigned char * sig_der, size_t cb_sig_der);
	
}crypto_context_t;
crypto_context_t * crypto_context_init(crypto_context_t * crypto, enum crypto_backend_type * backend, void * user_data);
void crypto_context_cleanup(crypto_context_t * crypto);


crypto_privkey_t * crypto_privkey_import(crypto_context_t * crypto, const unsigned char * secdata, ssize_t length);
ssize_t crypto_privkey_export(crypto_context_t * crypto, 
	const crypto_privkey_t * privkey, 
	unsigned char ** p_secdata);
void crypto_privkey_free(crypto_privkey_t * privkey);
const crypto_pubkey_t * crypto_privkey_get_pubkey(crypto_privkey_t * privkey);

crypto_pubkey_t * crypto_pubkey_import(crypto_context_t * crypto, const unsigned char * pubkey_data, size_t length);
ssize_t crypto_pubkey_export(crypto_context_t * crypto, 
	crypto_pubkey_t * pubkey, int compressed_flag, 
	unsigned char ** p_pubkey_data);
void crypto_pubkey_free(crypto_pubkey_t * pubkey);

crypto_signature_t * crypto_signature_import(crypto_context_t * crypto, const unsigned char * sig_der, size_t length);
ssize_t crypto_signature_export(crypto_context_t * crypto, const crypto_signature_t * sig, unsigned char ** p_sig_der);
void crypto_signature_free(crypto_signature_t * sig);

#ifdef __cplusplus
}
#endif
#endif
