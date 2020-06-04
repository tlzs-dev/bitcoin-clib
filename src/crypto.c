/*
 * crypto.c
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



#include <ctype.h>		// for ptrdiff_t
#include <secp256k1.h>	// use https://github.com/bitcoin/bitcoin/tree/master/src/secp256k1


#include "crypto.h"


typedef struct crypto_context_private
{
	crypto_context_t * crypto;
	secp256k1_context * sign_ctx;		
	secp256k1_context * verify_ctx;
}crypto_context_private_t;


#define MAX_PUBKEY_DATA_LENGTH (65)

struct crypto_pubkey
{
	secp256k1_pubkey key[1];
	unsigned char data[MAX_PUBKEY_DATA_LENGTH];
	size_t cb_data;
	int compressed_flag;
};

#define PRIVKEY_SIZE (32)
struct crypto_privkey
{
	unsigned char key[PRIVKEY_SIZE];
	size_t length;
	struct crypto_pubkey pubkey[1];
}; 

crypto_privkey_t * crypto_privkey_import(crypto_context_t * crypto, const unsigned char * secdata, ssize_t length)
{
	assert(crypto && crypto->priv);
	assert(secdata && length <= 32);
	
	crypto_context_private_t * priv = crypto->priv;
	secp256k1_context * secp = priv->sign_ctx;
	assert(secp);
	
	crypto_privkey_t * privkey = calloc(1, sizeof(*privkey));
	assert(privkey);
	
	memcpy(privkey->key, secdata, length);
	int ok = secp256k1_ec_seckey_verify(secp, privkey->key);
	if(!ok)
	{
		fprintf(stderr, "[ERROR]: invalid privkey data.");
		memset(privkey->key, 0, sizeof(privkey->key)); // clear sensitive data
		free(privkey);
		return NULL;
	}
	
	ok = secp256k1_ec_pubkey_create(secp, privkey->pubkey->key, privkey->key);
	if(!ok)
	{
		fprintf(stderr, "[ERROR]: calc pubkey failed.");
		memset(privkey->key, 0, sizeof(privkey->key)); // clear sensitive data
		free(privkey);
		return NULL;
	}
	
	privkey->length = PRIVKEY_SIZE;	// to confirm this is a valid key
	
	return privkey;
}
ssize_t crypto_privkey_export(crypto_context_t * crypto, const crypto_privkey_t * privkey, unsigned char ** p_secdata)
{
	assert(crypto && crypto->priv);
	assert(privkey);

	if(privkey->length != PRIVKEY_SIZE) return -1;	// invalid key
	if(NULL == p_secdata) return PRIVKEY_SIZE;		// return key length

	unsigned char * secdata = *p_secdata;
	if(NULL == secdata)
	{
		secdata = malloc(PRIVKEY_SIZE);
		assert(secdata);
		*p_secdata = secdata;
	}
	
	memcpy(secdata, privkey->key, PRIVKEY_SIZE);
	return PRIVKEY_SIZE;
}
void crypto_privkey_free(crypto_privkey_t * privkey)
{
	free(privkey);
}

crypto_pubkey_t * crypto_pubkey_import(crypto_context_t * crypto, const unsigned char * pubkey_data, size_t length)
{
	assert(crypto && crypto->priv);
	assert(pubkey_data && length <= MAX_PUBKEY_DATA_LENGTH);
	
	crypto_context_private_t * priv = crypto->priv;
	secp256k1_context * secp = priv->verify_ctx;
	assert(secp);
	
	crypto_pubkey_t * pubkey = calloc(1, sizeof(*pubkey));
	assert(pubkey);
	
	int ok = secp256k1_ec_pubkey_parse(secp, pubkey->key, pubkey_data, length);
	if(!ok)
	{
		fprintf(stderr, "[ERROR]: parse pubkey failed.");
		free(pubkey);
		return NULL;
	}
	return pubkey;
}
ssize_t crypto_pubkey_export(crypto_context_t * crypto, crypto_pubkey_t * pubkey, 
	int compressed_flag, unsigned char ** p_pubkey_data)
{
	assert(crypto && crypto->priv);
	assert(pubkey);
	
	crypto_context_private_t * priv = crypto->priv;
	secp256k1_context * secp = priv->verify_ctx;
	
	int ok = 0;
	if(0 == pubkey->cb_data || compressed_flag != pubkey->compressed_flag)
	{
		pubkey->cb_data = sizeof(pubkey->data);
		ok = secp256k1_ec_pubkey_serialize(secp, 
			pubkey->data, &pubkey->cb_data, 
			pubkey->key, 
			compressed_flag?SECP256K1_EC_COMPRESSED:SECP256K1_EC_UNCOMPRESSED);
		if(!ok)
		{
			fprintf(stderr, "[ERROR]: serialize pubkey failed.");
			pubkey->cb_data = 0;
			return -1;
		}
		pubkey->compressed_flag = compressed_flag;
	}
	
	if(NULL == p_pubkey_data) return pubkey->cb_data;	// return data length
	
	assert(pubkey->cb_data > 0 && pubkey->cb_data < MAX_PUBKEY_DATA_LENGTH);
	unsigned char * pubkey_data = *p_pubkey_data;
	if(NULL == pubkey_data)
	{
		pubkey_data = malloc(pubkey->cb_data);
		assert(pubkey_data);
		
		*p_pubkey_data = pubkey_data;
	}
	memcpy(pubkey_data, pubkey->data, pubkey->cb_data);
	return pubkey->cb_data;
}
void crypto_pubkey_free(crypto_pubkey_t * pubkey)
{
	free(pubkey);
}



crypto_context_private_t * crypto_context_private_new(crypto_context_t * crypto)
{
	assert(crypto);
	crypto_context_private_t * priv = calloc(1, sizeof(*priv));
	assert(priv);
	
	priv->crypto = crypto;
	crypto->priv = priv;
	
	priv->sign_ctx = secp256k1_context_create(SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN);
	priv->verify_ctx = secp256k1_context_create(SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY);
	
	assert(priv->sign_ctx && priv->verify_ctx);
	
	return priv;
}

void crypto_context_private_free(crypto_context_private_t * priv)
{
	if(NULL == priv) return;
	if(priv->sign_ctx)
	{
		secp256k1_context_destroy(priv->sign_ctx);
		priv->sign_ctx = NULL;
	}
	if(priv->verify_ctx)
	{
		secp256k1_context_destroy(priv->verify_ctx);
		priv->verify_ctx = NULL;
	}
	free(priv);
	return;
}

static int crypto_sign(struct crypto_context * crypto, 
	const unsigned char * msg, size_t msg_len,
	const crypto_privkey_t * privkey, 
	unsigned char ** p_signatuer_der, ssize_t * p_cb_sig_der)
{
	assert(crypto && crypto->priv);
	assert(privkey && msg);
		
	crypto_context_private_t * priv = crypto->priv;
	secp256k1_context * secp = priv->sign_ctx;
	assert(secp);
	
	secp256k1_ecdsa_signature sig[1];
	memset(sig, 0, sizeof(sig));
	
	int ok = secp256k1_ecdsa_sign(secp, sig, 
		(unsigned char *)msg, 
		privkey->key, 
		secp256k1_nonce_function_default, NULL);
	if(ok > 0) return 0;
	return -1;
}
static int crypto_verify(struct crypto_context * crypto, 
	const unsigned char * msg, size_t msg_len,
	const crypto_pubkey_t * pubkey, 
	const unsigned char * sig_der, size_t cb_sig_der)
{
	assert(crypto && crypto->priv);
	assert(pubkey && msg && sig_der && cb_sig_der > 0);
		
	crypto_context_private_t * priv = crypto->priv;
	secp256k1_context * secp = priv->verify_ctx;
	assert(secp);
	
	secp256k1_ecdsa_signature sig[1];
	memset(sig, 0, sizeof(sig));
	
	int ok = 0;
	ok = secp256k1_ecdsa_signature_parse_der(secp, sig, sig_der, cb_sig_der);
	if(!ok)
	{
		fprintf(stderr, "[ERROR]: parse signature failed.\n");
		return -1;
	}
	
	ok = secp256k1_ecdsa_verify(secp, sig, 
		msg,
		pubkey->key);
	if(ok > 0) return 0;
	return -1;
}

crypto_context_t * crypto_context_init(crypto_context_t * crypto, enum crypto_backend_type * backend, void * user_data)
{
	assert(backend == crypto_backend_libsecp256);
	if(NULL == crypto) crypto = calloc(1, sizeof(* crypto));
	assert(crypto);
	
	crypto->user_data = user_data;
	crypto->sign = crypto_sign;
	crypto->verify = crypto_verify;
	
	crypto_context_private_t * priv = crypto_context_private_new(crypto);
	assert(priv && crypto->priv == priv);
	
	
	return crypto;
}
void crypto_context_cleanup(crypto_context_t * crypto)
{
	if(crypto)
	{
		crypto_context_private_free(crypto->priv);
		crypto->priv = NULL;
	}
	return;
}



#undef PRIVKEY_SIZE

#if defined(_TEST_CRYPTO) && defined(_STAND_ALONE)
int main(int argc, char **argv)
{
	unsigned char hmac_key[16] = { 0x01, };
	unsigned char hash[64] = { 0 };
	hmac256(hmac_key, 16, (unsigned char *)"hello world", 11, hash);
	
	for(int i = 0; i < 32; ++i)
	{
		printf("%.2x", hash[i]);
	}
	printf("\n");
	
	aes256_gcm_ctx_t aes[1];
	
	unsigned char message[1024];
	unsigned char cipher[1024] = { 0 };
	unsigned char plain[1024] = { 0 };
	for(int i = 0; i < (int)(sizeof(message) / sizeof(message[0])); ++i)
	{
		message[i] = i * 2;
	}
	aes256_gcm_init(aes, hash);
	aes256_gcm_encrypt(aes, 1024 / 16, cipher, message);
	
	aes256_gcm_decrypt(aes, 1024 / 16, plain, cipher);
	
	for(int i = 0; i < (int)(sizeof(plain) / sizeof(plain[0])); ++i)
	{
		printf(" %.2x <-- %.2x | ", plain[i], cipher[i]);
		if((i & 0x0f) == 0x0F) printf("\n");
	}
	return 0;
}
#endif
