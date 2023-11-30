/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _OPENSSL_PRIVATE_H
#define _OPENSSL_PRIVATE_H

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/ossl_typ.h>

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>

#define SSL_SUCCESS 1

extern int openssl_ex_data_idx;

extern int verify_certificate(int preverify_ok, X509_STORE_CTX *store);

typedef struct {
	SSL_CTX *sctx;
	SSL *ssl;
} openssl_ctx_t;

static inline void print_openssl_err_all()
{
	unsigned long l;

	while ((l = ERR_get_error())) {
		char buf[1024];

		ERR_error_string_n(l, buf, sizeof buf);
		RTLS_DEBUG("Error %lx: %s\n", l, buf);
	}
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
extern int X509_STORE_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
				       CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
extern const STACK_OF(X509_EXTENSION) * X509_get0_extensions(const X509 *x);
extern int X509_STORE_set_ex_data(X509_STORE *ctx, int idx, void *data);
extern void *X509_STORE_get_ex_data(const X509_STORE *ctx, int idx);
extern X509_STORE *X509_STORE_CTX_get0_store(X509_STORE_CTX *ctx);
extern int X509_get_signature_info(X509 *x, int *mdnid, int *pknid, int *secbits, uint32_t *flags);
#endif
#endif
