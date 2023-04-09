/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2023 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common.h"

typedef void SSL_CTX;
typedef void X509_STORE_CTX;
typedef void SSL;
// https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_verify.html
typedef int (*SSL_verify_cb)(int preverify_ok, X509_STORE_CTX *x509_ctx);

typedef void X509;
typedef void EVP_PKEY;
typedef void RSA;
#define STACK_OF(type) void

typedef struct {
	// clang-format off
    // https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_verify.html
    void (*SSL_CTX_set_verify)(SSL_CTX *ctx, int mode, SSL_verify_cb verify_callback);
    void (*SSL_set_verify)(SSL *ssl, int mode, SSL_verify_cb verify_callback);
    // https://www.openssl.org/docs/man1.1.1/man3/SSL_accept.html
    int (*SSL_accept)(SSL *ssl);
    // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html
    int (*SSL_connect)(SSL *ssl);
	// clang-format on
} openssl_ctx_t;

static openssl_ctx_t openssl_ctx;

int init_openssl_ctx()
{
	/* Check if openssl  */
	void *dl_handle = dlopen("libssl.so", RTLD_LAZY | RTLD_NOLOAD);
	if (!dl_handle) {
		fprintf(stderr, "OpenSSL is not used, rats-tls would be disabled.\n");
		return 0;
	}

	return dlsym_load((void **)&openssl_ctx.SSL_CTX_set_verify, "SSL_CTX_set_verify") &&
	       dlsym_load((void **)&openssl_ctx.SSL_set_verify, "SSL_set_verify") &&
	       dlsym_load((void **)&openssl_ctx.SSL_accept, "SSL_accept") &&
	       dlsym_load((void **)&openssl_ctx.SSL_connect, "SSL_connect");
}

/* 
 * rats-tls wrapper functions
 */
int setup_verifier_with_openssl_ssl_ctx_obj(SSL_CTX *ctx)
{
	rats_tls_err_t ret = rats_tls_setup_ssl(global_rtls_handle, SETUP_VERIRIER,
						OPENSSL_SSL_CTX_POINTER, ctx);
	if (ret != RATS_TLS_ERR_NONE) {
		fprintf(stderr, "Failed to setup verifier: %#x\n", ret);
		return 0;
	}
	return 1;
}

int setup_verifier_with_openssl_ssl_obj(SSL *ssl)
{
	rats_tls_err_t ret =
		rats_tls_setup_ssl(global_rtls_handle, SETUP_VERIRIER, OPENSSL_SSL_POINTER, ssl);
	if (ret != RATS_TLS_ERR_NONE) {
		fprintf(stderr, "Failed to setup verifier: %#x\n", ret);
		return 0;
	}
	return 1;
}

int setup_attester_with_openssl_ssl_ctx_obj(SSL_CTX *ctx)
{
	rats_tls_err_t ret = rats_tls_setup_ssl(global_rtls_handle, SETUP_ATTESTER,
						OPENSSL_SSL_CTX_POINTER, ctx);
	if (ret != RATS_TLS_ERR_NONE) {
		fprintf(stderr, "Failed to setup setup attester: %#x\n", ret);
		return 0;
	}
	return 1;
}

int setup_attester_with_openssl_ssl_obj(SSL *ssl)
{
	rats_tls_err_t ret =
		rats_tls_setup_ssl(global_rtls_handle, SETUP_ATTESTER, OPENSSL_SSL_POINTER, ssl);
	if (ret != RATS_TLS_ERR_NONE) {
		fprintf(stderr, "Failed to setup setup attester: %#x\n", ret);
		return 0;
	}
	return 1;
}

/* 
 * Symbols (functions) that are hooked
 */

void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb verify_callback)
{
	fprintf(stderr, "SSL_CTX_set_verify() called\n");
	openssl_ctx.SSL_CTX_set_verify(ctx, mode, verify_callback);
	setup_verifier_with_openssl_ssl_ctx_obj(ctx);
}

void SSL_set_verify(SSL *ssl, int mode, SSL_verify_cb verify_callback)
{
	fprintf(stderr, "SSL_set_verify() called\n");
	openssl_ctx.SSL_set_verify(ssl, mode, verify_callback);
	setup_verifier_with_openssl_ssl_obj(ssl);
}

int SSL_accept(SSL *ssl)
{
	fprintf(stderr, "SSL_accept() called\n");
	setup_verifier_with_openssl_ssl_obj(ssl);
	return openssl_ctx.SSL_accept(ssl);
}

int SSL_connect(SSL *ssl)
{
	fprintf(stderr, "SSL_connect() called\n");
	setup_verifier_with_openssl_ssl_obj(ssl);
	return openssl_ctx.SSL_connect(ssl);
}

// https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_use_certificate.html
int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x)
{
	return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}
int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len, unsigned char *d)
{
	return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}
int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type)
{
	return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}
int SSL_use_certificate(SSL *ssl, X509 *x)
{
	return setup_attester_with_openssl_ssl_obj(ssl);
}
int SSL_use_certificate_ASN1(SSL *ssl, unsigned char *d, int len)
{
	return setup_attester_with_openssl_ssl_obj(ssl);
}
int SSL_use_certificate_file(SSL *ssl, const char *file, int type)
{
	return setup_attester_with_openssl_ssl_obj(ssl);
}
int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file)
{
	return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}
int SSL_use_certificate_chain_file(SSL *ssl, const char *file)
{
	return setup_attester_with_openssl_ssl_obj(ssl);
}
int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)
{
	return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}
int SSL_CTX_use_PrivateKey_ASN1(int pk, SSL_CTX *ctx, unsigned char *d, long len)
{
	return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type)
{
	return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}
int SSL_CTX_use_RSAPrivateKey(SSL_CTX *ctx, RSA *rsa)
{
	return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}
int SSL_CTX_use_RSAPrivateKey_ASN1(SSL_CTX *ctx, unsigned char *d, long len)
{
	return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}
int SSL_CTX_use_RSAPrivateKey_file(SSL_CTX *ctx, const char *file, int type)
{
	return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}
int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey)
{
	return setup_attester_with_openssl_ssl_obj(ssl);
}
int SSL_use_PrivateKey_ASN1(int pk, SSL *ssl, unsigned char *d, long len)
{
	return setup_attester_with_openssl_ssl_obj(ssl);
}
int SSL_use_PrivateKey_file(SSL *ssl, const char *file, int type)
{
	return setup_attester_with_openssl_ssl_obj(ssl);
}
int SSL_use_RSAPrivateKey(SSL *ssl, RSA *rsa)
{
	return setup_attester_with_openssl_ssl_obj(ssl);
}
int SSL_use_RSAPrivateKey_ASN1(SSL *ssl, unsigned char *d, long len)
{
	return setup_attester_with_openssl_ssl_obj(ssl);
}
int SSL_use_RSAPrivateKey_file(SSL *ssl, const char *file, int type)
{
	return setup_attester_with_openssl_ssl_obj(ssl);
}
int SSL_CTX_use_cert_and_key(SSL_CTX *ctx, X509 *x, EVP_PKEY *pkey, STACK_OF(X509) * chain,
			     int override)
{
	return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}
int SSL_use_cert_and_key(SSL *ssl, X509 *x, EVP_PKEY *pkey, STACK_OF(X509) * chain, int override)
{
	return setup_attester_with_openssl_ssl_obj(ssl);
}
