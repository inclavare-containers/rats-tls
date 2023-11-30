/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <rats-tls/log.h>
#include <rats-tls/err.h>
#include <rats-tls/tls_wrapper.h>
#include "openssl.h"

tls_wrapper_err_t openssl_internal_negotiate(tls_wrapper_ctx_t *ctx, unsigned long conf_flags,
					     int fd, int (*verify)(int, X509_STORE_CTX *))
{
	openssl_ctx_t *ssl_ctx = ctx->tls_private;

	/*
	 * Set the verification mode.
	 * Refer to https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_verify.html
	 *
	 * client: SSL_VERIFY_PEER
	 * server: SSL_VERIFY_NONE
	 * client+mutual: SSL_VERIFY_PEER
	 * server+mutual: SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
	 */
	if (verify) {
		int mode = SSL_VERIFY_NONE;

		if (!(conf_flags & RATS_TLS_CONF_FLAGS_SERVER))
			mode |= SSL_VERIFY_PEER;
		else if (conf_flags & RATS_TLS_CONF_FLAGS_MUTUAL)
			mode |= SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

		SSL_CTX_set_verify(ssl_ctx->sctx, mode, verify);
	}

	SSL *ssl = SSL_new(ssl_ctx->sctx);
	if (!ssl)
		return -TLS_WRAPPER_ERR_NO_MEM;

	X509_STORE *cert_store = SSL_CTX_get_cert_store(ssl_ctx->sctx);
	X509_STORE_set_ex_data(cert_store, openssl_ex_data_idx, ctx);

	/* Attach openssl to the socket */
	int ret = SSL_set_fd(ssl, fd);
	if (ret != SSL_SUCCESS) {
		RTLS_ERR("failed to attach SSL with fd, ret is %x\n", ret);
		return -TLS_WRAPPER_ERR_INVALID;
	}

	ERR_clear_error();
	int err;
	if (conf_flags & RATS_TLS_CONF_FLAGS_SERVER)
		err = SSL_accept(ssl);
	else
		err = SSL_connect(ssl);

	if (err != 1) {
		if (conf_flags & RATS_TLS_CONF_FLAGS_SERVER)
			RTLS_ERR("failed to negotiate %d, SSL_get_error(): %d\n", err,
				 SSL_get_error(ssl, err));
		else
			RTLS_ERR("failed to connect %d, SSL_get_error(): %d\n", err,
				 SSL_get_error(ssl, err));
		// TODO: handle result of SSL_get_error()
		print_openssl_err_all(ssl, err);

		return OPENSSL_ERR_CODE(err);
	}

	ssl_ctx->ssl = ssl;

	if (conf_flags & RATS_TLS_CONF_FLAGS_SERVER)
		RTLS_DEBUG("success to negotiate\n");
	else
		RTLS_DEBUG("success to connect\n");

	return TLS_WRAPPER_ERR_NONE;
}

tls_wrapper_err_t openssl_tls_negotiate(tls_wrapper_ctx_t *ctx, int fd)
{
	RTLS_DEBUG("ctx %p, fd %d\n", ctx, fd);

	if (!ctx)
		return -TLS_WRAPPER_ERR_INVALID;

	int (*verify)(int, X509_STORE_CTX *) = NULL;
	unsigned long conf_flags = ctx->conf_flags;

	if (!(conf_flags & RATS_TLS_CONF_FLAGS_SERVER) ||
	    (conf_flags & RATS_TLS_CONF_FLAGS_MUTUAL)) {
		verify = verify_certificate;
	}

	return openssl_internal_negotiate(ctx, conf_flags, fd, verify);
}
