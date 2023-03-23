/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/tls_wrapper.h>
#include "openssl.h"

tls_wrapper_err_t openssl_tls_transmit(tls_wrapper_ctx_t *ctx, void *buf, size_t *buf_size)
{
	RTLS_DEBUG("ctx %p, buf %p, buf_size %p\n", ctx, buf, buf_size);

	if (!ctx || !buf || !buf_size)
		return -TLS_WRAPPER_ERR_INVALID;

	openssl_ctx_t *ssl_ctx = (openssl_ctx_t *)ctx->tls_private;
	if (ssl_ctx == NULL || ssl_ctx->ssl == NULL)
		return -TLS_WRAPPER_ERR_TRANSMIT;

	ERR_clear_error();

	int rc = SSL_write(ssl_ctx->ssl, buf, (int)*buf_size);
	if (rc <= 0) {
		// TODO: handle result of SSL_get_error()
		RTLS_ERR("SSL_write() failed: %d, SSL_get_error(): %d\n", rc,
			 SSL_get_error(ssl_ctx->ssl, rc));
		print_openssl_err_all();
		return -TLS_WRAPPER_ERR_TRANSMIT;
	}
	*buf_size = (size_t)rc;

	return TLS_WRAPPER_ERR_NONE;
}
