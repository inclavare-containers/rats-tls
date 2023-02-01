/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <rats-tls/log.h>
#include <rats-tls/tls_wrapper.h>
#include <rats-tls/hash.h>

tls_wrapper_err_t nulltls_negotiate(tls_wrapper_ctx_t *ctx, int fd)
{
	RTLS_DEBUG("ctx %p, fd %d\n", ctx, fd);

	if (!(ctx->conf_flags & RATS_TLS_CONF_FLAGS_SERVER) ||
	    ((ctx->conf_flags & RATS_TLS_CONF_FLAGS_MUTUAL) &&
	     (ctx->conf_flags & RATS_TLS_CONF_FLAGS_SERVER))) {
		RTLS_INFO(
			"there is no evidence in tls_wrapper_nulltls, so we just use a dummy evidence here");

		size_t pubkey_buffer_size = 0;
		uint8_t pubkey_buffer[pubkey_buffer_size];
		tls_wrapper_err_t err = tls_wrapper_verify_certificate_extension(
			ctx, pubkey_buffer, pubkey_buffer_size, NULL, 0, NULL, 0);
		if (err != TLS_WRAPPER_ERR_NONE) {
			RTLS_ERR("ERROR: failed to verify certificate extension\n");
			return err;
		}
	}
	return TLS_WRAPPER_ERR_NONE;
}
