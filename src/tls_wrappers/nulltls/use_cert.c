/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/tls_wrapper.h>

tls_wrapper_err_t nulltls_use_cert(tls_wrapper_ctx_t *ctx, uint8_t *cert_buf, size_t cert_len)
{
	RTLS_DEBUG("ctx: %p, cert_buf: %p, cert_len: %zu\n", ctx, cert_buf, cert_len);

	return TLS_WRAPPER_ERR_NONE;
}
