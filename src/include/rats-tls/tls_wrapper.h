/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _RATS_TLS_TLS_WRAPPER_H
#define _RATS_TLS_TLS_WRAPPER_H

#include <stdint.h>
#include <stddef.h>
#include <rats-tls/err.h>
#include <rats-tls/api.h>
#include <rats-tls/cert.h>
#include <rats-tls/endorsement.h>

#define TLS_WRAPPER_TYPE_MAX 32

#define TLS_WRAPPER_API_VERSION_1	1
#define TLS_WRAPPER_API_VERSION_MAX	TLS_WRAPPER_API_VERSION_1
#define TLS_WRAPPER_API_VERSION_DEFAULT TLS_WRAPPER_API_VERSION_1

#define TLS_WRAPPER_OPTS_FLAGS_SGX_ENCLAVE 1

typedef struct tls_wrapper_ctx tls_wrapper_ctx_t;

typedef struct {
	uint8_t api_version;
	unsigned long flags;
	const char name[TLS_TYPE_NAME_SIZE];
	uint8_t priority;

	/* Optional */
	tls_wrapper_err_t (*pre_init)(void);
	tls_wrapper_err_t (*init)(tls_wrapper_ctx_t *ctx);
	tls_wrapper_err_t (*use_privkey)(tls_wrapper_ctx_t *ctx, rats_tls_cert_algo_t algo,
					 void *privkey_buf, size_t privkey_len);
	tls_wrapper_err_t (*use_cert)(tls_wrapper_ctx_t *ctx, rats_tls_cert_info_t *cert_info);
	tls_wrapper_err_t (*negotiate)(tls_wrapper_ctx_t *ctx, int fd);
	tls_wrapper_err_t (*transmit)(tls_wrapper_ctx_t *ctx, void *buf, size_t *buf_size);
	tls_wrapper_err_t (*receive)(tls_wrapper_ctx_t *ctx, void *buf, size_t *buf_size);
	tls_wrapper_err_t (*cleanup)(tls_wrapper_ctx_t *ctx);
} tls_wrapper_opts_t;

struct tls_wrapper_ctx {
	/* associate tls wrapper with the enclave verifier instances */
	struct rtls_core_context_t *rtls_handle;
	tls_wrapper_opts_t *opts;
	void *tls_private;
	int fd;
	unsigned long conf_flags;
	rats_tls_log_level_t log_level;
	void *handle;
};

extern tls_wrapper_err_t tls_wrapper_register(const tls_wrapper_opts_t *);

extern tls_wrapper_err_t
tls_wrapper_verify_certificate_extension(tls_wrapper_ctx_t *tls_ctx, const uint8_t *pubkey_buffer,
					 size_t pubkey_buffer_size, uint8_t *evidence_buffer,
					 size_t evidence_buffer_size, uint8_t *endorsements_buffer,
					 size_t endorsements_buffer_size);

#endif
