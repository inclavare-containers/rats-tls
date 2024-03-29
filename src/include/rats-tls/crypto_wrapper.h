/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _RATS_TLS_CRYPTO_WRAPPER_H
#define _RATS_TLS_CRYPTO_WRAPPER_H

#include <stdint.h>
#include <stddef.h>
#include <rats-tls/compilation.h>
#include <rats-tls/err.h>
#include <rats-tls/api.h>
#include <rats-tls/cert.h>
#include <rats-tls/hash.h>

#define CRYPTO_WRAPPER_TYPE_MAX 32

#define CRYPTO_WRAPPER_API_VERSION_1	   1
#define CRYPTO_WRAPPER_API_VERSION_MAX	   CRYPTO_WRAPPER_API_VERSION_1
#define CRYPTO_WRAPPER_API_VERSION_DEFAULT CRYPTO_WRAPPER_API_VERSION_1

#define CRYPTO_WRAPPER_OPTS_FLAGS_SGX_ENCLAVE 1

typedef struct crypto_wrapper_ctx crypto_wrapper_ctx_t;

typedef struct {
	uint8_t api_version;
	unsigned long flags;
	const char name[CRYPTO_TYPE_NAME_SIZE];
	uint8_t priority;

	/* Optional */
	crypto_wrapper_err_t (*pre_init)(void);
	crypto_wrapper_err_t (*init)(crypto_wrapper_ctx_t *ctx);
	crypto_wrapper_err_t (*gen_privkey)(crypto_wrapper_ctx_t *ctx, rats_tls_cert_algo_t algo,
					    uint8_t *privkey_buf, unsigned int *privkey_len);
	crypto_wrapper_err_t (*gen_pubkey_hash)(crypto_wrapper_ctx_t *ctx,
						rats_tls_cert_algo_t algo, uint8_t *hash);
	crypto_wrapper_err_t (*gen_hash)(crypto_wrapper_ctx_t *ctx, hash_algo_t hash_algo,
					 const uint8_t *data, size_t size, uint8_t *hash);
	crypto_wrapper_err_t (*gen_cert)(crypto_wrapper_ctx_t *ctx, rats_tls_cert_algo_t algo,
					 rats_tls_cert_info_t *cert_info);
	crypto_wrapper_err_t (*cleanup)(crypto_wrapper_ctx_t *ctx);
} crypto_wrapper_opts_t;

struct crypto_wrapper_ctx {
	crypto_wrapper_opts_t *opts;
	void *crypto_private;
	unsigned long conf_flags;
	rats_tls_log_level_t log_level;
	rats_tls_cert_algo_t cert_algo;
	void *handle;
};

extern crypto_wrapper_err_t crypto_wrapper_register(const crypto_wrapper_opts_t *);

#endif /* _ENCLAVE_CRYPTO_WRAPPER_H */
