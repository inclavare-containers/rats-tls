/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <rats-tls/api.h>
#include <rats-tls/log.h>
#include <rats-tls/claim.h>
#include "internal/core.h"
#include "internal/crypto_wrapper.h"
#include "internal/tls_wrapper.h"
#include "internal/attester.h"
#include "internal/verifier.h"
#include <openssl/opensslv.h>

rats_tls_err_t rats_tls_init(const rats_tls_conf_t *conf, rats_tls_handle *handle)
{
	if (!conf || !handle)
		return -RATS_TLS_ERR_INVALID;

	RTLS_DEBUG("conf %p, handle %p\n", conf, handle);

	rtls_core_context_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -RATS_TLS_ERR_NO_MEM;

	ctx->config = *conf;

	rats_tls_err_t err = -RATS_TLS_ERR_INVALID;

	if (ctx->config.api_version > RATS_TLS_API_VERSION_MAX) {
		RTLS_ERR("unsupported rats-tls api version %d > %d\n", ctx->config.api_version,
			 RATS_TLS_API_VERSION_MAX);
		goto err_ctx;
	}

	if (ctx->config.log_level < 0 || ctx->config.log_level >= RATS_TLS_LOG_LEVEL_MAX) {
		ctx->config.log_level = global_core_context.config.log_level;
		RTLS_WARN("log level reset to global value %d\n",
			  global_core_context.config.log_level);
	}

	/* FIXME: it is intended to use the certificate with different algorithm */
	if (ctx->config.cert_algo == RATS_TLS_CERT_ALGO_DEFAULT) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		ctx->config.cert_algo = RATS_TLS_CERT_ALGO_RSA_3072_SHA256;
#else
		ctx->config.cert_algo = RATS_TLS_CERT_ALGO_ECC_256_SHA256;
#endif
	}

	if (ctx->config.cert_algo < 0 || ctx->config.cert_algo >= RATS_TLS_CERT_ALGO_MAX) {
		ctx->config.cert_algo = global_core_context.config.cert_algo;
		RTLS_WARN("certificate algorithm reset to global value %d\n",
			  global_core_context.config.cert_algo);
	}

	global_log_level = ctx->config.log_level;

	/* Make a copy of user-defined custom claims */
	if (conf->custom_claims && conf->custom_claims_length) {
		RTLS_DEBUG("conf->custom_claims: %p conf->custom_claims_length: %zu\n",
			   conf->custom_claims, conf->custom_claims_length);
		ctx->config.custom_claims =
			clone_claims_list(conf->custom_claims, conf->custom_claims_length);
		err = RATS_TLS_ERR_NO_MEM;
		if (!ctx->config.custom_claims) {
			RTLS_ERR("failed to make copy of custom claims: out of memory\n");
			goto err_ctx;
		}
		ctx->config.custom_claims_length = conf->custom_claims_length;
	} else {
		ctx->config.custom_claims = NULL;
		ctx->config.custom_claims_length = 0;
	}

	/* Select the target crypto wrapper to be used */
	char *choice = ctx->config.crypto_type;
	if (choice[0] == '\0') {
		choice = global_core_context.config.crypto_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	err = rtls_crypto_wrapper_select(ctx, choice);
	if (err != RATS_TLS_ERR_NONE)
		goto err_ctx;

	/* Select the target attester to be used */
	choice = ctx->config.attester_type;
	if (choice[0] == '\0') {
		choice = global_core_context.config.attester_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	err = rtls_attester_select(ctx, choice, ctx->config.cert_algo);
	if (err != RATS_TLS_ERR_NONE)
		goto err_ctx;

	/* Select the target verifier to be used */
	choice = ctx->config.verifier_type;
	if (choice[0] == '\0') {
		choice = global_core_context.config.verifier_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	err = rtls_verifier_select(ctx, choice, ctx->config.cert_algo);
	if (err != RATS_TLS_ERR_NONE)
		goto err_ctx;

	/* Select the target tls wrapper to be used */
	choice = ctx->config.tls_type;
	if (choice[0] == '\0') {
		choice = global_core_context.config.tls_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	err = rtls_tls_wrapper_select(ctx, choice);
	if (err != RATS_TLS_ERR_NONE)
		goto err_ctx;

	/* Check whether requiring to generate TLS certificate */
	if ((ctx->config.flags & RATS_TLS_CONF_FLAGS_SERVER) ||
	    (ctx->config.flags & RATS_TLS_CONF_FLAGS_MUTUAL)) {
		/* Avoid re-generation of TLS certificates */
		if (!(ctx->flags & RATS_TLS_CTX_FLAGS_CERT_CREATED)) {
			err = rtls_core_generate_certificate(ctx);
			if (err != RATS_TLS_ERR_NONE)
				goto err_ctx;
			ctx->flags |= RATS_TLS_CTX_FLAGS_CERT_CREATED;
		}
	}

	*handle = ctx;

	RTLS_DEBUG("the handle %p returned\n", ctx);

	return RATS_TLS_ERR_NONE;

err_ctx:
	free(ctx);
	return err;
}
