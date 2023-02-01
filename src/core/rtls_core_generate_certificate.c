/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/err.h>
#include "internal/core.h"
#include "internal/attester.h"
#include "internal/verifier.h"
#include "internal/dice.h"
#include <string.h>

rats_tls_err_t rtls_core_generate_certificate(rtls_core_context_t *ctx)
{
	RTLS_DEBUG("ctx %p\n", ctx);

	if (!ctx || !ctx->tls_wrapper || !ctx->tls_wrapper->opts || !ctx->crypto_wrapper ||
	    !ctx->crypto_wrapper->opts || !ctx->crypto_wrapper->opts->gen_pubkey_hash ||
	    !ctx->crypto_wrapper->opts->gen_cert)
		return -RATS_TLS_ERR_INVALID;

	/* Avoid re-generation of TLS certificates */
	if (ctx->flags & RATS_TLS_CTX_FLAGS_CERT_CREATED)
		return RATS_TLS_ERR_NONE;

	/* Check whether the specified algorithm is supported.
	 *
	 * TODO: the supported algorithm list should be provided by a crypto
	 * wrapper instance, and the core logic can search a proper crypto
	 * wrapper instance to address the requesting algorithm.
	 */
	unsigned int hash_size;

	switch (ctx->config.cert_algo) {
	case RATS_TLS_CERT_ALGO_RSA_3072_SHA256:
	case RATS_TLS_CERT_ALGO_ECC_256_SHA256:
		hash_size = SHA256_HASH_SIZE;
		break;
	default:
		RTLS_DEBUG("unknown algorithm %d\n", ctx->config.cert_algo);
		return -RATS_TLS_ERR_UNSUPPORTED_CERT_ALGO;
	}

	/* Generate the new key */
	crypto_wrapper_err_t c_err;
	uint8_t privkey_buf[2048];
	unsigned int privkey_len = sizeof(privkey_buf);
	c_err = ctx->crypto_wrapper->opts->gen_privkey(ctx->crypto_wrapper, ctx->config.cert_algo,
						       privkey_buf, &privkey_len);
	if (c_err != CRYPTO_WRAPPER_ERR_NONE)
		return c_err;

	/* Generate the hash of public key */
	uint8_t hash[hash_size];
	c_err = ctx->crypto_wrapper->opts->gen_pubkey_hash(ctx->crypto_wrapper,
							   ctx->config.cert_algo, hash);
	if (c_err != CRYPTO_WRAPPER_ERR_NONE)
		return c_err;

	/* Collect evidence */
	attestation_evidence_t evidence;
	memset(&evidence, 0, sizeof(attestation_evidence_t));

	// TODO: implement per-session freshness and put "nonce" in custom claims list.
	uint8_t *claims_buffer = NULL;
	size_t claims_buffer_size = 0;

	/* Using sha256 hash of claims_buffer as user data */
	RTLS_DEBUG("fill evidence user-data field with sha256 of claims_buffer\n");
	/* Generate claims_buffer */
	enclave_attester_err_t a_ret = dice_generate_claims_buffer(
		HASH_ALGO_SHA256, hash, ctx->config.custom_claims, ctx->config.custom_claims_length,
		&claims_buffer, &claims_buffer_size);
	if (a_ret != ENCLAVE_ATTESTER_ERR_NONE) {
		RTLS_DEBUG("generate claims_buffer failed. a_ret: %#x\n", a_ret);
		return a_ret;
	}

	/* Note here we reuse `uint8_t hash[hash_size]` to store sha256 hash of claims_buffer */
	ctx->crypto_wrapper->opts->gen_hash(ctx->crypto_wrapper, HASH_ALGO_SHA256, claims_buffer,
					    claims_buffer_size, hash);
	if (hash_size >= 16)
		RTLS_DEBUG(
			"evidence user-data field [%zu] %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x...\n",
			(size_t)hash_size, hash[0], hash[1], hash[2], hash[3], hash[4], hash[5],
			hash[6], hash[7], hash[8], hash[9], hash[10], hash[11], hash[12], hash[13],
			hash[14], hash[15]);
	enclave_attester_err_t q_err = ctx->attester->opts->collect_evidence(
		ctx->attester, &evidence, ctx->config.cert_algo, hash, hash_size);
	if (q_err != ENCLAVE_ATTESTER_ERR_NONE) {
		free(claims_buffer);
		claims_buffer = NULL;
		return q_err;
	}
	RTLS_DEBUG("evidence.type: '%s'\n", evidence.type);

	/* Prepare cert info for cert generation */
	rats_tls_cert_info_t cert_info = {
		.subject = {
			.organization = (const unsigned char *)"Inclavare Containers",
			.common_name = (const unsigned char *)"RATS-TLS",
		},
	};
	cert_info.evidence_buffer = NULL;
	cert_info.evidence_buffer_size = 0;
	cert_info.endorsements_buffer = NULL;
	cert_info.endorsements_buffer_size = 0;

	/* Get DICE evidence buffer */
	/* This check is a workaround for the nullattester.
	 * Note: For nullattester, we do not generate an evidence_buffer. nor do we generate evidence extension.  */
	if (evidence.type[0] == '\0') {
		RTLS_WARN(
			"evidence type is empty, which is normal only when you are using nullattester.\n");
	} else {
		enclave_attester_err_t d_ret = dice_generate_evidence_buffer_with_tag(
			&evidence, claims_buffer, claims_buffer_size, &cert_info.evidence_buffer,
			&cert_info.evidence_buffer_size);
		free(claims_buffer);
		claims_buffer = NULL;
		if (d_ret != ENCLAVE_ATTESTER_ERR_NONE) {
			return d_ret;
		}
	}
	RTLS_DEBUG("evidence buffer size: %zu\n", cert_info.evidence_buffer_size);

	/* Collect endorsements if required */
	if ((evidence.type[0] != '\0' /* skip for nullattester */ &&
	     ctx->config.flags & RATS_TLS_CONF_FLAGS_PROVIDE_ENDORSEMENTS) &&
	    ctx->attester->opts->collect_endorsements) {
		attestation_endorsement_t endorsements;
		memset(&endorsements, 0, sizeof(attestation_endorsement_t));

		enclave_attester_err_t q_ret = ctx->attester->opts->collect_endorsements(
			ctx->attester, &evidence, &endorsements);
		if (q_ret != ENCLAVE_ATTESTER_ERR_NONE) {
			RTLS_WARN("failed to collect collateral: %#x\n", q_ret);
			/* Since endorsements are not essential, we tolerate the failure to occur. */
		} else {
			/* Get DICE endorsements buffer */
			enclave_attester_err_t d_ret = dice_generate_endorsements_buffer_with_tag(
				evidence.type, &endorsements, &cert_info.endorsements_buffer,
				&cert_info.endorsements_buffer_size);
			free_endorsements(evidence.type, &endorsements);
			if (d_ret != ENCLAVE_ATTESTER_ERR_NONE) {
				RTLS_ERR("Failed to generate endorsements buffer %#x\n", d_ret);
				return d_ret;
			}
		}
	}
	RTLS_DEBUG("endorsements buffer size: %zu\n", cert_info.endorsements_buffer_size);

	/* Generate the TLS certificate */
	c_err = ctx->crypto_wrapper->opts->gen_cert(ctx->crypto_wrapper, ctx->config.cert_algo,
						    &cert_info);
	if (c_err != CRYPTO_WRAPPER_ERR_NONE)
		return c_err;

	/* Use the TLS certificate and private key for TLS session */
	if (privkey_len) {
		tls_wrapper_err_t t_err;

		t_err = ctx->tls_wrapper->opts->use_privkey(ctx->tls_wrapper, ctx->config.cert_algo,
							    privkey_buf, privkey_len);
		if (t_err != TLS_WRAPPER_ERR_NONE)
			return t_err;

		t_err = ctx->tls_wrapper->opts->use_cert(ctx->tls_wrapper, &cert_info);
		if (t_err != TLS_WRAPPER_ERR_NONE)
			return t_err;
	}

	/* Prevent from re-generation of TLS certificate */
	ctx->flags |= RATS_TLS_CTX_FLAGS_CERT_CREATED;

	return RATS_TLS_ERR_NONE;
}
