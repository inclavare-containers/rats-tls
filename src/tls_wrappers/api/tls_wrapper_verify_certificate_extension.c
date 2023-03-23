/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <rats-tls/log.h>
#include <rats-tls/err.h>

#include "internal/tls_wrapper.h"
#include "internal/attester.h"
#include "internal/verifier.h"
#include "internal/dice.h"

#include <rats-tls/csv.h>
// clang-format off
#ifdef SGX
#include "sgx_report.h"
#endif
#include "sgx_quote_3.h"
// clang-format on

tls_wrapper_err_t
tls_wrapper_verify_evidence(tls_wrapper_ctx_t *tls_ctx, attestation_evidence_t *evidence,
			    uint8_t *hash, uint32_t hash_len,
			    attestation_endorsement_t *endorsements /* Optional */)
{
	RTLS_DEBUG("tls_wrapper_verify_evidence() called with evidence type: '%s'\n",
		   evidence->type);

	if (!tls_ctx || !tls_ctx->rtls_handle || !tls_ctx->rtls_handle->verifier ||
	    !tls_ctx->rtls_handle->verifier->opts ||
	    !tls_ctx->rtls_handle->verifier->opts->verify_evidence)
		return -TLS_WRAPPER_ERR_INVALID;

	if (strcmp(tls_ctx->rtls_handle->verifier->opts->type, evidence->type) &&
	    !(tls_ctx->rtls_handle->flags & RATS_TLS_CONF_FLAGS_VERIFIER_ENFORCED)) {
		RTLS_WARN("type doesn't match between verifier '%s' and evidence '%s'\n",
			  tls_ctx->rtls_handle->verifier->opts->name, evidence->type);
		rats_tls_err_t tlserr =
			rtls_verifier_select(tls_ctx->rtls_handle, evidence->type,
					     tls_ctx->rtls_handle->config.cert_algo);
		if (tlserr != RATS_TLS_ERR_NONE) {
			RTLS_ERR("the verifier selecting err %#x during verifying cert extension\n",
				 tlserr);
			return -TLS_WRAPPER_ERR_INVALID;
		}
	}

	enclave_verifier_err_t err = tls_ctx->rtls_handle->verifier->opts->verify_evidence(
		tls_ctx->rtls_handle->verifier, evidence, hash, hash_len, endorsements);
	if (err != ENCLAVE_VERIFIER_ERR_NONE) {
		RTLS_ERR("failed to verify evidence %#x\n", err);
		return -TLS_WRAPPER_ERR_INVALID;
	}

	return TLS_WRAPPER_ERR_NONE;
}

tls_wrapper_err_t tls_wrapper_verify_certificate_extension(
	tls_wrapper_ctx_t *tls_ctx,
	const uint8_t *pubkey_buffer /* in SubjectPublicKeyInfo format */,
	size_t pubkey_buffer_size, uint8_t *evidence_buffer /* optional, for nullverifier */,
	size_t evidence_buffer_size, uint8_t *endorsements_buffer /* optional */,
	size_t endorsements_buffer_size)
{
	tls_wrapper_err_t ret;

	attestation_evidence_t evidence;

	uint8_t *claims_buffer = NULL;
	size_t claims_buffer_size = 0;
	claim_t *custom_claims = NULL;
	size_t custom_claims_length = 0;

	RTLS_DEBUG(
		"tls_ctx: %p, pubkey_buffer: %p, pubkey_buffer_size: %zu, evidence_buffer: %p, evidence_buffer_size: %zu, endorsements_buffer: %p, endorsements_buffer_size: %zu\n",
		tls_ctx, pubkey_buffer, pubkey_buffer_size, evidence_buffer, evidence_buffer_size,
		endorsements_buffer, endorsements_buffer_size);

	if (!tls_ctx || !tls_ctx->rtls_handle || !tls_ctx->rtls_handle->verifier ||
	    !tls_ctx->rtls_handle->verifier->opts ||
	    !tls_ctx->rtls_handle->verifier->opts->verify_evidence || !pubkey_buffer)
		return -TLS_WRAPPER_ERR_INVALID;

	/* Get evidence struct and claims_buffer from evidence_buffer. */
	if (!evidence_buffer) {
		/* evidence_buffer is empty, which means that the other party is using a non-dice certificate or is using a nullattester */
		RTLS_WARN("there is no evidence buffer in peer's certificate.\n");
		memset(&evidence, 0, sizeof(attestation_evidence_t));
	} else {
		enclave_verifier_err_t d_ret = dice_parse_evidence_buffer_with_tag(
			evidence_buffer, evidence_buffer_size, &evidence, &claims_buffer,
			&claims_buffer_size);
		if (d_ret != ENCLAVE_VERIFIER_ERR_NONE) {
			ret = TLS_WRAPPER_ERR_INVALID;
			RTLS_ERR("dice failed to parse evidence from evidence buffer: %#x\n",
				 d_ret);
			goto err;
		}
	}
	RTLS_DEBUG("evidence->type: '%s'\n", evidence.type);

	/* Get endorsements (optional) from endorsements_buffer */
	attestation_endorsement_t endorsements;
	memset(&endorsements, 0, sizeof(attestation_endorsement_t));

	bool has_endorsements = endorsements_buffer && endorsements_buffer_size;
	RTLS_DEBUG("has_endorsements: %s\n", has_endorsements ? "true" : "false");
	if (has_endorsements) {
		enclave_verifier_err_t d_ret = dice_parse_endorsements_buffer_with_tag(
			evidence.type, endorsements_buffer, endorsements_buffer_size,
			&endorsements);
		if (d_ret != ENCLAVE_VERIFIER_ERR_NONE) {
			ret = TLS_WRAPPER_ERR_INVALID;
			RTLS_ERR(
				"dice failed to parse endorsements from endorsements buffer: %#x\n",
				d_ret);
			goto err;
		}
	}

	/* Prepare hash value as evidence userdata to be verified.
	 * The hash value in evidence user-data field shall be the SHA256 hash of the `claims-buffer` byte string.
	 */
	RTLS_DEBUG("check evidence userdata field with sha256 of claims_buffer\n");
	uint8_t claims_buffer_hash[SHA256_HASH_SIZE];
	size_t claims_buffer_hash_len = sizeof(claims_buffer_hash);
	if (!claims_buffer) {
		/* Note that the custom_buffer will not be null if the evidence_buffer is successfully parsed.
		 * So this branch indicates the case where there is no evidence_buffer in the certificate, i.e. a peer that does not support the evidence extension, or a peer that uses nullattester.
		 */
		RTLS_WARN(
			"set claims buffer hash value to 0, since there is no evidence buffer in peer's certificate.\n");
		memset(claims_buffer_hash, 0, claims_buffer_hash_len);
	} else {
		crypto_wrapper_err_t c_err = tls_ctx->rtls_handle->crypto_wrapper->opts->gen_hash(
			tls_ctx->rtls_handle->crypto_wrapper, HASH_ALGO_SHA256, claims_buffer,
			claims_buffer_size, claims_buffer_hash);
		if (c_err != CRYPTO_WRAPPER_ERR_NONE) {
			RTLS_ERR("failed to calculate hash of claims_buffer: %#x\n", c_err);
			ret = TLS_WRAPPER_ERR_INVALID;
			goto err;
		}
		if (claims_buffer_hash_len >= 16)
			RTLS_DEBUG(
				"sha256 of claims_buffer [%zu] %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x...\n",
				claims_buffer_hash_len, claims_buffer_hash[0],
				claims_buffer_hash[1], claims_buffer_hash[2], claims_buffer_hash[3],
				claims_buffer_hash[4], claims_buffer_hash[5], claims_buffer_hash[6],
				claims_buffer_hash[7], claims_buffer_hash[8], claims_buffer_hash[9],
				claims_buffer_hash[10], claims_buffer_hash[11],
				claims_buffer_hash[12], claims_buffer_hash[13],
				claims_buffer_hash[14], claims_buffer_hash[15]);
	}

	/* Verify evidence and userdata */
	ret = tls_wrapper_verify_evidence(tls_ctx, &evidence, claims_buffer_hash,
					  claims_buffer_hash_len,
					  has_endorsements ? &endorsements : NULL);
	if (has_endorsements)
		free_endorsements(evidence.type, &endorsements);
	if (ret != TLS_WRAPPER_ERR_NONE) {
		RTLS_ERR("failed to verify evidence: %#x\n", ret);
		goto err;
	}

	/* Parse and verify claims buffer */
	if (claims_buffer) {
		hash_algo_t pubkey_hash_algo = HASH_ALGO_RESERVED;
		uint8_t pubkey_hash[MAX_HASH_SIZE];
		enclave_verifier_err_t d_ret = dice_parse_claims_buffer(
			claims_buffer, claims_buffer_size, &pubkey_hash_algo, pubkey_hash,
			&custom_claims, &custom_claims_length);
		free(claims_buffer);
		claims_buffer = NULL;
		if (d_ret != ENCLAVE_VERIFIER_ERR_NONE) {
			ret = TLS_WRAPPER_ERR_INVALID;
			RTLS_ERR("dice failed to parse claims from claims_buffer: %#x\n", d_ret);
			goto err;
		}

		RTLS_DEBUG("custom_claims %p, claims_size %zu\n", custom_claims,
			   custom_claims_length);
		for (size_t i = 0; i < custom_claims_length; ++i) {
			RTLS_DEBUG("custom_claims[%zu] -> name: '%s' value_size: %zu\n", i,
				   custom_claims[i].name, custom_claims[i].value_size);
		}

		/* Verify pubkey_hash */
		RTLS_DEBUG("check pubkey hash. pubkey_hash: %p, pubkey_hash_algo: %d\n",
			   pubkey_hash, pubkey_hash_algo);

		uint8_t calculated_pubkey_hash[MAX_HASH_SIZE];
		crypto_wrapper_err_t c_err = tls_ctx->rtls_handle->crypto_wrapper->opts->gen_hash(
			tls_ctx->rtls_handle->crypto_wrapper, pubkey_hash_algo, pubkey_buffer,
			pubkey_buffer_size, calculated_pubkey_hash);
		if (c_err != CRYPTO_WRAPPER_ERR_NONE) {
			RTLS_ERR("failed to calculate hash of pubkey: %#x\n", c_err);
			ret = TLS_WRAPPER_ERR_INVALID;
			goto err;
		}

		size_t hash_size = hash_size_of_algo(pubkey_hash_algo);
		if (hash_size == 0) {
			RTLS_FATAL("failed verify hash of pubkey: unsupported hash algo id: %u\n",
				   pubkey_hash_algo);
			ret = TLS_WRAPPER_ERR_INVALID;
			goto err;
		}
		RTLS_DEBUG("The hash of public key [%zu] %02x%02x%02x%02x%02x%02x%02x%02x...\n",
			   hash_size, calculated_pubkey_hash[0], calculated_pubkey_hash[1],
			   calculated_pubkey_hash[2], calculated_pubkey_hash[3],
			   calculated_pubkey_hash[4], calculated_pubkey_hash[5],
			   calculated_pubkey_hash[6], calculated_pubkey_hash[7]);

		if (memcmp(pubkey_hash, calculated_pubkey_hash, hash_size)) {
			RTLS_ERR("unmatched pubkey hash value in claims buffer\n");
			ret = TLS_WRAPPER_ERR_INVALID;
			goto err;
		}
	}

	/* Verify evidence struct via user_callback */
	rtls_evidence_t ev;
	memset(&ev, 0, sizeof(ev));
	ev.custom_claims = custom_claims;
	ev.custom_claims_length = custom_claims_length;
	if (!strncmp(evidence.type, "sgx_ecdsa", sizeof(evidence.type))) {
		sgx_quote3_t *quote3 = (sgx_quote3_t *)evidence.ecdsa.quote;

		ev.sgx.mr_enclave = (uint8_t *)quote3->report_body.mr_enclave.m;
		ev.sgx.mr_signer = quote3->report_body.mr_signer.m;
		ev.sgx.product_id = quote3->report_body.isv_prod_id;
		ev.sgx.security_version = quote3->report_body.isv_svn;
		ev.sgx.attributes = (uint8_t *)&(quote3->report_body.attributes);
		ev.type = SGX_ECDSA;
		ev.quote = (char *)quote3;
		ev.quote_size = sizeof(sgx_quote3_t);
	}
#if 0
	else if (!strncmp(evidence.type, "tdx_ecdsa", sizeof(evidence.type))) {
		sgx_quote4_t *quote4 = (sgx_quote4_t *)evidence.tdx.quote;
		ev.tdx.mrseam = (uint8_t *)&(quote4->report_body.mr_seam);
		ev.tdx.mrseamsigner = (uint8_t *)&(quote4->report_body.mrsigner_seam);
		ev.tdx.tcb_svns = (uint8_t *)&(quote4->report_body.tee_tcb_svn);
		ev.tdx.mrtd = (uint8_t *)&(quote4->report_body.mr_td);
		ev.tdx.rtmr = (char *)quote4->report_body.rt_mr;
		ev.type = TDX_ECDSA;
		ev.quote = (char *)quote4;
	}
#endif
	else if (!strncmp(evidence.type, "csv", sizeof(evidence.type))) {
		csv_evidence *c_evi = (csv_evidence *)evidence.csv.report;
		csv_attestation_report *report = &c_evi->attestation_report;
		int i = 0;
		int cnt = (offsetof(csv_attestation_report, anonce) -
			   offsetof(csv_attestation_report, user_pubkey_digest)) /
			  sizeof(uint32_t);

		for (i = 0; i < cnt; i++)
			((uint32_t *)report)[i] ^= report->anonce;

		ev.csv.vm_id = (uint8_t *)&(report->vm_id);
		ev.csv.vm_id_sz = sizeof(report->vm_id);
		ev.csv.vm_version = (uint8_t *)&(report->vm_version);
		ev.csv.vm_version_sz = sizeof(report->vm_version);
		ev.csv.measure = (uint8_t *)&(report->measure);
		ev.csv.measure_sz = sizeof(report->measure);
		ev.csv.policy = (uint8_t *)&(report->policy);
		ev.csv.policy_sz = sizeof(report->policy);
		ev.type = CSV;
		ev.quote = (char *)report;
		ev.quote_size = sizeof(*report);
	}

	if (tls_ctx->rtls_handle->user_callback) {
		int rc = tls_ctx->rtls_handle->user_callback(&ev);
		if (!rc) {
			RTLS_ERR("failed to verify user callback %d\n", rc);
			ret = TLS_WRAPPER_ERR_INVALID;
			goto err;
		}
	}

	ret = TLS_WRAPPER_ERR_NONE;
err:
	if (claims_buffer)
		free(claims_buffer);
	if (custom_claims)
		free_claims_list(custom_claims, custom_claims_length);

	return ret;
}
