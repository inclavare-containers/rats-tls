/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include <string.h>
#include <assert.h>
#include <rats-tls/log.h>
#include <rats-tls/err.h>
#include <rats-tls/tls_wrapper.h>
#include <rats-tls/oid.h>
#include <rats-tls/csv.h>
#include <internal/core.h>
#include <internal/dice.h>
// clang-format off
#ifdef SGX
#include "sgx_report.h"
#endif
#include "sgx_quote_3.h"
// clang-format on
#include "per_thread.h"
#include "openssl.h"

static int rtls_memcpy_s(void *dst, uint32_t dst_size, const void *src, uint32_t num_bytes)
{
	int result = 0;

	if (dst == NULL) {
		RTLS_ERR("dst parameter is null pointer!\n");
		goto done;
	}

	if (src == NULL || dst_size < num_bytes) {
		RTLS_ERR("invalid parameters found!\n");
		goto done;
	}

	if ((dst >= src && ((uint8_t *)dst < (uint8_t *)src + num_bytes)) ||
	    (dst < src && ((uint8_t *)dst + dst_size > (uint8_t *)src))) {
		RTLS_ERR("there is overlapping copy here!\n");
		goto done;
	}

	memcpy(dst, src, num_bytes);
	result = 1;

done:
	return result;
}

static crypto_wrapper_err_t calc_pubkey_sha256(X509 *cert, uint8_t *hash)
{
	EVP_PKEY *pkey = X509_get_pubkey(cert);
	if (!pkey) {
		RTLS_ERR("Unable to decode the public key from certificate\n");
		return -CRYPTO_WRAPPER_ERR_INVALID;
	}

	crypto_wrapper_err_t err = CRYPTO_WRAPPER_ERR_NONE;

	int len = i2d_PUBKEY(pkey, NULL);
	unsigned char buf[len];
	unsigned char *p = buf;
	len = i2d_PUBKEY(pkey, &p);

	SHA256(buf, len, hash);

	// clang-format off
	RTLS_DEBUG("The hash of public key [%d] %02x%02x%02x%02x%02x%02x%02x%02x...%02x%02x%02x%02x\n",
		   SHA256_HASH_SIZE, hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
		   hash[SHA256_HASH_SIZE - 4], hash[SHA256_HASH_SIZE - 3], hash[SHA256_HASH_SIZE - 2],
		   hash[SHA256_HASH_SIZE - 1]);
	// clang-format on

	EVP_PKEY_free(pkey);

	return err;
}

static int find_extension_from_cert(X509 *cert, const char *oid, uint8_t **data_out,
				    size_t *data_len_out, bool optional)
{
	int result = SSL_SUCCESS;
	const STACK_OF(X509_EXTENSION) * extensions;

	*data_out = NULL;
	*data_len_out = 0;

	/* Set a pointer to the stack of extensions (possibly NULL) */
	if (!(extensions = X509_get0_extensions(cert))) {
		RTLS_DEBUG("failed to extensions from X509\n");
		return 0;
	}

	/* Get the number of extensions (possibly zero) */
	int num_extensions = sk_X509_EXTENSION_num(extensions);

	/* Find the certificate with this OID */
	for (int i = 0; i < num_extensions; ++i) {
		X509_EXTENSION *ext;
		ASN1_OBJECT *obj;
		char oid_buf[128];

		/* Get the i-th extension from the stack */
		if (!(ext = sk_X509_EXTENSION_value(extensions, i))) {
			RTLS_ERR("failed to get X509 extension value\n");
			continue;
		}

		/* Get the OID */
		if (!(obj = X509_EXTENSION_get_object(ext))) {
			RTLS_ERR("failed to get the OID from object\n");
			continue;
		}

		/* Get the string name of the OID */
		if (!OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1)) {
			RTLS_ERR("failed to get string name of the oid\n");
			continue;
		}

		/* If found then get the data */
		if (!strcmp((const char *)oid_buf, oid)) {
			ASN1_OCTET_STRING *str;

			/* Get the data from the extension */
			if (!(str = X509_EXTENSION_get_data(ext))) {
				RTLS_ERR("failed to get data from teh extension\n");
				return 0;
			}

			*data_out = malloc(str->length);
			if (!*data_out) {
				RTLS_ERR("failed to allocate memory for data from extension\n");
				result = 0;
				goto done;
			}
			rtls_memcpy_s(*data_out, str->length, str->data, str->length);
			*data_len_out = str->length;
			result = SSL_SUCCESS;
			goto done;
		}
	}

	/* If this extension is optional, return success */
	if (!optional)
		result = 0;

done:
	return result;
}

static tls_wrapper_err_t
verify_evidence_buffer(tls_wrapper_ctx_t *tls_ctx,
		       uint8_t *evidence_buffer /* optional, for nullverifier */,
		       size_t evidence_buffer_size,
		       __attribute__((unused)) uint8_t *endorsements_buffer /* optional */,
		       __attribute__((unused)) size_t endorsements_buffer_size,
		       uint8_t *pubkey_hash /* Assume it is sha256 hash */)
{
	tls_wrapper_err_t ret;

	attestation_evidence_t evidence;

	uint8_t *claims_buffer = NULL;
	size_t claims_buffer_size = 0;
	claim_t *custom_claims = NULL;
	size_t custom_claims_length = 0;

	RTLS_DEBUG("verify_evidence_buffer() called\n");

	if (!tls_ctx || !tls_ctx->rtls_handle || !tls_ctx->rtls_handle->verifier ||
	    !tls_ctx->rtls_handle->verifier->opts ||
	    !tls_ctx->rtls_handle->verifier->opts->verify_evidence || !pubkey_hash)
		return -TLS_WRAPPER_ERR_INVALID;

	if (!evidence_buffer) {
		/* evidence_buffer is empty, which means that the other party is using a non-dice certificate or is using a nullattester */
		RTLS_WARN("there is no evidence in peer's certificate.\n");
		memset(&evidence, 0, sizeof(attestation_evidence_t));
	} else {
		/* Get evidence struct and claims_buffer(optional) from evidence_buffer */
		enclave_verifier_err_t d_ret = dice_parse_evidence_buffer_with_tag(
			evidence_buffer, evidence_buffer_size, &evidence, &claims_buffer,
			&claims_buffer_size);
		if (d_ret != ENCLAVE_VERIFIER_ERR_NONE) {
			ret = -TLS_WRAPPER_ERR_INVALID;
			RTLS_ERR("dice failed to parse evidence from evidence buffer: %#x\n",
				 d_ret);
			goto err;
		}
	}
	RTLS_DEBUG("evidence->type: '%s'\n", evidence.type);

	if (claims_buffer) {
		/* If claims_buffer exists, the hash value in evidence user-data field shall be the SHA256 hash of the `claims-buffer` byte string */
		RTLS_DEBUG("check evidence user-data field with sha256 of claims_buffer\n");
		uint8_t hash[SHA256_DIGEST_LENGTH];
		size_t hash_len = SHA256_DIGEST_LENGTH;
		SHA256(claims_buffer, claims_buffer_size, hash);
		if (hash_len >= 16)
			RTLS_DEBUG(
				"sha256 of claims_buffer [%zu] %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x...\n",
				hash_len, hash[0], hash[1], hash[2], hash[3], hash[4], hash[5],
				hash[6], hash[7], hash[8], hash[9], hash[10], hash[11], hash[12],
				hash[13], hash[14], hash[15]);
		ret = tls_wrapper_verify_certificate_extension(tls_ctx, &evidence, hash, hash_len);
		if (ret != TLS_WRAPPER_ERR_NONE) {
			RTLS_ERR("failed to verify evidence: %#x\n", ret);
			goto err;
		}
	} else {
		/* Or the user-data field shall hold pubkey-hash-value */
		/* NOTE: Since there is no universal way to get user-data field, we need a little trick here: generate sha265 pubkey-hash-value for the public key of the certificate being verified */
		RTLS_DEBUG("check evidence user-data field with pubkey-hash-value\n");
		uint8_t *pubkey_hash_value_buffer = NULL;
		size_t pubkey_hash_value_buffer_size = 0;
		enclave_attester_err_t gen_ret = dice_generate_pubkey_hash_value_buffer(
			pubkey_hash, &pubkey_hash_value_buffer, &pubkey_hash_value_buffer_size);
		if (gen_ret != ENCLAVE_ATTESTER_ERR_NONE) {
			RTLS_ERR(
				"failed to verify evidence: unable to verify pubkey-hash-value, internal error code: %#x\n",
				gen_ret);
			ret = gen_ret == ENCLAVE_ATTESTER_ERR_NO_MEM ? ENCLAVE_VERIFIER_ERR_NO_MEM :
								       ENCLAVE_VERIFIER_ERR_INVALID;
			goto err;
		}
		if (pubkey_hash_value_buffer_size >= 16) {
			uint8_t *data = pubkey_hash_value_buffer;
			RTLS_DEBUG(
				"pubkey-hash-value [%zu] %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x...\n",
				pubkey_hash_value_buffer_size, data[0], data[1], data[2], data[3],
				data[4], data[5], data[6], data[7], data[8], data[9], data[10],
				data[11], data[12], data[13], data[14], data[15]);
		}
		ret = tls_wrapper_verify_certificate_extension(tls_ctx, &evidence,
							       pubkey_hash_value_buffer,
							       pubkey_hash_value_buffer_size);
		free(pubkey_hash_value_buffer);
		if (ret != TLS_WRAPPER_ERR_NONE) {
			RTLS_ERR("failed to verify evidence: %#x\n", ret);
			goto err;
		}
	}

	/* Parse verify claims buffer from evidence buffer */
	if (claims_buffer) {
		enclave_verifier_err_t d_ret = dice_parse_and_verify_claims_buffer(
			pubkey_hash, claims_buffer, claims_buffer_size, &custom_claims,
			&custom_claims_length);
		free(claims_buffer);
		claims_buffer = NULL;
		if (d_ret != ENCLAVE_VERIFIER_ERR_NONE) {
			ret = -TLS_WRAPPER_ERR_INVALID;
			RTLS_ERR("dice failed to parse claims from claims_buffer: %#x\n", d_ret);
			goto err;
		}

		RTLS_DEBUG("custom_claims %p, claims_size %zu\n", custom_claims,
			   custom_claims_length);
		for (size_t i = 0; i < custom_claims_length; ++i) {
			RTLS_DEBUG(
				"custom_claims[%zu] -> name: '%s' value_size: %zu value: '%.*s'\n",
				i, custom_claims[i].name, custom_claims[i].value_size,
				(int)custom_claims[i].value_size, custom_claims[i].value);
		}
	}

	/* Verify evidence struct via user_callback */
	rtls_evidence_t ev;
	memset(&ev, 0, sizeof(ev));
	ev.custom_claims = custom_claims;
	ev.custom_claims_length = custom_claims_length;
	if (!strncmp(evidence.type, "sgx_ecdsa", sizeof(evidence.type))) {
		sgx_quote3_t *quote3 = (sgx_quote3_t *)evidence.ecdsa.quote;

		ev.sgx.mr_enclave = (char *)quote3->report_body.mr_enclave.m;
		ev.sgx.mr_signer = quote3->report_body.mr_signer.m;
		ev.sgx.product_id = quote3->report_body.isv_prod_id;
		ev.sgx.security_version = quote3->report_body.isv_svn;
		ev.sgx.attributes = (char *)&(quote3->report_body.attributes);
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
		ev.tdx.tdel_info = &(evidence.tdx.quote[TDX_ECDSA_QUOTE_SZ]);
		ev.tdx.tdel_info_sz = evidence.tdx.tdel_info_len;
		ev.tdx.tdel_data = &(evidence.tdx.quote[TDX_ECDSA_QUOTE_SZ + TDEL_INFO_SZ]);
		ev.tdx.tdel_data_sz = evidence.tdx.tdel_data_len;
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
			ret = -TLS_WRAPPER_ERR_INVALID;
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

int verify_certificate(int preverify_ok, X509_STORE_CTX *ctx)
{
	RTLS_DEBUG(
		"verify_certificate preverify_ok: %d, ctx: %p, X509_STORE_CTX_get_error(ctx): %d\n",
		preverify_ok, ctx, X509_STORE_CTX_get_error(ctx));

/*
* This code allows you to use command "openssl x509 -in /tmp/cert.der -inform der -text -noout"
* to dump the content of TLS certificate with evidence extension.
*/
#if 0
	#ifndef SGX
	X509 *crt = X509_STORE_CTX_get_current_cert(ctx);
	if (!crt) {
		RTLS_ERR("failed to retrieve certificate\n");
		return 0;
	}

	/* Convert the certificate into a buffer in DER format */
	int der_cert_size = i2d_X509(crt, NULL);
	unsigned char *der_buf = (unsigned char *)malloc((size_t)der_cert_size);
	if (!der_buf) {
		RTLS_ERR("failed to allocate buffer (%d-byte) for certificate\n", der_cert_size);
		return 0;
	}

	unsigned char *der_cert = der_buf;
	der_cert_size = i2d_X509(crt, &der_cert);

	/* Dump certificate */
	FILE *fp = fopen("/tmp/cert.der", "wb");
	fwrite(der_buf, der_cert_size, 1, fp);
	fclose(fp);

	free(der_buf);
	#endif
#endif

	X509_STORE *cert_store = X509_STORE_CTX_get0_store(ctx);
	int *ex_data = per_thread_getspecific();
	if (!ex_data) {
		RTLS_ERR("failed to get ex_data\n");
		return 0;
	}

	tls_wrapper_ctx_t *tls_ctx = X509_STORE_get_ex_data(cert_store, *ex_data);
	if (!tls_ctx) {
		RTLS_ERR("failed to get tls_wrapper_ctx pointer\n");
		return 0;
	}

	X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
	if (!cert) {
		RTLS_ERR("failed to get cert from x509 context!\n");
		return 0;
	}

	if (!preverify_ok) {
		int err = X509_STORE_CTX_get_error(ctx);

		/* We tolerate the case where the passed certificate is a self-signed certificate. */
		if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
			return SSL_SUCCESS;

		/* According to the dice standard, the DiceTaggedEvidence extension should be set to critical=true.
		 * However, there is no way via the openssl api to know directly which extension is causing
		 * X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION, so we have to tolerate all this cases here.
		 * This may be a security issue if there are other critical extensions that neither we nor openssl can handle.
		 * See:
		 *  - https://github.com/openssl/openssl/blob/a63fa5f711f1f97e623348656b42717d6904ee3e/crypto/x509/x509_vfy.c#L490
		 *  - https://github.com/openssl/openssl/blob/a63fa5f711f1f97e623348656b42717d6904ee3e/crypto/x509/v3_purp.c#LL596C34-L596C34
		 */
		if (err == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION)
			return SSL_SUCCESS;

		/*
		 * A typical and unrecoverable error code is
		 * X509_V_ERR_CERT_NOT_YET_VALID (9), which implies the
		 * time-keeping is not consistent between client and server.
		 */
		RTLS_ERR("Failed on pre-verification due to %d\n", err);

		if (err == X509_V_ERR_CERT_NOT_YET_VALID)
			RTLS_ERR("Please ensure check the time-keeping "
				 "is consistent between client and "
				 "server\n");

		return 0;
	}

	const int hash_size = SHA256_HASH_SIZE;
	uint8_t hash[hash_size];
	crypto_wrapper_err_t err = calc_pubkey_sha256(cert, hash);
	if (err != CRYPTO_WRAPPER_ERR_NONE)
		return 0;

	/* Extract the Rats TLS certificate extension_buffer and endorsements_buffer(optional) from the TLS
	 * certificate extension.
	 */
	uint8_t *evidence_buffer = NULL;
	size_t evidence_buffer_size = 0;
	uint8_t *endorsements_buffer = NULL;
	size_t endorsements_buffer_size = 0;

	int rc = find_extension_from_cert(cert, TCG_DICE_TAGGED_EVIDENCE_OID, &evidence_buffer,
					  &evidence_buffer_size, true);
	if (rc != SSL_SUCCESS) {
		RTLS_ERR("failed to extract the evidence extensions from the certificate %d\n", rc);
		return rc;
	}

	rc = find_extension_from_cert(cert, TCG_DICE_ENDORSEMENT_MANIFEST_OID, &endorsements_buffer,
				      &endorsements_buffer_size, true);
	if (rc != SSL_SUCCESS) {
		free(evidence_buffer);
		RTLS_ERR("failed to extract the endorsements extensions from the certificate %d\n",
			 rc);
		return rc;
	}

	tls_wrapper_err_t t_err = verify_evidence_buffer(tls_ctx, evidence_buffer,
							 evidence_buffer_size, endorsements_buffer,
							 endorsements_buffer_size, hash);
	if (t_err != TLS_WRAPPER_ERR_NONE) {
		RTLS_ERR("failed to verify certificate extension %#x\n", err);
		return 0;
	}

	return SSL_SUCCESS;
}
