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

static crypto_wrapper_err_t calc_pubkey_hash(X509 *cert, uint8_t *hash, int *hash_size)
{
	int hash_algo;
	int pkey_algo;
	if (!X509_get_signature_info(cert, &hash_algo, &pkey_algo, NULL, NULL)) {
		RTLS_ERR("Failed on retrieving information about the signature of certificate\n");
		return -CRYPTO_WRAPPER_ERR_INVALID;
	}

	if (hash_algo == NID_undef) {
		RTLS_ERR("Invalid signing digest algorithm\n");
		return -CRYPTO_WRAPPER_ERR_INVALID;
	}

	const EVP_MD *md = EVP_get_digestbynid(hash_algo);
	if (!md) {
		RTLS_ERR("Invalid signing digest algorithm for EVP_MD\n");
		return -CRYPTO_WRAPPER_ERR_INVALID;
	}

	if (pkey_algo == NID_undef) {
		RTLS_ERR("Invalid public key algorithm\n");
		return -CRYPTO_WRAPPER_ERR_INVALID;
	}

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

	if (!EVP_Digest(buf, len, hash, NULL, md, NULL)) {
		RTLS_ERR("Failed to hash the public key\n");
		err = -CRYPTO_WRAPPER_ERR_INVALID;
	}

	*hash_size = EVP_MD_size(md);

	// clang-format off
	RTLS_DEBUG("The hash of public key [%d] %02x%02x%02x%02x%02x%02x%02x%02x...%02x%02x%02x%02x\n",
		   len, hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
		   hash[*hash_size - 4], hash[*hash_size - 3], hash[*hash_size - 2],
		   hash[*hash_size - 1]);
	// clang-format on

	EVP_PKEY_free(pkey);

	return err;
}

static int find_oid(X509 *crt, const char *oid)
{
	// clang-format off
	const STACK_OF(X509_EXTENSION) *extensions;
	// clang-format on

	/* Set a pointer to the stack of extensions (possibly NULL) */
	if (!(extensions = X509_get0_extensions(crt))) {
		RTLS_DEBUG("there are no extensions in X509 cert\n");
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

		if (!strcmp((const char *)oid_buf, oid))
			return SSL_SUCCESS;
	}

	return 0;
}

static int find_extension_from_cert(X509 *cert, const char *oid, uint8_t *data, uint32_t *size)
{
	int result = SSL_SUCCESS;
	const STACK_OF(X509_EXTENSION) * extensions;

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

			if ((uint32_t)str->length > *size) {
				if (data)
					RTLS_DEBUG("buffer is too small (%d-byte vs %d-byte)\n",
						   (uint32_t)str->length, *size);

				*size = (uint32_t)str->length;
			}
			if (data) {
				rtls_memcpy_s(data, *size, str->data, (uint32_t)str->length);
				*size = (uint32_t)str->length;
				result = SSL_SUCCESS;
				goto done;
			}
		}
	}

	result = 0;

done:
	return result;
}

int openssl_extract_x509_extensions(X509 *crt, attestation_evidence_t *evidence)
{
	if (!strcmp(evidence->type, "sgx_epid")) {
		evidence->epid.ias_report_len = sizeof(evidence->epid.ias_report);
		int rc = find_extension_from_cert(crt, ias_response_body_oid,
						  evidence->epid.ias_report,
						  &evidence->epid.ias_report_len);
		if (rc != SSL_SUCCESS)
			return rc;

		evidence->epid.ias_sign_ca_cert_len = sizeof(evidence->epid.ias_sign_ca_cert);
		rc = find_extension_from_cert(crt, ias_root_cert_oid,
					      evidence->epid.ias_sign_ca_cert,
					      &evidence->epid.ias_sign_ca_cert_len);
		if (rc != SSL_SUCCESS)
			return rc;

		evidence->epid.ias_sign_cert_len = sizeof(evidence->epid.ias_sign_cert);
		rc = find_extension_from_cert(crt, ias_leaf_cert_oid, evidence->epid.ias_sign_cert,
					      &evidence->epid.ias_sign_cert_len);
		if (rc != SSL_SUCCESS)
			return rc;

		evidence->epid.ias_report_signature_len =
			sizeof(evidence->epid.ias_report_signature);
		rc = find_extension_from_cert(crt, ias_report_signature_oid,
					      evidence->epid.ias_report_signature,
					      &evidence->epid.ias_report_signature_len);
		return rc;
	} else if (!strcmp(evidence->type, "sgx_ecdsa")) {
		evidence->ecdsa.quote_len = sizeof(evidence->ecdsa.quote);
		return find_extension_from_cert(crt, ecdsa_quote_oid, evidence->ecdsa.quote,
						&evidence->ecdsa.quote_len);
	} else if (!strcmp(evidence->type, "tdx_ecdsa")) {
		evidence->tdx.quote_len = sizeof(evidence->tdx.quote);
		return find_extension_from_cert(crt, tdx_quote_oid, evidence->tdx.quote,
						&evidence->tdx.quote_len);
	} else if (!strcmp(evidence->type, "sgx_la")) {
		evidence->la.report_len = sizeof(evidence->la.report);
		return find_extension_from_cert(crt, la_report_oid, evidence->la.report,
						&evidence->la.report_len);
	} else if (!strcmp(evidence->type, "sev_snp")) {
		evidence->snp.report_len = sizeof(evidence->snp.report);
		return find_extension_from_cert(crt, snp_report_oid, evidence->snp.report,
						&evidence->snp.report_len);
	} else if (!strcmp(evidence->type, "sev")) {
		evidence->sev.report_len = sizeof(evidence->sev.report);
		return find_extension_from_cert(crt, sev_report_oid, evidence->sev.report,
						&evidence->sev.report_len);
	} else if (!strcmp(evidence->type, "csv")) {
		evidence->csv.report_len = sizeof(evidence->csv.report);
		return find_extension_from_cert(crt, csv_report_oid, evidence->csv.report,
						&evidence->csv.report_len);
	} else
		RTLS_WARN("Unhandled evidence type %s\n", evidence->type);

	return SSL_SUCCESS;
}

#ifdef SGX
int verify_certificate(X509_STORE_CTX *ctx)
{
	int preverify_ok = 0;
#else
int verify_certificate(int preverify_ok, X509_STORE_CTX *ctx)
{
#endif

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

#if OPENSSL_VERSION_NUMBER < 0x10100000L
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

#else
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
#endif

	X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
	if (!cert) {
		RTLS_ERR("failed to get cert from x509 context!\n");
		return 0;
	}

	if (!preverify_ok) {
		int err = X509_STORE_CTX_get_error(ctx);

		/*
		 * A typical and unrecoverable error code is
		 * X509_V_ERR_CERT_NOT_YET_VALID (9), which implies the
		 * time-keeping is not consistent between client and server.
		 */
		if (err != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
			RTLS_ERR("Failed on pre-verification due to %d\n", err);

			if (err == X509_V_ERR_CERT_NOT_YET_VALID)
				RTLS_ERR("Please ensure check the time-keeping "
					 "is consistent between client and "
					 "server\n");

			return 0;
		}
	}

	uint8_t hash[EVP_MAX_MD_SIZE];
	int hash_size;
	crypto_wrapper_err_t err = calc_pubkey_hash(cert, hash, &hash_size);
	if (err != CRYPTO_WRAPPER_ERR_NONE)
		return 0;

	/* Extract the Rats TLS certificate extension from the TLS certificate
	 * extension and parse it into evidence
	 */
	attestation_evidence_t evidence;

	if (find_oid(cert, (const char *)ecdsa_quote_oid) == SSL_SUCCESS)
		snprintf(evidence.type, sizeof(evidence.type), "%s", "sgx_ecdsa");
	else if (find_oid(cert, (const char *)tdx_quote_oid) == SSL_SUCCESS)
		snprintf(evidence.type, sizeof(evidence.type), "tdx_ecdsa");
	else if (find_oid(cert, (const char *)la_report_oid) == SSL_SUCCESS)
		snprintf(evidence.type, sizeof(evidence.type), "%s", "sgx_la");
	else if (find_oid(cert, (const char *)snp_report_oid) == SSL_SUCCESS)
		snprintf(evidence.type, sizeof(evidence.type), "%s", "sev_snp");
	else if (find_oid(cert, (const char *)sev_report_oid) == SSL_SUCCESS)
		snprintf(evidence.type, sizeof(evidence.type), "%s", "sev");
	else if (find_oid(cert, (const char *)csv_report_oid) == SSL_SUCCESS)
		snprintf(evidence.type, sizeof(evidence.type), "%s", "csv");
	else
		snprintf(evidence.type, sizeof(evidence.type), "%s", "nullverifier");

	int rc = openssl_extract_x509_extensions(cert, &evidence);
	if (rc != SSL_SUCCESS) {
		RTLS_ERR("failed to extract the extensions from the certificate %d\n", rc);
		return 0;
	}

	tls_wrapper_err_t t_err =
		tls_wrapper_verify_certificate_extension(tls_ctx, &evidence, hash, hash_size);
	if (t_err != TLS_WRAPPER_ERR_NONE) {
		RTLS_ERR("failed to verify certificate extension %#x\n", err);
		return 0;
	}

	rtls_evidence_t ev;
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
		rc = tls_ctx->rtls_handle->user_callback(&ev);
		if (!rc) {
			RTLS_ERR("failed to verify user callback %d\n", rc);
			return 0;
		}
	}

	return SSL_SUCCESS;
}
