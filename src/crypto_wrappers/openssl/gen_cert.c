/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <rats-tls/log.h>
#include <rats-tls/crypto_wrapper.h>
#include "internal/dice.h"
#include "openssl.h"

#define CERT_SERIAL_NUMBER 1

static bool using_cert_nonce = false;

static int x509_extension_add_common(X509 *cert)
{
	int ret = 0;
	X509V3_CTX ctx;

	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

	X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
	if (!ext) {
		RTLS_ERR("failed to create basic constraint extension\n");
		goto err;
	}

	if (!X509_add_ext(cert, ext, -1)) {
		RTLS_ERR("failed to add basic constraint extension\n");
		goto err;
	}

	X509_EXTENSION_free(ext);

	ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
	if (!ext) {
		RTLS_ERR("failed to create subject key identifier extension\n");
		goto err;
	}

	if (!X509_add_ext(cert, ext, -1)) {
		RTLS_ERR("failed to add subject key identifier extension\n");
		goto err;
	}

	X509_EXTENSION_free(ext);

	ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, "keyid:always");
	if (!ext) {
		RTLS_ERR("failed to create authority key identifier extension\n");
		goto err;
	}

	if (!X509_add_ext(cert, ext, -1)) {
		RTLS_ERR("failed to add authority key identifier extension\n");
		goto err;
	}

	X509_EXTENSION_free(ext);
	ext = NULL;

	ret = 1;

err:
	if (ext)
		X509_EXTENSION_free(ext);

	return ret;
}

static int x509_extension_add(X509 *cert, const char *oid, bool critical, const void *data,
			      size_t data_len)
{
	ASN1_OCTET_STRING *octet = NULL;
	int ret = 0;
	X509_EXTENSION *ext = NULL;

	int nid = OBJ_txt2nid(oid);
	if (nid == NID_undef) {
		nid = OBJ_create(oid, NULL, NULL);
		if (nid == NID_undef) {
			RTLS_ERR("failed to create the object %s\n", oid);
			return ret;
		}
	}

	octet = ASN1_OCTET_STRING_new();
	if (!octet)
		goto err;

	ASN1_OCTET_STRING_set(octet, data, data_len);

	ext = X509_EXTENSION_create_by_NID(NULL, nid, critical, octet);
	if (!ext) {
		RTLS_ERR("failed to create extension\n");
		goto err;
	}

	if (!X509_add_ext(cert, ext, -1)) {
		RTLS_ERR("failed to add extension %s\n", oid);
		goto err;
	}

	ret = 1;

err:
	if (ext)
		X509_EXTENSION_free(ext);

	if (octet)
		ASN1_OCTET_STRING_free(octet);

	return ret;
}

crypto_wrapper_err_t openssl_gen_cert(crypto_wrapper_ctx_t *ctx, rats_tls_cert_algo_t algo,
				      rats_tls_cert_info_t *cert_info)
{
	openssl_ctx *octx = NULL;
	cert_subject_t *subject;
	X509 *cert = NULL;
	X509_NAME *name;
	EVP_PKEY *pkey = NULL;
	unsigned char *der;
	int len;
	int ret;

	RTLS_DEBUG("ctx %p, cert_info %p\n", ctx, cert_info);

	if (!ctx || !cert_info)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	octx = ctx->crypto_private;

	pkey = EVP_PKEY_new();
	if (!pkey)
		return -CRYPTO_WRAPPER_ERR_NO_MEM;

	ret = -CRYPTO_WRAPPER_ERR_PRIV_KEY_LEN;

	if (algo == RATS_TLS_CERT_ALGO_ECC_256_SHA256) {
		if (!EVP_PKEY_assign_EC_KEY(pkey, octx->eckey))
			goto err;
	} else if (algo == RATS_TLS_CERT_ALGO_RSA_3072_SHA256) {
		if (!EVP_PKEY_assign_RSA(pkey, octx->key))
			goto err;
	} else {
		return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;
	}

	ret = -CRYPTO_WRAPPER_ERR_NO_MEM;
	cert = X509_new();
	if (!cert)
		goto err;

	X509_set_version(cert, 2 /* x509 version 3 cert */);
	ASN1_INTEGER_set(X509_get_serialNumber(cert), CERT_SERIAL_NUMBER);
	if (!using_cert_nonce) {
		/* WORKAROUND: allow 1 hour delay for the systems behind current clock */
		X509_gmtime_adj(X509_get_notBefore(cert), -3600);
		/* 1 year */
		X509_gmtime_adj(X509_get_notAfter(cert), (long)3600 * 24 * 365 * 1);
	} else {
		/* WORKAROUND: with nonce mechanism, the validity of cert can be fixed within a larger range. */
		const char timestr_notBefore[] = "19700101000001Z";
		const char timestr_notAfter[] = "20491231235959Z";
		ASN1_TIME_set_string(X509_get_notBefore(cert), timestr_notBefore);
		ASN1_TIME_set_string(X509_get_notAfter(cert), timestr_notAfter);
	}

	ret = -CRYPTO_WRAPPER_ERR_PUB_KEY_LEN;
	if (!X509_set_pubkey(cert, pkey))
		goto err;

	/* subject name */
	name = X509_get_subject_name(cert);
	if (!name)
		goto err;

	subject = &cert_info->subject;
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, subject->organization, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, subject->organization_unit, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, subject->common_name, -1, -1, 0);
	if (!X509_set_issuer_name(cert, name))
		goto err;

	ret = -CRYPTO_WRAPPER_ERR_CERT_EXTENSION;

	if (!x509_extension_add_common(cert))
		goto err;

	/* Add evidence extension */
	if (cert_info->evidence_buffer_size) {
		/* The DiceTaggedEvidence extension criticality flag SHOULD be marked critical. */
		if (!x509_extension_add(cert, TCG_DICE_TAGGED_EVIDENCE_OID, false,
					cert_info->evidence_buffer,
					cert_info->evidence_buffer_size) != RATS_TLS_ERR_NONE)
			goto err;
	}

	/* Add endorsements extension */
	if (cert_info->endorsements_buffer_size) {
		if (!x509_extension_add(cert, TCG_DICE_ENDORSEMENT_MANIFEST_OID, false,
					cert_info->endorsements_buffer,
					cert_info->endorsements_buffer_size) != RATS_TLS_ERR_NONE)
			goto err;
	}

	ret = -CRYPTO_WRAPPER_ERR_CERT;
	if (!X509_sign(cert, pkey, EVP_sha256()))
		goto err;

	der = cert_info->cert_buf;
	len = i2d_X509(cert, &der);
	if (len < 0)
		goto err;

	cert_info->cert_len = len;

	RTLS_DEBUG("self-signing certificate generated\n");

	ret = CRYPTO_WRAPPER_ERR_NONE;

err:
	if (ret != CRYPTO_WRAPPER_ERR_NONE)
		RTLS_DEBUG("failed to generate certificate %d\n", ret);

	if (cert)
		X509_free(cert);

	if (pkey)
		EVP_PKEY_free(pkey);

	return ret;
}
