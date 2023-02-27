/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include <string.h>
#include <rats-tls/log.h>
#include <rats-tls/err.h>
#include <rats-tls/tls_wrapper.h>
#include <internal/core.h>
#include <internal/dice.h>
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

#if 0
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
#endif

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

	/* Get pubkey in SubjectPublicKeyInfo format from cert */
	EVP_PKEY *pkey = X509_get_pubkey(cert);
	if (!pkey) {
		RTLS_ERR("Unable to decode the public key from certificate\n");
		return TLS_WRAPPER_ERR_INVALID;
	}
	int pubkey_buffer_size = i2d_PUBKEY(pkey, NULL);
	unsigned char pubkey_buffer[pubkey_buffer_size];
	unsigned char *p = pubkey_buffer;
	i2d_PUBKEY(pkey, &p);
	EVP_PKEY_free(pkey);

	/* Extract the RATS-TLS certificate evidence_buffer(optional for nullverifier) and endorsements_buffer(optional) from the TLS
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

	tls_wrapper_err_t t_err = tls_wrapper_verify_certificate_extension(
		tls_ctx, pubkey_buffer, pubkey_buffer_size, evidence_buffer, evidence_buffer_size,
		endorsements_buffer, endorsements_buffer_size);
	if (t_err != TLS_WRAPPER_ERR_NONE) {
		RTLS_ERR("failed to verify certificate extension %#x\n", t_err);
		return 0;
	}

	return SSL_SUCCESS;
}
