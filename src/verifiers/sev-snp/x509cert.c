/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <rats-tls/log.h>
#include "x509cert.h"
#include "utils.h"

int convert_der_to_pem(char *in_file_name, char *out_file_name)
{
	char cmdline_str[200] = {
		0,
	};

	int count = snprintf(cmdline_str, sizeof(cmdline_str),
			     "openssl x509 -inform der -in %s -out %s", in_file_name,
			     out_file_name);
	cmdline_str[count] = '\0';

	if (system(cmdline_str) != 0)
		return -1;

	return 0;
}

bool read_pem_into_x509(char *file_name, X509 **x509_cert)
{
	FILE *pFile = NULL;
	pFile = fopen(file_name, "re");
	if (!pFile)
		return false;

	*x509_cert = PEM_read_X509(pFile, NULL, NULL, NULL);
	if (!x509_cert) {
		RTLS_ERR("failed to read x509 from file: %s\n", file_name);
		fclose(pFile);
		return false;
	}

	fclose(pFile);

	return true;
}

bool x509_validate_signature(X509 *child_cert, X509 *intermediate_cert, X509 *parent_cert)
{
	bool ret = false;
	X509_STORE *store = NULL;
	X509_STORE_CTX *store_ctx = NULL;

	/* Create the store */
	store = X509_STORE_new();
	if (!store)
		goto err;

	/* Add the parent cert to the store */
	if (X509_STORE_add_cert(store, parent_cert) != 1) {
		RTLS_ERR("failed to add parent_cert to x509_store\n");
		goto err;
	}

	/* Add the intermediate cert to the store */
	if (intermediate_cert) {
		if (X509_STORE_add_cert(store, intermediate_cert) != 1) {
			RTLS_ERR("failed to add intermediate_cert to x509_store\n");
			goto err;
		}
	}

	/* Create the store context */
	store_ctx = X509_STORE_CTX_new();
	if (!store_ctx) {
		RTLS_ERR("failed to create x509_store_context\n");
		goto err;
	}

	/* Pass the store (parent and intermediate cert) and child cert (need
	 * to be verified) into the store context
	 */
	if (X509_STORE_CTX_init(store_ctx, store, child_cert, NULL) != 1) {
		RTLS_ERR("failed to initialize 509_store_context\n");
		goto err;
	}

	/* Specify which cert to verify */
	X509_STORE_CTX_set_cert(store_ctx, child_cert);

	/* Verify the certificate */
	ret = X509_verify_cert(store_ctx);
	if (ret != 1) {
		RTLS_ERR("failed to verify x509 cert: %s\n",
			 X509_verify_cert_error_string(X509_STORE_CTX_get_error(store_ctx)));
		goto err;
	}

	ret = true;

err:
	if (store_ctx)
		X509_STORE_CTX_free(store_ctx);
	if (store)
		X509_STORE_free(store);

	return ret;
}
