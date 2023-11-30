/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/tls_wrapper.h>
#include "internal/core.h"
#include "openssl.h"

tls_wrapper_err_t openssl_setup_ssl_verifier(tls_wrapper_ctx_t *ctx, rats_tls_ssl_obj_type obj_type,
					     void *obj)
{
	SSL_verify_cb old_verify_cb = NULL;
	X509_STORE *cert_store = NULL;
	int verify_mode = 0;

	switch (obj_type) {
	case OPENSSL_SSL_POINTER: {
		SSL *ssl = (SSL *)obj;
		old_verify_cb = SSL_get_verify_callback(ssl);
		SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);
		/* Note that we use parent SSL_CTX struct's store pointer here, however we will miss this
		 * if the user calls SSL_set0_verify_cert_store(). SSL_get0_verify_cert_store() is good to
		 * slove this problem, but it requires newer openssl version.
		 * See: https://www.openssl.org/docs/man1.1.1/man3/SSL_get0_verify_cert_store.html
		 */
		cert_store = SSL_CTX_get_cert_store(ssl_ctx);
		verify_mode = SSL_get_verify_mode(ssl);
		if (old_verify_cb == verify_certificate)
			break;
		X509_STORE_set_ex_data(cert_store, openssl_ex_data_idx, ctx);
		SSL_set_verify(ssl, verify_mode, verify_certificate);
		break;
	}
	case OPENSSL_SSL_CTX_POINTER: {
		SSL_CTX *ssl_ctx = (SSL_CTX *)obj;
		old_verify_cb = SSL_CTX_get_verify_callback(ssl_ctx);
		cert_store = SSL_CTX_get_cert_store(ssl_ctx);
		verify_mode = SSL_CTX_get_verify_mode(ssl_ctx);
		if (old_verify_cb == verify_certificate)
			break;
		X509_STORE_set_ex_data(cert_store, openssl_ex_data_idx, ctx);
		SSL_CTX_set_verify(ssl_ctx, verify_mode, verify_certificate);
		// TODO: call old_verify_cb, and detect duplicate calls of this function.
		break;
	}
	default:
		RTLS_ERR("Unsupported ssl object type: %#x, obj: %p\n", obj_type, obj);
		return TLS_WRAPPER_ERR_INVALID;
	}
	return TLS_WRAPPER_ERR_NONE;
}

tls_wrapper_err_t openssl_setup_ssl_attester(tls_wrapper_ctx_t *ctx, rats_tls_ssl_obj_type obj_type,
					     void *obj)
{
	uint8_t *privkey_buf = NULL;
	size_t privkey_len = 0;
	uint8_t *cert_buf = NULL;
	size_t cert_len = 0;

	rats_tls_err_t ret = RATS_TLS_ERR_NONE;

	ret = rtls_core_generate_certificate_internal(ctx->rtls_handle, &privkey_buf, &privkey_len,
						      &cert_buf, &cert_len);

	int EPKEY;
	rats_tls_cert_algo_t cert_algo = ctx->rtls_handle->config.cert_algo;
	if (cert_algo == RATS_TLS_CERT_ALGO_ECC_256_SHA256) {
		EPKEY = EVP_PKEY_EC;
	} else if (cert_algo == RATS_TLS_CERT_ALGO_RSA_3072_SHA256) {
		EPKEY = EVP_PKEY_RSA;
	} else {
		ret = CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;
		goto err;
	}

	ERR_clear_error();

	switch (obj_type) {
	case OPENSSL_SSL_POINTER: {
		SSL *ssl = (SSL *)obj;
		int ssl_ret = SSL_use_certificate_ASN1(ssl, cert_buf, cert_len);
		if (ssl_ret != SSL_SUCCESS) {
			RTLS_ERR("Failed to setup certificate: %s\n",
				 ERR_error_string(ERR_get_error(), NULL));
			ret = OPENSSL_ERR_CODE(ssl_ret);
			goto err;
		}
		ssl_ret = SSL_use_PrivateKey_ASN1(EPKEY, ssl, privkey_buf, (long)privkey_len);
		if (ssl_ret != SSL_SUCCESS) {
			RTLS_ERR("Failed to setup private key: %s\n",
				 ERR_error_string(ERR_get_error(), NULL));
			ret = OPENSSL_ERR_CODE(ssl_ret);
			goto err;
		}
		break;
	}
	case OPENSSL_SSL_CTX_POINTER: {
		SSL_CTX *ssl_ctx = (SSL_CTX *)obj;
		int ssl_ret = SSL_CTX_use_certificate_ASN1(ssl_ctx, cert_len, cert_buf);
		if (ssl_ret != SSL_SUCCESS) {
			RTLS_ERR("Failed to setup certificate: %s\n",
				 ERR_error_string(ERR_get_error(), NULL));
			ret = OPENSSL_ERR_CODE(ssl_ret);
			goto err;
		}
		ssl_ret =
			SSL_CTX_use_PrivateKey_ASN1(EPKEY, ssl_ctx, privkey_buf, (long)privkey_len);
		if (ssl_ret != SSL_SUCCESS) {
			RTLS_ERR("Failed to setup private key: %s\n",
				 ERR_error_string(ERR_get_error(), NULL));
			ret = OPENSSL_ERR_CODE(ssl_ret);
			goto err;
		}
		break;
	}
	default:
		RTLS_ERR("Unsupported ssl object type: %#x, obj: %p\n", obj_type, obj);
		ret = TLS_WRAPPER_ERR_INVALID;
		goto err;
	}
	ret = TLS_WRAPPER_ERR_NONE;
err:
	if (privkey_buf)
		free(privkey_buf);
	if (cert_buf)
		free(cert_buf);
	return ret;
}

tls_wrapper_err_t openssl_setup_ssl(tls_wrapper_ctx_t *ctx, rats_tls_setup_type setup_type,
				    rats_tls_ssl_obj_type obj_type, void *obj)
{
	RTLS_DEBUG("handle %p, obj_type %#x, obj %p\n", ctx, obj_type, obj);

	if (!ctx || !obj)
		return TLS_WRAPPER_ERR_INVALID;

	switch (setup_type) {
	case SETUP_VERIRIER:
		return openssl_setup_ssl_verifier(ctx, obj_type, obj);
		break;
	case SETUP_ATTESTER:
		return openssl_setup_ssl_attester(ctx, obj_type, obj);
		break;
	default:
		RTLS_ERR("Unsupported setup type: %#x\n", setup_type);
		return TLS_WRAPPER_ERR_INVALID;
	}
	return TLS_WRAPPER_ERR_NONE;
}
