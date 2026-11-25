/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _OPENSSL_CRYPT_H
#define _OPENSSL_CRYPT_H

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

typedef struct {
	RSA *key;
	EC_KEY *eckey;
	EVP_PKEY *pkey;
} openssl_ctx;

#endif
