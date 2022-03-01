/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _SEVAPI_H
#define _SEVAPI_H

#include <stdint.h>

// Chapter 2 - Summary of Keys
typedef uint8_t aes_128_key[128 / 8];
typedef uint8_t hmac_key_128[128 / 8];
typedef uint8_t hmac_sha_256[256 / 8];
typedef uint8_t hmac_sha_384[384 / 8];
typedef uint8_t hmac_sha_512[512 / 8];

typedef enum __attribute__((mode(QI))) SHA_TYPE {
	SHA_ALGO_256 = 0,
	SHA_ALGO_384 = 1,
} SHA_TYPE;

// Appendix C.1: ALGO Enumeration
/**
 * SEV Algorithm cipher codes.
 */
typedef enum __attribute__((mode(HI))) SEV_SIG_ALGO {
	SEV_SIG_ALGO_INVALID = 0x0,
	SEV_SIG_ALGO_RSA_SHA256 = 0x1,
	SEV_SIG_ALGO_ECDSA_SHA256 = 0x2,
	SEV_SIG_ALGO_ECDH_SHA256 = 0x3,
	SEV_SIG_ALGO_RSA_SHA384 = 0x101,
	SEV_SIG_ALGO_ECDSA_SHA384 = 0x102,
	SEV_SIG_ALGO_ECDH_SHA384 = 0x103,
} SEV_SIG_ALGO;

// Appendix C.4: Signature Formats
/**
 * SEV Signature may be RSA or ECDSA.
 */
#define SEV_RSA_SIG_MAX_BITS	    4096
#define SEV_ECDSA_SIG_COMP_MAX_BITS 576
#define SEV_SIG_SIZE		    (SEV_RSA_SIG_MAX_BITS / 8)

// Appendix C.4.1: RSA Signature
/**
 * SEV RSA Signature data.
 *
 * @S - Signature bits.
 */
typedef struct __attribute__((__packed__)) sev_rsa_sig_t {
	uint8_t s[SEV_RSA_SIG_MAX_BITS / 8];
} sev_rsa_sig;

// Appendix C.4.2: ECDSA Signature
/**
 * SEV Elliptical Curve Signature data.
 *
 * @r    - R component of the signature.
 * @s    - S component of the signature.
 * @rmbz - RESERVED. Must be zero!
 */
typedef struct __attribute__((__packed__)) sev_ecdsa_sig_t {
	uint8_t r[SEV_ECDSA_SIG_COMP_MAX_BITS / 8];
	uint8_t s[SEV_ECDSA_SIG_COMP_MAX_BITS / 8];
	uint8_t rmbz[SEV_SIG_SIZE - 2 * SEV_ECDSA_SIG_COMP_MAX_BITS / 8];
} sev_ecdsa_sig;

/**
 * SEV Signature may be RSA or ECDSA.
 */
typedef union {
	sev_rsa_sig rsa;
	sev_ecdsa_sig ecdsa;
} sev_sig;

#endif /* _SEVAPI_H */
