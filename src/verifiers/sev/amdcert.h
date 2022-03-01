/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _AMDCERT_H
#define _AMDCERT_H

#include "sev_utils.h"

#define AMD_CERT_ID_SIZE_BYTES 16
#define AMD_CERT_VERSION       0x01
#define AMD_CERT_KEY_BITS_2K   2048
#define AMD_CERT_KEY_BITS_4K   4096
#define AMD_CERT_KEY_BYTES_4K  512

/* Appendix B.1: Certificate Format */
typedef union {
	uint8_t short_len[2048 / 8];
	uint8_t long_len[4096 / 8];
} amd_cert_pub_exp;

typedef union {
	uint8_t short_len[2048 / 8];
	uint8_t long_len[4096 / 8];
} amd_cert_mod;

typedef union {
	uint8_t short_len[2048 / 8];
	uint8_t long_len[4096 / 8];
} amd_cert_sig;

typedef enum __attribute__((mode(QI))) AMD_SIG_USAGE {
	AMD_USAGE_ARK = 0x00,
	AMD_USAGE_ASK = 0x13,
} AMD_SIG_USAGE;

/* Appendix B.1: AMD Signing Key Certificate Format */
typedef struct __attribute__((__packed__)) amd_cert_t {
	uint32_t version; // Certificate Version. Should be 1.
	uint64_t key_id_0; // The unique ID for this key
	uint64_t key_id_1;
	uint64_t certifying_id_0; // The unique ID for the key that signed this cert.
	uint64_t certifying_id_1; // If this cert is self-signed, then equals KEY_ID field.
	uint32_t key_usage; // AMD_SIG_USAGE
	uint64_t reserved_0;
	uint64_t reserved_1;
	uint32_t pub_exp_size; // Size of public exponent in bits. Must be 2048/4096.
	uint32_t modulus_size; // Size of modulus in bits. Must be 2048/4096.
	amd_cert_pub_exp pub_exp; // Public exponent of this key. Size is pub_exp_size.
	amd_cert_mod modulus; // Public modulus of this key. Size is modulus_size.
	amd_cert_sig sig; // Public signature of this key. Size is modulus_size.
} amd_cert;

static uint8_t amd_root_key_id_naples[AMD_CERT_ID_SIZE_BYTES] = { 0x1b, 0xb9, 0x87, 0xc3,
								  0x59, 0x49, 0x46, 0x06,
								  0xb1, 0x74, 0x94, 0x56,
								  0x01, 0xc9, 0xea, 0x5b };

static uint8_t amd_root_key_id_rome[AMD_CERT_ID_SIZE_BYTES] = { 0xe6, 0x00, 0x21, 0x22, 0xfb, 0x58,
								0x41, 0x93, 0x99, 0xd1, 0x5f, 0xee,
								0x7b, 0x13, 0x13, 0x51 };

static uint8_t amd_root_key_id_milan[AMD_CERT_ID_SIZE_BYTES] = { 0x94, 0xC3, 0x8E, 0x41, 0x77, 0xD0,
								 0x47, 0x92, 0x92, 0xA7, 0xAE, 0x67,
								 0x1D, 0x08, 0x3F, 0xB6 };

size_t amd_cert_get_size(const amd_cert *cert);
int amd_cert_init(amd_cert *cert, const uint8_t *buffer);
bool amd_cert_validate_ark(const amd_cert *ark, enum ePSP_DEVICE_TYPE device_type);
bool amd_cert_validate_ask(const amd_cert *ask, const amd_cert *ark,
			   enum ePSP_DEVICE_TYPE device_type);
int amd_cert_export_pub_key(const amd_cert *cert, sev_cert *pub_key_cert);

#endif /* _AMDCERT_H */
