/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _HYGONCERT_H_
#define _HYGONCERT_H_

#include <rats-tls/csv.h>

typedef enum {
	KEY_USAGE_TYPE_HSK = 0x13,
	KEY_USAGE_TYPE_INVALID = 0x1000,
	KEY_USAGE_TYPE_MIN = 0x1001,
	KEY_USAGE_TYPE_PEK = 0x1002,
	KEY_USAGE_TYPE_PDH = 0x1003,
	KEY_USAGE_TYPE_CEK = 0x1004,
	KEY_USAGE_TYPE_MAX = 0x1004,
} key_usage_t;

#define HYGON_SM2_UID_SIZE 256
#define HYGON_ECC_UID_SIZE HYGON_SM2_UID_SIZE
typedef struct __attribute__((__packed__)) hygon_sm2_pubkey_in_cert {
	uint32_t curve_id;
	uint8_t qx[72];
	uint8_t qy[72];
	uint16_t userid_len;
	uint8_t userid[HYGON_SM2_UID_SIZE - sizeof(uint16_t)];
} hygon_pubkey_t;

typedef struct __attribute__((__packed__)) hygon_sm2_signature_in_cert {
	uint8_t r[72];
	uint8_t s[72];
} hygon_signature_t;

#define HYGON_CHIP_KEY_ID_SIZE 16
typedef struct __attribute__((__packed__)) hygon_root_cert {
	uint32_t version;
	struct {
		uint8_t id[HYGON_CHIP_KEY_ID_SIZE];
	} key_id, certifying_id;
	uint32_t key_usage;
	uint8_t reserved1[24];
	union {
		uint8_t pubkey[4 + 72 * 2 + 256];
		hygon_pubkey_t ecc_pubkey;
	};
	uint8_t reserved2[108];
	union {
		uint8_t signature[72 * 2];
		hygon_signature_t ecc_sig;
	};
	uint8_t reserved3[112];
} hygon_root_cert_t;

typedef struct __attribute__((__packed__)) hygon_csv_sm2_pubkey_in_cert {
	uint32_t curve_id;
	uint8_t qx[72];
	uint8_t qy[72];
	uint16_t uid_len;
	uint8_t uid[HYGON_SM2_UID_SIZE - sizeof(uint16_t)];
	uint8_t reserved[624];
} hygon_csv_pubkey_t;

typedef struct __attribute__((__packed__)) hygon_csv_sm2_signature_in_cert {
	uint8_t r[72];
	uint8_t s[72];
	uint8_t reserved[368];
} hygon_csv_signature_t;

typedef struct __attribute__((__packed__)) csv_cert {
	uint32_t version;
	uint8_t api_major;
	uint8_t api_minor;
	uint8_t reserved1;
	uint8_t reserved2;
	uint32_t pubkey_usage;
	uint32_t pubkey_algo;
	hygon_csv_pubkey_t sm2_pubkey;
	uint32_t sig1_usage;
	uint32_t sig1_algo;
	hygon_csv_signature_t ecc_sig1;
	uint32_t sig2_usage;
	uint32_t sig2_algo;
	hygon_csv_signature_t ecc_sig2;
} csv_cert_t;

int verify_hsk_cert(hygon_root_cert_t *cert);
int verify_cek_cert(hygon_root_cert_t *hsk_cert, csv_cert_t *cek_cert);
int verify_pek_cert(csv_cert_t *cek_cert, csv_cert_t *pek_cert);
int sm2_verify_attestation_report(csv_cert_t *pek_cert, csv_attestation_report *report);

#endif /* _HYGONCERT_H_ */
