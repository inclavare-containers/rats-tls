/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _SEV_H
#define _SEV_H

#include <linux/types.h>
#include "../../verifiers/sev-snp/sevapi.h"

/* The following structures are defined by AMD, please refer to
 * https://www.amd.com/system/files/TechDocs/55766_SEV-KM_API_Specification.pdf for details.
 */

typedef struct __attribute__((__packed__)) sev_attestation_report_t {
	uint8_t mnonce[16];
	uint8_t launch_digest[32];
	uint32_t policy;
	uint32_t sig_usage;
	uint32_t sig_algo;
	uint32_t reserved;
	uint8_t sig1[144];
} sev_attestation_report;

/* Appendix C.3: SEV Certificates */
#define SEV_RSA_PUB_KEY_MAX_BITS   4096
#define SEV_ECDSA_PUB_KEY_MAX_BITS 576
#define SEV_ECDH_PUB_KEY_MAX_BITS  576
#define SEV_PUB_KEY_SIZE	   (SEV_RSA_PUB_KEY_MAX_BITS / 8)

/* Appendix C.3.1 Public Key Formats - RSA Public Key
 * SEV RSA Public key information.
 *
 * @modulus_size - Size of modulus in bits.
 * @pub_exp      - The public exponent of the public key.
 * @modulus      - The modulus of the public key.
 */
typedef struct __attribute__((__packed__)) sev_rsa_pub_key_t {
	uint32_t modulus_size;
	uint8_t pub_exp[SEV_RSA_PUB_KEY_MAX_BITS / 8];
	uint8_t modulus[SEV_RSA_PUB_KEY_MAX_BITS / 8];
} sev_rsa_pub_key;

/* SEV Elliptical Curve algorithm details.
 *
 * @SEV_EC_INVALID - Invalid cipher size selected.
 * @SEV_EC_P256    - 256 bit elliptical curve cipher.
 * @SEV_EC_P384    - 384 bit elliptical curve cipher.
 */
typedef enum __attribute__((mode(QI)))
SEV_EC { SEV_EC_INVALID = 0,
	 SEV_EC_P256 = 1,
	 SEV_EC_P384 = 2,
} SEV_EC;

/* Appendix C.3.2: Public Key Formats - ECDSA Public Key
 * SEV Elliptical Curve DSA algorithm details.
 *
 * @curve - The SEV Elliptical curve ID.
 * @qx    - x component of the public point Q.
 * @qy    - y component of the public point Q.
 * @rmbz  - RESERVED. Must be zero!
 */
typedef struct __attribute__((__packed__)) sev_ecdsa_pub_key_t {
	uint32_t curve; // SEV_EC as a uint32_t
	uint8_t qx[SEV_ECDSA_PUB_KEY_MAX_BITS / 8];
	uint8_t qy[SEV_ECDSA_PUB_KEY_MAX_BITS / 8];
	uint8_t rmbz[SEV_PUB_KEY_SIZE - 2 * SEV_ECDSA_PUB_KEY_MAX_BITS / 8 - sizeof(uint32_t)];
} sev_ecdsa_pub_key;

/* Appendix C.3.3: Public Key Formats - ECDH Public Key
 * SEV Elliptical Curve Diffie Hellman Public Key details.
 *
 * @curve - The SEV Elliptical curve ID.
 * @qx    - x component of the public point Q.
 * @qy    - y component of the public point Q.
 * @rmbz  - RESERVED. Must be zero!
 */
typedef struct __attribute__((__packed__)) sev_ecdh_pub_key_t {
	uint32_t curve; // SEV_EC as a uint32_t
	uint8_t qx[SEV_ECDH_PUB_KEY_MAX_BITS / 8];
	uint8_t qy[SEV_ECDH_PUB_KEY_MAX_BITS / 8];
	uint8_t rmbz[SEV_PUB_KEY_SIZE - 2 * SEV_ECDH_PUB_KEY_MAX_BITS / 8 - sizeof(uint32_t)];
} sev_ecdh_pub_key;

/* Appendix C.4: Public Key Formats
 * The SEV Public Key memory slot may hold RSA, ECDSA, or ECDH.
 */
typedef union {
	sev_rsa_pub_key rsa;
	sev_ecdsa_pub_key ecdsa;
	sev_ecdh_pub_key ecdh;
} sev_pubkey;

/* Appendix C.1: USAGE Enumeration
 * SEV Usage codes.
 */
typedef enum __attribute__((mode(HI))) SEV_USAGE {
	SEV_USAGE_ARK = 0x0,
	SEV_USAGE_ASK = 0x13,
	SEV_USAGE_INVALID = 0x1000,
	SEV_USAGE_OCA = 0x1001,
	SEV_USAGE_PEK = 0x1002,
	SEV_USAGE_PDH = 0x1003,
	SEV_USAGE_CEK = 0x1004,
} SEV_USAGE;

/* Appendix C.1: SEV Certificate Format
 * SEV Certificate format.
 *
 * @version       - Certificate version, set to 01h.
 * @api_major     - If PEK, set to API major version, otherwise zero.
 * @api_minor     - If PEK, set to API minor version, otherwise zero.
 * @reserved_0    - RESERVED, Must be zero!
 * @reserved_1    - RESERVED, Must be zero!
 * @pub_key_usage - Public key usage              (SEV_SIG_USAGE).
 * @pub_key_algo  - Public key algorithm          (SEV_SIG_ALGO).
 * @pub_key       - Public Key.
 * @sig_1_usage   - Key usage of SIG1 signing key (SEV_SIG_USAGE).
 * @sig_1_algo    - First signature algorithm     (SEV_SIG_ALGO).
 * @sig_1         - First signature.
 * @sig_2_usage   - Key usage of SIG2 signing key (SEV_SIG_USAGE).
 * @sig_2_algo    - Second signature algorithm    (SEV_SIG_ALGO).
 * @sig_2         - Second signature
 */
typedef struct __attribute__((__packed__)) sev_cert_t {
	uint32_t version;
	uint8_t api_major;
	uint8_t api_minor;
	uint8_t reserved_0;
	uint8_t reserved_1;
	uint32_t pub_key_usage;
	uint32_t pub_key_algo;
	sev_pubkey pub_key;
	uint32_t sig_1_usage;
	uint32_t sig_1_algo;
	sev_sig sig_1;
	uint32_t sig_2_usage;
	uint32_t sig_2_algo;
	sev_sig sig_2;
} sev_cert;

enum __attribute__((mode(QI))) ePSP_DEVICE_TYPE {
	PSP_DEVICE_TYPE_ROME = 0,
	PSP_DEVICE_TYPE_NAPLES = 1,
	PSP_DEVICE_TYPE_MILAN = 2,
	PSP_DEVICE_TYPE_INVALID = 3,
};

typedef struct __attribute__((__packed__)) sev_evidence_t {
	sev_attestation_report attestation_report;
	sev_cert cek_cert;
	sev_cert pek_cert;
	sev_cert oca_cert;
	enum ePSP_DEVICE_TYPE device_type;
} sev_evidence_t;

#endif /* _SEV_H */
