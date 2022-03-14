/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _ENCLAVE_CERT_H
#define _ENCLAVE_CERT_H

#define OID_LENGTH 64

typedef struct {
	const unsigned char *organization;
	const unsigned char *organization_unit;
	const unsigned char *common_name;
} cert_subject_t;

typedef struct {
	uint8_t ias_report[2 * 1024];
	uint32_t ias_report_len;
	uint8_t ias_sign_ca_cert[2 * 1024];
	uint32_t ias_sign_ca_cert_len;
	uint8_t ias_sign_cert[2 * 1024];
	uint32_t ias_sign_cert_len;
	uint8_t ias_report_signature[2 * 1024];
	uint32_t ias_report_signature_len;
} attestation_verification_report_t;

typedef struct {
	uint8_t report[8192];
	uint32_t report_len;
} tee_attestation_evidence_t;

typedef struct {
	char type[ENCLAVE_ATTESTER_TYPE_NAME_SIZE];
	union {
		attestation_verification_report_t epid;
		tee_attestation_evidence_t evidence;
	};
} attestation_evidence_t;

typedef struct {
	cert_subject_t subject;
	unsigned int cert_len;
	uint8_t cert_buf[8192];
	attestation_evidence_t evidence;
} rats_tls_cert_info_t;

#endif
