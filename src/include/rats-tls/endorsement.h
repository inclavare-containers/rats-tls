/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _RATS_TLS_ENDORSEMENT_H
#define _RATS_TLS_ENDORSEMENT_H

#include <stdint.h>

typedef struct {
	uint32_t version;
	char *pck_crl_issuer_chain;
	uint32_t pck_crl_issuer_chain_size;
	char *root_ca_crl;
	uint32_t root_ca_crl_size;
	char *pck_crl;
	uint32_t pck_crl_size;
	char *tcb_info_issuer_chain;
	uint32_t tcb_info_issuer_chain_size;
	char *tcb_info;
	uint32_t tcb_info_size;
	char *qe_identity_issuer_chain;
	uint32_t qe_identity_issuer_chain_size;
	char *qe_identity;
	uint32_t qe_identity_size;
} sgx_ecdsa_attestation_collateral_t;

typedef struct {
	union {
		sgx_ecdsa_attestation_collateral_t ecdsa; /* SGX / TDX ECDSA */
	};
} attestation_endorsement_t;

void free_endorsements(const char *type, attestation_endorsement_t *endorsements);

#endif
