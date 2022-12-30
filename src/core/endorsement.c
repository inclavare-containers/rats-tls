/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <rats-tls/endorsement.h>
#include <rats-tls/err.h>
#include <rats-tls/log.h>

void free_endorsements(const char *type, attestation_endorsement_t *endorsements)
{
	if (!type || !endorsements)
		return;

	if (!strcmp(type, "sgx_ecdsa") || !strcmp(type, "tdx_ecdsa")) {
		if (endorsements->ecdsa.pck_crl_issuer_chain) {
			free(endorsements->ecdsa.pck_crl_issuer_chain);
			endorsements->ecdsa.pck_crl_issuer_chain = NULL;
		}
		if (endorsements->ecdsa.root_ca_crl) {
			free(endorsements->ecdsa.root_ca_crl);
			endorsements->ecdsa.root_ca_crl = NULL;
		}
		if (endorsements->ecdsa.pck_crl) {
			free(endorsements->ecdsa.pck_crl);
			endorsements->ecdsa.pck_crl = NULL;
		}
		if (endorsements->ecdsa.tcb_info_issuer_chain) {
			free(endorsements->ecdsa.tcb_info_issuer_chain);
			endorsements->ecdsa.tcb_info_issuer_chain = NULL;
		}
		if (endorsements->ecdsa.tcb_info) {
			free(endorsements->ecdsa.tcb_info);
			endorsements->ecdsa.tcb_info = NULL;
		}
		if (endorsements->ecdsa.qe_identity_issuer_chain) {
			free(endorsements->ecdsa.qe_identity_issuer_chain);
			endorsements->ecdsa.qe_identity_issuer_chain = NULL;
		}
		if (endorsements->ecdsa.qe_identity) {
			free(endorsements->ecdsa.qe_identity);
			endorsements->ecdsa.qe_identity = NULL;
		}
	} else {
		RTLS_WARN("Unable to free endorsements: unsupported evidence type: %s\n", type);
	}
}
