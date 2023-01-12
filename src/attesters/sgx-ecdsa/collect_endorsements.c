/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2023 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <unistd.h>
#include <rats-tls/log.h>
#include <rats-tls/attester.h>
#include <stddef.h>

// clang-format off
#ifdef SGX
#include <sgx_lfence.h>
#include "rtls_t.h"
#include <sgx_ql_quote.h>
// clang-format on

enclave_attester_err_t sgx_ecdsa_collect_endorsements(enclave_attester_ctx_t *ctx,
						      attestation_evidence_t *evidence,
						      attestation_endorsement_t *endorsements)
{
	enclave_attester_err_t ret = ENCLAVE_ATTESTER_ERR_NONE;
	uint8_t *collateral_untrusted = NULL; /* address of collateral in untrusted-app */

	RTLS_DEBUG("ctx %p, evidence %p, endorsements %p\n", ctx, evidence, endorsements);

	int sgx_status = ocall_tee_qv_get_collateral(
		&ret, evidence->ecdsa.quote, evidence->ecdsa.quote_len, &collateral_untrusted);
	if (sgx_status != SGX_SUCCESS || ret != ENCLAVE_ATTESTER_ERR_NONE) {
		RTLS_ERR("ocall_tee_qv_get_collateral() failed: sgx_status: %#x, ret: %#x\n",
			 sgx_status, ret);
		if (sgx_status != SGX_SUCCESS)
			ret = ENCLAVE_ATTESTER_ERR_UNKNOWN;
		goto err;
	}
	RTLS_DEBUG("ocall_tee_qv_get_collateral() succeeded. collateral_untrusted: %p\n",
		   collateral_untrusted);

	/* Since we have to access memory pointed to by collateral_untrusted, before that we check if this memory is in the untrusted-app. */
	if (!sgx_is_outside_enclave(collateral_untrusted, sizeof(sgx_ql_qve_collateral_t))) {
		ret = ENCLAVE_ATTESTER_ERR_INVALID;
		goto err;
	}
	/* fence after boundary check */
	sgx_lfence();

	/* Copy collateral struct from untrusted-app to enclave memory */
	sgx_ql_qve_collateral_t collateral;
	memcpy(&collateral, collateral_untrusted, sizeof(sgx_ql_qve_collateral_t));

	/* Copy fields from collateral to endorsements->ecdsa */
	sgx_ql_qve_collateral_t *c = &collateral;
	sgx_ecdsa_attestation_collateral_t *e = &endorsements->ecdsa;

	e->version = c->version;
	#define COPY_ENDORSEMENT_FIELD(value_field, size_field)                                            \
		{                                                                                          \
			/* Make sure the memory that each filed pointed to is in the untrusted-app side */ \
			if (!sgx_is_outside_enclave(c->value_field, c->size_field)) {                      \
				ret = ENCLAVE_ATTESTER_ERR_INVALID;                                        \
				goto err;                                                                  \
			}                                                                                  \
			sgx_lfence();                                                                      \
			e->value_field = malloc(c->size_field);                                            \
			if (!e->value_field) {                                                             \
				ret = ENCLAVE_ATTESTER_ERR_NO_MEM;                                         \
				goto err;                                                                  \
			}                                                                                  \
			memcpy(e->value_field, c->value_field, c->size_field);                             \
			e->size_field = c->size_field;                                                     \
		}

	COPY_ENDORSEMENT_FIELD(pck_crl_issuer_chain, pck_crl_issuer_chain_size);

	COPY_ENDORSEMENT_FIELD(root_ca_crl, root_ca_crl_size);

	COPY_ENDORSEMENT_FIELD(pck_crl, pck_crl_size);

	COPY_ENDORSEMENT_FIELD(tcb_info_issuer_chain, tcb_info_issuer_chain_size);

	COPY_ENDORSEMENT_FIELD(tcb_info, tcb_info_size);

	COPY_ENDORSEMENT_FIELD(qe_identity_issuer_chain, qe_identity_issuer_chain_size);

	COPY_ENDORSEMENT_FIELD(qe_identity, qe_identity_size);

	RTLS_DEBUG(
		"version: %u, pck_crl_issuer_chain_size: %u, root_ca_crl_size: %u, pck_crl_size: %u, tcb_info_issuer_chain_size: %u, tcb_info_size: %u, qe_identity_issuer_chain_size: %u, qe_identity_size: %u\n",
		c->version, c->pck_crl_issuer_chain_size, c->root_ca_crl_size, c->pck_crl_size,
		c->tcb_info_issuer_chain_size, c->tcb_info_size, c->qe_identity_issuer_chain_size,
		c->qe_identity_size);

	ret = ENCLAVE_ATTESTER_ERR_NONE;
err:
	if (collateral_untrusted) {
		enclave_attester_err_t q_ret;
		sgx_status = ocall_tee_qv_free_collateral(&q_ret, collateral_untrusted);
		if (sgx_status != SGX_SUCCESS || ret != ENCLAVE_ATTESTER_ERR_NONE) {
			RTLS_ERR(
				"ocall_tee_qv_free_collateral() failed: sgx_status: %#x, q_ret: %#x\n",
				sgx_status, q_ret);
		}
	}

	if (ret != ENCLAVE_ATTESTER_ERR_NONE)
		free_endorsements(evidence->type, endorsements);
	return ret;
}

#else

enclave_attester_err_t sgx_ecdsa_collect_endorsements(enclave_attester_ctx_t *ctx,
						      attestation_evidence_t *evidence,
						      attestation_endorsement_t *endorsements)
{
	RTLS_DEBUG("ctx %p, evidence %p, endorsements %p\n", ctx, evidence, endorsements);

	RTLS_WARN("Collecting endorsements on modes other than SGX is not supported.\n");

	return ENCLAVE_ATTESTER_ERR_UNKNOWN;
}
#endif