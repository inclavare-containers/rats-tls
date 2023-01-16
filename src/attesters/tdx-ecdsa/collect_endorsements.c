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
#include <tdx_attest.h>
#include <sgx_dcap_quoteverify.h>

enclave_attester_err_t tdx_ecdsa_collect_endorsements(enclave_attester_ctx_t *ctx,
						      attestation_evidence_t *evidence,
						      attestation_endorsement_t *endorsements)
{
	enclave_attester_err_t ret = ENCLAVE_ATTESTER_ERR_NONE;
	sgx_ql_qve_collateral_t *collateral = NULL;

	RTLS_DEBUG("ctx %p, evidence %p, endorsements %p\n", ctx, evidence, endorsements);

	uint32_t collateral_size;
	quote3_error_t qv_ret = tee_qv_get_collateral(evidence->tdx.quote, evidence->tdx.quote_len,
						      (uint8_t **)&collateral, &collateral_size);
	if (SGX_QL_SUCCESS != qv_ret) {
		RTLS_ERR("tee_qv_get_collateral(): 0x%04x\n", qv_ret);
		ret = SGX_ECDSA_ATTESTER_ERR_CODE((int)qv_ret);
		goto err;
	}

	/* Copy fields from collateral to endorsements->ecdsa */
	sgx_ql_qve_collateral_t *c = collateral;
	sgx_ecdsa_attestation_collateral_t *e = &endorsements->ecdsa;

	e->version = c->version;
#define COPY_ENDORSEMENT_FIELD(value_field, size_field)                \
	{                                                              \
		e->value_field = malloc(c->size_field);                \
		if (!e->value_field) {                                 \
			ret = ENCLAVE_ATTESTER_ERR_NO_MEM;             \
			goto err;                                      \
		}                                                      \
		memcpy(e->value_field, c->value_field, c->size_field); \
		e->size_field = c->size_field;                         \
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
	if (collateral) {
		quote3_error_t qv_ret = tee_qv_free_collateral((uint8_t *)collateral);
		if (SGX_QL_SUCCESS != qv_ret) {
			RTLS_ERR("tee_qv_free_collateral(): 0x%04x\n", qv_ret);
		}
	}

	if (ret != ENCLAVE_ATTESTER_ERR_NONE)
		free_endorsements(evidence->type, endorsements);
	return ret;
}
