/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>
#include <rats-tls/log.h>
#include <rats-tls/attester.h>
#include <rats-tls/verifier.h>
#include <sgx_urts.h>
#include <sgx_quote.h>
#include <sgx_quote_3.h>
#include <sgx_ql_quote.h>
#include <sgx_dcap_quoteverify.h>
#include <sgx_dcap_ql_wrapper.h>
#include "rtls_u.h"

void ocall_get_target_info(sgx_target_info_t *qe_target_info)
{
	int qe3_ret = sgx_qe_get_target_info(qe_target_info);
	if (SGX_QL_SUCCESS != qe3_ret)
		RTLS_ERR("sgx_qe_get_target_info() with error code 0x%04x\n", qe3_ret);
}

enclave_attester_err_t ocall_qe_get_quote_size(uint32_t *quote_size)
{
	quote3_error_t qe3_ret = sgx_qe_get_quote_size(quote_size);
	if (SGX_QL_SUCCESS != qe3_ret) {
		RTLS_ERR("sgx_qe_get_quote_size(): 0x%04x\n", qe3_ret);
		return SGX_ECDSA_ATTESTER_ERR_CODE((int)qe3_ret);
	}

	return ENCLAVE_ATTESTER_ERR_NONE;
}

enclave_attester_err_t ocall_qe_get_quote(sgx_report_t *report, uint32_t quote_size, uint8_t *quote)
{
	quote3_error_t qe3_ret = sgx_qe_get_quote(report, quote_size, quote);
	if (SGX_QL_SUCCESS != qe3_ret) {
		RTLS_ERR("sgx_qe_get_quote(): 0x%04x\n", qe3_ret);
		return SGX_ECDSA_ATTESTER_ERR_CODE((int)qe3_ret);
	}

	return ENCLAVE_ATTESTER_ERR_NONE;
}

enclave_verifier_err_t ocall_sgx_qv_get_quote_supplemental_data_size(uint32_t *p_data_size)
{
	quote3_error_t dcap_ret = sgx_qv_get_quote_supplemental_data_size(p_data_size);
	if (dcap_ret != SGX_QL_SUCCESS) {
		RTLS_ERR("failed to get quote supplemental data size by sgx qv: %04x\n", dcap_ret);
		return SGX_ECDSA_VERIFIER_ERR_CODE((int)dcap_ret);
	}
	return ENCLAVE_VERIFIER_ERR_NONE;
}

enclave_verifier_err_t ocall_ecdsa_verify_evidence(
	uint8_t *p_quote, uint32_t quote_size, uint32_t collateral_version,
	char *collateral_pck_crl_issuer_chain, uint32_t collateral_pck_crl_issuer_chain_size,
	char *collateral_root_ca_crl, uint32_t collateral_root_ca_crl_size,
	char *collateral_pck_crl, uint32_t collateral_pck_crl_size,
	char *collateral_tcb_info_issuer_chain, uint32_t collateral_tcb_info_issuer_chain_size,
	char *collateral_tcb_info, uint32_t collateral_tcb_info_size,
	char *collateral_qe_identity_issuer_chain,
	uint32_t collateral_qe_identity_issuer_chain_size, char *collateral_qe_identity,
	uint32_t collateral_qe_identity_size, time_t expiration_check_date,
	uint32_t *p_collateral_expiration_status, sgx_ql_qv_result_t *p_quote_verification_result,
	sgx_ql_qe_report_info_t *p_qve_report_info, uint32_t supplemental_data_size,
	uint8_t *p_supplemental_data)

{
	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;
	quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;

	/* sgx_ecdsa_qve instance re-uses this code and thus we need to distinguish
	 * it from sgx_ecdsa instance.
	 */
	bool is_sgx_ecdsa_qve = p_qve_report_info != NULL;
	if (is_sgx_ecdsa_qve) {
		/* Set enclave load policy of Quote Verification Library before loading the QvE enclave. */
		dcap_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
		if (dcap_ret == SGX_QL_SUCCESS)
			RTLS_INFO("sgx qv setting for enclave load policy succeeds.\n");
		else {
			RTLS_ERR("failed to set enclave load policy by sgx qv: %04x\n", dcap_ret);
			err = SGX_ECDSA_VERIFIER_ERR_CODE((int)dcap_ret);
			goto errret;
		}
	}

	if (collateral_pck_crl_issuer_chain && collateral_root_ca_crl && collateral_pck_crl &&
	    collateral_tcb_info_issuer_chain && collateral_tcb_info &&
	    collateral_qe_identity_issuer_chain && collateral_qe_identity) {
		sgx_ql_qve_collateral_t collateral = {
			.version = collateral_version,
			.tee_type = 0x00000000, /* SGX */
			.pck_crl_issuer_chain = collateral_pck_crl_issuer_chain,
			.pck_crl_issuer_chain_size = collateral_pck_crl_issuer_chain_size,
			.root_ca_crl = collateral_root_ca_crl,
			.root_ca_crl_size = collateral_root_ca_crl_size,
			.pck_crl = collateral_pck_crl,
			.pck_crl_size = collateral_pck_crl_size,
			.tcb_info_issuer_chain = collateral_tcb_info_issuer_chain,
			.tcb_info_issuer_chain_size = collateral_tcb_info_issuer_chain_size,
			.tcb_info = collateral_tcb_info,
			.tcb_info_size = collateral_tcb_info_size,
			.qe_identity_issuer_chain = collateral_qe_identity_issuer_chain,
			.qe_identity_issuer_chain_size = collateral_qe_identity_issuer_chain_size,
			.qe_identity = collateral_qe_identity,
			.qe_identity_size = collateral_qe_identity_size,
		};

		dcap_ret = sgx_qv_verify_quote(p_quote, quote_size, &collateral,
					       expiration_check_date,
					       p_collateral_expiration_status,
					       p_quote_verification_result, p_qve_report_info,
					       supplemental_data_size, p_supplemental_data);
	} else {
		dcap_ret = sgx_qv_verify_quote(p_quote, quote_size, NULL, expiration_check_date,
					       p_collateral_expiration_status,
					       p_quote_verification_result, p_qve_report_info,
					       supplemental_data_size, p_supplemental_data);
	}
	if (dcap_ret == SGX_QL_SUCCESS)
		RTLS_INFO("sgx qv verifies quote successfully.\n");
	else {
		RTLS_ERR("failed to verify quote by sgx qv: %04x\n", dcap_ret);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)dcap_ret);
		goto errret;
	}

	err = ENCLAVE_VERIFIER_ERR_NONE;
errret:
	return err;
}

enclave_attester_err_t
ocall_tee_qv_get_collateral(const uint8_t *pquote /* in */, uint32_t quote_size /* in */,
			    uint8_t **pp_quote_collateral_untrusted /* out */)
{
	uint32_t collateral_size;
	quote3_error_t qv_ret = tee_qv_get_collateral(
		pquote, quote_size, pp_quote_collateral_untrusted, &collateral_size);
	if (SGX_QL_SUCCESS != qv_ret) {
		RTLS_ERR("tee_qv_get_collateral(): 0x%04x\n", qv_ret);
		return SGX_ECDSA_ATTESTER_ERR_CODE((int)qv_ret);
	}
	return ENCLAVE_ATTESTER_ERR_NONE;
}

enclave_attester_err_t
ocall_tee_qv_free_collateral(uint8_t *p_quote_collateral_untrusted /* user_check */)
{
	quote3_error_t qv_ret = tee_qv_free_collateral(p_quote_collateral_untrusted);
	if (SGX_QL_SUCCESS != qv_ret) {
		RTLS_ERR("tee_qv_free_collateral(): 0x%04x\n", qv_ret);
		return SGX_ECDSA_ATTESTER_ERR_CODE((int)qv_ret);
	}
	return ENCLAVE_ATTESTER_ERR_NONE;
}
