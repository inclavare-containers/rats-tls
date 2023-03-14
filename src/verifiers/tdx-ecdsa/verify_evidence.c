/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <rats-tls/log.h>
#include <rats-tls/verifier.h>
#include "tdx-ecdsa.h"
// clang-format off
#ifdef SGX
#include <rtls_t.h>
#include <sgx_utils.h>
#include <sgx_trts.h>
#include <time.h>
#else
#include <sgx_dcap_quoteverify.h>
#endif
// clang-format on

#ifdef SGX
static enclave_verifier_err_t ecdsa_verify_evidence(__attribute__((unused))
						    enclave_verifier_ctx_t *ctx,
						    attestation_evidence_t *evidence,
						    attestation_endorsement_t *endorsements)
{
	enclave_verifier_err_t err = ENCLAVE_VERIFIER_ERR_NONE;
	time_t current_time;
	uint32_t collateral_expiration_status = 1;
	sgx_isv_svn_t qve_isvsvn_threshold = 7; /* This value is published by Intel(R) PCS */
	sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	sgx_ql_qe_report_info_t qve_report_info = { 0 };
	uint8_t rand_nonce[sizeof(qve_report_info.nonce.rand)];
	uint32_t latest_version = 0;
	tee_supp_data_descriptor_t supp_data = { 0 };

	/* In QvE verifier mode, we need to provide a 'nonce' and current enclave's target info. */
	sgx_read_rand(rand_nonce, sizeof(rand_nonce));
	memcpy(qve_report_info.nonce.rand, rand_nonce, sizeof(rand_nonce));

	sgx_status_t sgx_self_target_ret =
		sgx_self_target(&qve_report_info.app_enclave_target_info);
	if (sgx_self_target_ret != SGX_SUCCESS) {
		RTLS_ERR("failed to get self target info sgx_self_target_ret. %04x\n",
			 sgx_self_target_ret);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)sgx_self_target_ret);
		goto errret;
	}

	int sgx_status = ocall_tee_get_supplemental_data_version_and_size(&err, evidence->tdx.quote,
									  evidence->tdx.quote_len,
									  &latest_version,
									  &supp_data.data_size);
	if (sgx_status != SGX_SUCCESS || err != ENCLAVE_VERIFIER_ERR_NONE) {
		RTLS_ERR(
			"ocall_tee_get_supplemental_data_version_and_size() failed. sgx_status: %#x, err: %#x\n",
			sgx_status, err);
		if (sgx_status == SGX_SUCCESS)
			err = ENCLAVE_VERIFIER_ERR_UNKNOWN;
		goto errret;
	}
	RTLS_INFO("sgx qv gets quote supplemental data size successfully.\n");

	supp_data.p_data = (uint8_t *)malloc(supp_data.data_size);
	if (!supp_data.p_data) {
		RTLS_ERR("failed to malloc supplemental data space.\n");
		err = ENCLAVE_VERIFIER_ERR_NO_MEM;
		goto errret;
	}
	memset(supp_data.p_data, 0, supp_data.data_size);

	{
		// TODO: get current time from a trusted clock source
		double t;
		sgx_status = ocall_current_time(&t);
		if (sgx_status != SGX_SUCCESS) {
			RTLS_ERR(
				"failed to get current time, since ocall_current_time() failed. sgx_status: %#x\n",
				sgx_status);
			err = ENCLAVE_VERIFIER_ERR_UNKNOWN;
			goto errret;
		}
		current_time = (time_t)t;
	}

	if (endorsements) {
		sgx_status = ocall_ecdsa_verify_evidence(
			&err, evidence->tdx.quote, evidence->tdx.quote_len,
			endorsements->ecdsa.version, endorsements->ecdsa.pck_crl_issuer_chain,
			endorsements->ecdsa.pck_crl_issuer_chain_size,
			endorsements->ecdsa.root_ca_crl, endorsements->ecdsa.root_ca_crl_size,
			endorsements->ecdsa.pck_crl, endorsements->ecdsa.pck_crl_size,
			endorsements->ecdsa.tcb_info_issuer_chain,
			endorsements->ecdsa.tcb_info_issuer_chain_size,
			endorsements->ecdsa.tcb_info, endorsements->ecdsa.tcb_info_size,
			endorsements->ecdsa.qe_identity_issuer_chain,
			endorsements->ecdsa.qe_identity_issuer_chain_size,
			endorsements->ecdsa.qe_identity, endorsements->ecdsa.qe_identity_size,
			current_time, &collateral_expiration_status, &quote_verification_result,
			&qve_report_info, supp_data.major_version, supp_data.data_size,
			supp_data.p_data);
	} else {
		sgx_status = ocall_ecdsa_verify_evidence(
			&err, evidence->tdx.quote, evidence->tdx.quote_len, 0, NULL, 0, NULL, 0,
			NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, current_time,
			&collateral_expiration_status, &quote_verification_result, &qve_report_info,
			supp_data.major_version, supp_data.data_size, supp_data.p_data);
	}
	if (sgx_status != SGX_SUCCESS || err != ENCLAVE_VERIFIER_ERR_NONE) {
		RTLS_ERR(
			"ocall_ecdsa_verify_evidence() failed. sgx_status: %#x, err: %#x, collateral_expiration_status: %#x, quote_verification_result: %#x\n",
			sgx_status, err, collateral_expiration_status, quote_verification_result);
		if (sgx_status == SGX_SUCCESS)
			err = ENCLAVE_VERIFIER_ERR_UNKNOWN;
		goto errret;
	}
	RTLS_INFO(
		"quote verification completed. quote_verification_result: %#x, collateral_expiration_status: %#x\n",
		quote_verification_result, collateral_expiration_status);

	/* For security purposes, we have to re-full the rand field before calling sgx_tvl_verify_qve_report_and_identity(), since the parameter 'p_qve_reporret_info' is marked as '[in, out]' in ocall_ecdsa_verify_evidence() */
	memcpy(qve_report_info.nonce.rand, rand_nonce, sizeof(rand_nonce));

	quote3_error_t verify_qveid_ret = sgx_tvl_verify_qve_report_and_identity(
		evidence->tdx.quote, evidence->tdx.quote_len, &qve_report_info, current_time,
		collateral_expiration_status, quote_verification_result, supp_data.p_data,
		supp_data.data_size, qve_isvsvn_threshold);
	if (verify_qveid_ret != SGX_QL_SUCCESS) {
		RTLS_ERR("verify QvE report and identity failed. %04x\n", verify_qveid_ret);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)verify_qveid_ret);
		goto errret;
	} else
		RTLS_INFO("verify QvE report and identity successfully.\n");

	/* Note that even if the Verify Quote API returns SGX_QL_SUCCESS, we still need to check collateral_expiration_status and quote_verification_result. */

	/* Check collateral expiration status */
	if (collateral_expiration_status != 0) {
		RTLS_ERR("verification failed because collateral is expired.\n");
		err = ENCLAVE_VERIFIER_ERR_UNKNOWN;
		goto errret;
	}

	/* Check verification result */
	switch (quote_verification_result) {
	case SGX_QL_QV_RESULT_OK:
	/* FIXME: currently we deem this as success */
	case SGX_QL_QV_RESULT_OUT_OF_DATE:
		RTLS_INFO("verification completed successfully.\n");
		err = ENCLAVE_VERIFIER_ERR_NONE;
		break;
	case SGX_QL_QV_RESULT_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
	case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
		RTLS_WARN("verification completed with Non-terminal result: %x\n",
			  quote_verification_result);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
	case SGX_QL_QV_RESULT_REVOKED:
	case SGX_QL_QV_RESULT_UNSPECIFIED:
	default:
		RTLS_WARN("verification completed with Terminal result: %x\n",
			  quote_verification_result);
		err = (int)quote_verification_result;
		break;
	}
errret:
	if (supp_data.p_data)
		free(supp_data.p_data);
	return err;
}

#else
static enclave_verifier_err_t ecdsa_verify_evidence(__attribute__((unused))
						    enclave_verifier_ctx_t *ctx,
						    attestation_evidence_t *evidence,
						    attestation_endorsement_t *endorsements)
{
	enclave_verifier_err_t err = ENCLAVE_VERIFIER_ERR_UNKNOWN;

	/* Call DCAP quote verify library to get supplemental data size */
	uint32_t supplemental_data_size = 0;
	uint8_t *p_supplemental_data = NULL;
	quote3_error_t dcap_ret = tdx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
	if (dcap_ret == SGX_QL_SUCCESS &&
	    supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t)) {
		RTLS_INFO("tdx qv gets quote supplemental data size successfully.\n");
		p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
		if (!p_supplemental_data) {
			RTLS_ERR("failed to malloc supplemental data space.\n");
			return -ENCLAVE_VERIFIER_ERR_NO_MEM;
		}
	} else {
		RTLS_ERR("failed to get quote supplemental data size by sgx qv: %04x\n", dcap_ret);
		return (int)dcap_ret;
	}

	/* Call DCAP quote verify library for quote verification */
	time_t current_time = time(NULL);
	sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	uint32_t collateral_expiration_status = 1;

	if (endorsements) {
		sgx_ql_qve_collateral_t collateral = {
			.version = endorsements->ecdsa.version,
			.tee_type = 0x00000081, /* TDX */
			.pck_crl_issuer_chain = endorsements->ecdsa.pck_crl_issuer_chain,
			.pck_crl_issuer_chain_size = endorsements->ecdsa.pck_crl_issuer_chain_size,
			.root_ca_crl = endorsements->ecdsa.root_ca_crl,
			.root_ca_crl_size = endorsements->ecdsa.root_ca_crl_size,
			.pck_crl = endorsements->ecdsa.pck_crl,
			.pck_crl_size = endorsements->ecdsa.pck_crl_size,
			.tcb_info_issuer_chain = endorsements->ecdsa.tcb_info_issuer_chain,
			.tcb_info_issuer_chain_size =
				endorsements->ecdsa.tcb_info_issuer_chain_size,
			.tcb_info = endorsements->ecdsa.tcb_info,
			.tcb_info_size = endorsements->ecdsa.tcb_info_size,
			.qe_identity_issuer_chain = endorsements->ecdsa.qe_identity_issuer_chain,
			.qe_identity_issuer_chain_size =
				endorsements->ecdsa.qe_identity_issuer_chain_size,
			.qe_identity = endorsements->ecdsa.qe_identity,
			.qe_identity_size = endorsements->ecdsa.qe_identity_size,
		};

		dcap_ret = tdx_qv_verify_quote(evidence->tdx.quote,
					       (uint32_t)(evidence->tdx.quote_len), &collateral,
					       current_time, &collateral_expiration_status,
					       &quote_verification_result, NULL,
					       supplemental_data_size, p_supplemental_data);
	} else {
		dcap_ret = tdx_qv_verify_quote(evidence->tdx.quote,
					       (uint32_t)(evidence->tdx.quote_len), NULL,
					       current_time, &collateral_expiration_status,
					       &quote_verification_result, NULL,
					       supplemental_data_size, p_supplemental_data);
	}
	if (dcap_ret == SGX_QL_SUCCESS) {
		RTLS_INFO("tdx qv verifies quote successfully.\n");
	} else {
		RTLS_ERR("failed to verify quote by tdx qv: %04x\n", dcap_ret);
		err = (int)quote_verification_result;
		goto errret;
	}

	/* Check verification result */
	switch (quote_verification_result) {
	case SGX_QL_QV_RESULT_OK:
	/* FIXME: currently we deem this as success */
	case SGX_QL_QV_RESULT_OUT_OF_DATE:
		RTLS_INFO("verification completed successfully.\n");
		err = ENCLAVE_VERIFIER_ERR_NONE;
		break;
	case SGX_QL_QV_RESULT_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
	case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
		RTLS_WARN("verification completed with Non-terminal result: %x\n",
			  quote_verification_result);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
	case SGX_QL_QV_RESULT_REVOKED:
	case SGX_QL_QV_RESULT_UNSPECIFIED:
	default:
		RTLS_WARN("verification completed with Terminal result: %x\n",
			  quote_verification_result);
		err = (int)quote_verification_result;
		break;
	}
errret:
	free(p_supplemental_data);

	return err;
}
#endif

enclave_verifier_err_t tdx_ecdsa_verify_evidence(enclave_verifier_ctx_t *ctx,
						 attestation_evidence_t *evidence, uint8_t *hash,
						 uint32_t hash_len,
						 attestation_endorsement_t *endorsements)
{
	RTLS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	enclave_verifier_err_t err = ENCLAVE_VERIFIER_ERR_UNKNOWN;

	/* First verify the hash value */
	if (memcmp(hash, ((tdx_quote_t *)(evidence->tdx.quote))->report_body.report_data,
		   hash_len) != 0) {
		RTLS_ERR("unmatched hash value in evidence.\n");
		return ENCLAVE_VERIFIER_ERR_INVALID;
	}

	err = ecdsa_verify_evidence(ctx, evidence, endorsements);
	if (err != ENCLAVE_VERIFIER_ERR_NONE)
		RTLS_ERR("failed to verify ecdsa\n");

	return err;
}
