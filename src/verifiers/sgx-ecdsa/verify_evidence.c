/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// clang-format off
#include <string.h>
#include <rats-tls/log.h>
#include <rats-tls/verifier.h>
#include <sgx_urts.h>
#include <sgx_quote.h>
#include <sgx_quote_3.h>
#include <sgx_ql_quote.h>
#ifdef SGX
#include <rtls_t.h>
#include <sgx_utils.h>
#include <sgx_trts.h>
#include <time.h>
#elif defined(OCCLUM)
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "quote_verification.h"
#else
#include <sgx_dcap_ql_wrapper.h>
#include <sgx_dcap_quoteverify.h>
#endif
// clang-format on

#ifdef SGX

enclave_verifier_err_t ecdsa_verify_evidence(enclave_verifier_ctx_t *ctx, sgx_quote3_t *pquote,
					     uint32_t quote_size,
					     attestation_endorsement_t *endorsements)
{
	enclave_verifier_err_t err = ENCLAVE_VERIFIER_ERR_NONE;
	time_t current_time;
	uint32_t collateral_expiration_status = 1;
	sgx_isv_svn_t qve_isvsvn_threshold = 7; /* This value is published by Intel(R) PCS */
	sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	uint32_t supplemental_data_size = 0;
	uint8_t *p_supplemental_data = NULL;
	sgx_ql_qe_report_info_t qve_report_info;
	uint8_t rand_nonce[sizeof(qve_report_info.nonce.rand)];

	/* sgx_ecdsa_qve instance re-uses this code and thus we need to distinguish
	 * it from sgx_ecdsa instance.
	 */
	bool is_sgx_ecdsa_qve = !strcmp(ctx->opts->name, "sgx_ecdsa_qve");

	if (is_sgx_ecdsa_qve) {
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
	}

	int sgx_status =
		ocall_sgx_qv_get_quote_supplemental_data_size(&err, &supplemental_data_size);
	if (sgx_status != SGX_SUCCESS || err != ENCLAVE_VERIFIER_ERR_NONE) {
		RTLS_ERR("ocall_ecdsa_verify_evidence() failed. sgx_status: %#x, err: %#x\n",
			 sgx_status, err);
		if (sgx_status == SGX_SUCCESS)
			err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;
		goto errret;
	}
	RTLS_INFO("sgx qv gets quote supplemental data size successfully.\n");

	p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
	if (!p_supplemental_data) {
		RTLS_ERR("failed to malloc supplemental data space.\n");
		err = -ENCLAVE_VERIFIER_ERR_NO_MEM;
		goto errret;
	}

	{
		// TODO: get current time from a trusted clock source
		double t;
		sgx_status = ocall_current_time(&t);
		if (sgx_status != SGX_SUCCESS) {
			RTLS_ERR(
				"failed to get current time, since ocall_current_time() failed. sgx_status: %#x\n",
				sgx_status);
			err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;
			goto errret;
		}
		current_time = (time_t)t;
	}

	if (endorsements) {
		sgx_status = ocall_ecdsa_verify_evidence(
			&err, (uint8_t *)pquote, quote_size, endorsements->ecdsa.version,
			endorsements->ecdsa.pck_crl_issuer_chain,
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
			is_sgx_ecdsa_qve ? &qve_report_info : NULL, supplemental_data_size,
			p_supplemental_data);
	} else {
		sgx_status = ocall_ecdsa_verify_evidence(
			&err, (uint8_t *)pquote, quote_size, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
			NULL, 0, NULL, 0, NULL, 0, current_time, &collateral_expiration_status,
			&quote_verification_result, is_sgx_ecdsa_qve ? &qve_report_info : NULL,
			supplemental_data_size, p_supplemental_data);
	}
	if (sgx_status != SGX_SUCCESS || err != ENCLAVE_VERIFIER_ERR_NONE) {
		RTLS_ERR(
			"ocall_ecdsa_verify_evidence() failed. sgx_status: %#x, err: %#x, collateral_expiration_status: %#x, quote_verification_result: %#x\n",
			sgx_status, err, collateral_expiration_status, quote_verification_result);
		if (sgx_status == SGX_SUCCESS)
			err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;
		goto errret;
	}
	RTLS_INFO(
		"quote verification completed. quote_verification_result: %#x, collateral_expiration_status: %#x\n",
		quote_verification_result, collateral_expiration_status);

	if (is_sgx_ecdsa_qve) {
		/* For security purposes, we have to re-full the rand field before calling sgx_tvl_verify_qve_report_and_identity(), since the parameter 'p_qve_reporret_info' is marked as '[in, out]' in ocall_ecdsa_verify_evidence() */
		memcpy(qve_report_info.nonce.rand, rand_nonce, sizeof(rand_nonce));

		quote3_error_t verify_qveid_ret = sgx_tvl_verify_qve_report_and_identity(
			(uint8_t *)pquote, quote_size, &qve_report_info, current_time,
			collateral_expiration_status, quote_verification_result,
			p_supplemental_data, supplemental_data_size, qve_isvsvn_threshold);
		if (verify_qveid_ret != SGX_QL_SUCCESS) {
			RTLS_ERR("verify QvE report and identity failed. %04x\n", verify_qveid_ret);
			err = SGX_ECDSA_VERIFIER_ERR_CODE((int)verify_qveid_ret);
			goto errret;
		} else
			RTLS_INFO("verify QvE report and identity successfully.\n");
	}

	/* Note that even if the Verify Quote API returns SGX_QL_SUCCESS, we still need to check collateral_expiration_status and quote_verification_result. */

	/* Check collateral expiration status */
	if (collateral_expiration_status != 0) {
		RTLS_ERR("verification failed because collateral is expired.\n");
		err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;
		goto errret;
	}

	/* Check verification result */
	switch (quote_verification_result) {
	case SGX_QL_QV_RESULT_OK:
		RTLS_INFO("verification completed successfully.\n");
		err = ENCLAVE_VERIFIER_ERR_NONE;
		break;
	case SGX_QL_QV_RESULT_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_OUT_OF_DATE:
	case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
	case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
		RTLS_ERR("verification completed with Non-terminal result: %x\n",
			 quote_verification_result);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
	case SGX_QL_QV_RESULT_REVOKED:
	case SGX_QL_QV_RESULT_UNSPECIFIED:
	default:
		RTLS_ERR("verification completed with Terminal result: %x\n",
			 quote_verification_result);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	}

errret:
	if (p_supplemental_data)
		free(p_supplemental_data);
	return err;
}

#elif defined(OCCLUM)

#else

enclave_verifier_err_t ecdsa_verify_evidence(sgx_quote3_t *pquote, uint32_t quote_size,
					     attestation_endorsement_t *endorsements)
{
	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;
	uint32_t supplemental_data_size = 0;
	uint8_t *p_supplemental_data = NULL;
	sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	uint32_t collateral_expiration_status = 1;
	time_t current_time = 0;
	quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;

	dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
	if (dcap_ret == SGX_QL_SUCCESS) {
		RTLS_INFO("sgx qv gets quote supplemental data size successfully.\n");
		p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
		if (!p_supplemental_data) {
			RTLS_ERR("failed to malloc supplemental data space.\n");
			err = -ENCLAVE_VERIFIER_ERR_NO_MEM;
			goto errret;
		}
	} else {
		RTLS_ERR("failed to get quote supplemental data size by sgx qv: %04x\n", dcap_ret);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)dcap_ret);
		goto errret;
	}

	current_time = time(NULL);

	if (endorsements) {
		sgx_ql_qve_collateral_t collateral = {
			.version = endorsements->ecdsa.version,
			.tee_type = 0x00000000, /* SGX */
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

		dcap_ret = sgx_qv_verify_quote((uint8_t *)pquote, (uint32_t)quote_size, &collateral,
					       current_time, &collateral_expiration_status,
					       &quote_verification_result, NULL,
					       supplemental_data_size, p_supplemental_data);
	} else {
		dcap_ret = sgx_qv_verify_quote((uint8_t *)pquote, (uint32_t)quote_size, NULL,
					       current_time, &collateral_expiration_status,
					       &quote_verification_result, NULL,
					       supplemental_data_size, p_supplemental_data);
	}
	if (dcap_ret == SGX_QL_SUCCESS)
		RTLS_INFO("sgx qv verifies quote successfully.\n");
	else {
		RTLS_ERR("failed to verify quote by sgx qv: %04x\n", dcap_ret);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)dcap_ret);
		goto errret;
	}

	/* Check collateral expiration status */
	if (collateral_expiration_status != 0) {
		RTLS_ERR("verification failed because collateral is expired.\n");
		err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;
		goto errret;
	}

	/* Check verification result */
	switch (quote_verification_result) {
	case SGX_QL_QV_RESULT_OK:
		RTLS_INFO("verification completed successfully.\n");
		err = ENCLAVE_VERIFIER_ERR_NONE;
		break;
	case SGX_QL_QV_RESULT_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_OUT_OF_DATE:
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
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	}

errret:
	if (p_supplemental_data)
		free(p_supplemental_data);
	return err;
}
#endif

enclave_verifier_err_t
sgx_ecdsa_verify_evidence(enclave_verifier_ctx_t *ctx, attestation_evidence_t *evidence,
			  uint8_t *hash, __attribute__((unused)) uint32_t hash_len,
			  attestation_endorsement_t *endorsements /* optional */)
{
	RTLS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;

	sgx_quote3_t *pquote = (sgx_quote3_t *)evidence->ecdsa.quote;

	uint32_t quote_size = (uint32_t)sizeof(sgx_quote3_t) + pquote->signature_data_len;
	RTLS_DEBUG("quote size is %d, quote signature_data_len is %d\n", quote_size,
		   pquote->signature_data_len);

	/* First verify the hash value */
	if (memcmp(hash, pquote->report_body.report_data.d, hash_len) != 0) {
		RTLS_ERR("unmatched hash value in evidence.\n");
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}
#ifdef OCCLUM
	uint32_t supplemental_data_size = 0;
	uint8_t *p_supplemental_data = NULL;
	sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	uint32_t collateral_expiration_status = 1;

	int sgx_fd = open("/dev/sgx", O_RDONLY);
	if (sgx_fd < 0) {
		RTLS_ERR("failed to open /dev/sgx\n");
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}

	if (ioctl(sgx_fd, SGXIOC_GET_DCAP_SUPPLEMENTAL_SIZE, &supplemental_data_size) < 0) {
		RTLS_ERR("failed to ioctl get supplemental data size: %s\n", strerror(errno));
		close(sgx_fd);
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}

	p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
	if (!p_supplemental_data) {
		close(sgx_fd);
		return -ENCLAVE_VERIFIER_ERR_NO_MEM;
	}

	memset(p_supplemental_data, 0, supplemental_data_size);

	sgxioc_ver_dcap_quote_arg_t ver_quote_arg = {
		.quote_buf = evidence->ecdsa.quote,
		.quote_size = evidence->ecdsa.quote_len,
		.collateral_expiration_status = &collateral_expiration_status,
		.quote_verification_result = &quote_verification_result,
		.supplemental_data_size = supplemental_data_size,
		.supplemental_data = p_supplemental_data
	};

	if (ioctl(sgx_fd, SGXIOC_VER_DCAP_QUOTE, &ver_quote_arg) < 0) {
		RTLS_ERR("failed to ioctl verify quote: %s\n", strerror(errno));
		free(p_supplemental_data);
		close(sgx_fd);
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}

	close(sgx_fd);

	/* Check collateral expiration status */
	if (collateral_expiration_status != 0) {
		RTLS_ERR("verification failed because collateral is expired.\n");
		free(p_supplemental_data);
		return -ENCLAVE_VERIFIER_ERR_UNKNOWN;
	}

	/* Check verification result */
	switch (quote_verification_result) {
	case SGX_QL_QV_RESULT_OK:
		RTLS_INFO("verification completed successfully.\n");
		err = ENCLAVE_VERIFIER_ERR_NONE;
		break;
	case SGX_QL_QV_RESULT_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_OUT_OF_DATE:
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
		RTLS_ERR("verification completed with Terminal result: %x\n",
			 quote_verification_result);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	}
	free(p_supplemental_data);
#elif defined(SGX)
	err = ecdsa_verify_evidence(ctx, pquote, quote_size, endorsements);
	if (err != ENCLAVE_VERIFIER_ERR_NONE)
		RTLS_ERR("failed to verify ecdsa\n");
#else
	err = ecdsa_verify_evidence(pquote, quote_size, endorsements);
	if (err != ENCLAVE_VERIFIER_ERR_NONE)
		RTLS_ERR("failed to verify ecdsa\n");
#endif

	return err;
}
