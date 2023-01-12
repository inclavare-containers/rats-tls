/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/attester.h>
#include <string.h>
#include <sgx_error.h>
#include <sgx_report.h>

extern sgx_status_t sgx_generate_evidence(sgx_report_data_t *report_data, sgx_report_t *app_report);

/* The local attestation requires to exchange the target info between ISV
 * enclaves as the prerequisite. This is out of scope in rats-tls because it
 * requires to establish a out of band channel to do that. Instead, introduce
 * QE as the intermediator. One ISV enclave as attester can request the local
 * reports signed by QE and the opposite end of ISV enclave as verifier can
 * check the validation of local report through calling sgx_qe_get_attester()
 * which verifies the signed local report. Once getting attester successfully,
 * it presents ISV enclave's local report has been fully verified.
 */
enclave_attester_err_t sgx_la_collect_evidence(enclave_attester_ctx_t *ctx,
					       attestation_evidence_t *evidence,
					       rats_tls_cert_algo_t algo, uint8_t *hash,
					       uint32_t hash_len)
{
	RTLS_DEBUG("ctx %p, evidence %p, algo %d, hash %p\n", ctx, evidence, algo, hash);

	sgx_report_data_t report_data;
	if (sizeof(report_data.d) < hash_len) {
		RTLS_ERR("hash_len(%zu) shall be smaller than user-data filed size (%zu)\n",
			 hash_len, sizeof(report_data.d));
		return ENCLAVE_ATTESTER_ERR_INVALID;
	}
	memset(&report_data, 0, sizeof(sgx_report_data_t));
	memcpy(report_data.d, hash, hash_len);

	sgx_report_t isv_report;
	sgx_status_t generate_evidence_ret;
	generate_evidence_ret = sgx_generate_evidence(&report_data, &isv_report);
	if (generate_evidence_ret != SGX_SUCCESS) {
		RTLS_ERR("failed to generate evidence %#x\n", generate_evidence_ret);
		return SGX_LA_ATTESTER_ERR_CODE((int)generate_evidence_ret);
	}

	memcpy(evidence->la.report, &isv_report, sizeof(isv_report));
	evidence->la.report_len = sizeof(isv_report);

	snprintf(evidence->type, sizeof(evidence->type), "%s", "sgx_la");

	return ENCLAVE_ATTESTER_ERR_NONE;
}
