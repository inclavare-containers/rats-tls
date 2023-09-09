/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <string.h>
#include <rats-tls/log.h>
#include <rats-tls/verifier.h>
#include <rats-tls/csv.h>
#include "hygoncert.h"

static enclave_verifier_err_t verify_cert_chain(csv_evidence *evidence)
{
	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_INVALID;
	csv_attestation_report *report = &evidence->attestation_report;

	hygon_root_cert_t *hsk_cert = (hygon_root_cert_t *)evidence->hsk_cek_cert;
	csv_cert_t *cek_cert = (csv_cert_t *)(&evidence->hsk_cek_cert[HYGON_CERT_SIZE]);
	csv_cert_t *pek_cert = (csv_cert_t *)report->pek_cert;

	assert(sizeof(hygon_root_cert_t) == HYGON_CERT_SIZE);
	assert(sizeof(csv_cert_t) == HYGON_CSV_CERT_SIZE);

	/* Retrieve PEK cert and ChipId */
	int i, j;

	j = (offsetof(csv_attestation_report, reserved1) -
	     offsetof(csv_attestation_report, pek_cert)) /
	    sizeof(uint32_t);
	for (i = 0; i < j; i++)
		((uint32_t *)report->pek_cert)[i] ^= report->anonce;

	/* Verify HSK cert with HRK */
	if (verify_hsk_cert(hsk_cert) != 1) {
		RTLS_ERR("failed to verify HSK cert\n");
		return err;
	}
	RTLS_DEBUG("verify HSK cert successfully\n");

	/* Verify CEK cert with HSK */
	if (verify_cek_cert(hsk_cert, cek_cert) != 1) {
		RTLS_ERR("failed to verify CEK cert\n");
		return err;
	}
	RTLS_DEBUG("verify CEK cert successfully\n");

	/* Verigy PEK cert with CEK */
	if (verify_pek_cert(cek_cert, pek_cert) != 1) {
		RTLS_ERR("failed to verify PEK cert\n");
		return err;
	}
	RTLS_DEBUG("verify PEK cert successfully\n");

	return ENCLAVE_VERIFIER_ERR_NONE;
}

static enclave_verifier_err_t verify_attestation_report(csv_attestation_report *report)
{
	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_INVALID;

	csv_cert_t *pek_cert = (csv_cert_t *)report->pek_cert;

	if (sm2_verify_attestation_report(pek_cert, report) != 1) {
		RTLS_ERR("failed to verify csv attestation report\n");
		return err;
	}

	return ENCLAVE_VERIFIER_ERR_NONE;
}

enclave_verifier_err_t csv_verify_evidence(enclave_verifier_ctx_t *ctx,
					   attestation_evidence_t *evidence, uint8_t *hash,
					   uint32_t hash_len,
					   __attribute__((unused))
					   attestation_endorsement_t *endorsements)
{
	RTLS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;
	csv_evidence *c_evidence = (csv_evidence *)(&evidence->csv.report);
	csv_attestation_report *attestation_report = &c_evidence->attestation_report;

	/* Retrieve user_data from attestation report */
	uint8_t user_data[CSV_ATTESTATION_USER_DATA_SIZE] = {
		0,
	};
	int i;

	for (i = 0; i < sizeof(user_data) / sizeof(uint32_t); i++)
		((uint32_t *)user_data)[i] = ((uint32_t *)attestation_report->user_data)[i] ^
					     attestation_report->anonce;

	// clang-format off
	if (memcmp(hash, user_data,
		   hash_len <= CSV_ATTESTATION_USER_DATA_SIZE ? hash_len :
								CSV_ATTESTATION_USER_DATA_SIZE)) {
		RTLS_ERR("unmatched hash value in evidence\n");
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}
	// clang-format on

	assert(sizeof(csv_evidence) <= sizeof(evidence->csv.report));
	err = verify_cert_chain(c_evidence);
	if (err != ENCLAVE_VERIFIER_ERR_NONE) {
		RTLS_ERR("failed to verify csv cert chain\n");
		return err;
	}

	err = verify_attestation_report(attestation_report);
	if (err != ENCLAVE_VERIFIER_ERR_NONE)
		RTLS_ERR("failed to verify csv attestation report\n");

	return err;
}
