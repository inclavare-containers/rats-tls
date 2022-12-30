/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rats-tls/log.h>
#include <rats-tls/verifier.h>
#include "sev_utils.h"
#include "amdcert.h"
#include "sevcert.h"
#include "../../attesters/sev/sev.h"

int generate_ark_ask_cert(amd_cert *ask_cert, amd_cert *ark_cert, enum ePSP_DEVICE_TYPE device_type)
{
	char *ark_ask_cert_patch;
	char *default_dir = NULL;
	char *url = NULL;

	switch (device_type) {
	case PSP_DEVICE_TYPE_NAPLES:
		default_dir = SEV_NAPLES_DEFAULT_DIR;
		ark_ask_cert_patch = SEV_NAPLES_DEFAULT_DIR ASK_ARK_FILENAME;
		url = ASK_ARK_NAPLES_SITE;
		break;
	case PSP_DEVICE_TYPE_ROME:
		default_dir = SEV_ROME_DEFAULT_DIR;
		ark_ask_cert_patch = SEV_ROME_DEFAULT_DIR ASK_ARK_FILENAME;
		url = ASK_ARK_ROME_SITE;
		break;
	case PSP_DEVICE_TYPE_MILAN:
		default_dir = SEV_MILAN_DEFAULT_DIR;
		ark_ask_cert_patch = SEV_MILAN_DEFAULT_DIR ASK_ARK_FILENAME;
		url = ASK_ARK_MILAN_SITE;
		break;
	default:
		RTLS_ERR("unsupported device type %d\n", device_type);
		return -1;
	}

	char cmdline_str[200] = {
		0,
	};
	int count = 0;
	struct stat st;

	if (stat(default_dir, &st) == -1) {
		count = snprintf(cmdline_str, sizeof(cmdline_str), "mkdir -p %s", default_dir);
		cmdline_str[count] = '\0';
		if (system(cmdline_str) != 0)
			RTLS_ERR("failed to mkdir %s\n", default_dir);
		return -1;
	}

	count = snprintf(cmdline_str, sizeof(cmdline_str), "wget --no-proxy -O %s %s",
			 ark_ask_cert_patch, url);
	cmdline_str[count] = '\0';

	/* Don't re-download the ASK/ARK from the KDS server if you already have it */
	if (get_file_size(ark_ask_cert_patch) == 0) {
		if (system(cmdline_str) != 0) {
			RTLS_ERR("failed to download %s\n", ark_ask_cert_patch);
			return -1;
		}
	}

	/* Read in the ask_ark so we can split it into 2 separate cert files */
	uint8_t ask_ark_buf[sizeof(amd_cert) * 2] = { 0 };
	if (read_file(ark_ask_cert_patch, ask_ark_buf, sizeof(ask_ark_buf)) !=
	    sizeof(ask_ark_buf)) {
		RTLS_ERR("read %s fail\n", ark_ask_cert_patch);
		return -1;
	}

	/* Initialize the ASK */
	if (amd_cert_init(ask_cert, ask_ark_buf) != 0) {
		RTLS_ERR("failed to initialize ASK certificate\n");
		return -1;
	}

	/* Initialize the ARK */
	size_t ask_size = amd_cert_get_size(ask_cert);
	if (amd_cert_init(ark_cert, (uint8_t *)(ask_ark_buf + ask_size)) != 0) {
		RTLS_ERR("failed to initialize ASK certificate\n");
		return -1;
	}

	/* Check the usage of the ASK and ARK */
	if (ask_cert->key_usage != AMD_USAGE_ASK || ark_cert->key_usage != AMD_USAGE_ARK) {
		RTLS_ERR("certificate Usage %d did not match expected value %d\n",
			 ask_cert->key_usage, AMD_USAGE_ASK);
		return -1;
	}

	return 0;
}

enclave_verifier_err_t validate_cert_chain(sev_evidence_t *sev_evidence, amd_cert *ark_cert,
					   amd_cert *ask_cert)
{
	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_INVALID;
	sev_cert *cek = &sev_evidence->cek_cert;
	sev_cert *pek = &sev_evidence->pek_cert;
	sev_cert *oca = &sev_evidence->oca_cert;
	sev_attestation_report *report = &sev_evidence->attestation_report;
	enum ePSP_DEVICE_TYPE device_type = sev_evidence->device_type;

	/* Verify ARK cert with ARK */
	if (!amd_cert_validate_ark(ark_cert, device_type)) {
		RTLS_ERR("failed to verify ARK cert\n");
		return err;
	}
	RTLS_INFO("verify ARK cert successfully\n");

	/* Verify ASK cert with ARK */
	if (!amd_cert_validate_ask(ask_cert, ark_cert, device_type)) {
		RTLS_ERR("failed to verify ASK cert\n");
		return err;
	}
	RTLS_INFO("verify ASK cert successfully\n");

	/* Verify CEK cert with ASK */
	sev_cert ask_pubkey;
	if (amd_cert_export_pub_key(ask_cert, &ask_pubkey) != 0) {
		RTLS_ERR("failed to export pub key from ask\n");
		return err;
	}

	if (!verify_sev_cert(cek, &ask_pubkey, NULL)) {
		RTLS_ERR("failed to verify CEK cert\n");
		return err;
	}
	RTLS_INFO("verify CEK cert successfully\n");

	/* Verify PEK cert with CEK and OCA */
	if (!verify_sev_cert(pek, oca, cek)) {
		RTLS_ERR("failed to verify PEK cert\n");
		return err;
	}
	RTLS_INFO("verify PEK cert successfully\n");

	/* Verify attestation report with PEK */
	if (!validate_attestation(pek, report)) {
		RTLS_ERR("failed to verify sev attestation report\n");
		return err;
	}

	RTLS_INFO("SEV(-ES) attestation report validated successfully!\n");

	return ENCLAVE_VERIFIER_ERR_NONE;
}

enclave_verifier_err_t sev_verify_evidence(enclave_verifier_ctx_t *ctx,
					   attestation_evidence_t *evidence, uint8_t *hash,
					   uint32_t hash_len,
					   __attribute__((unused))
					   attestation_endorsement_t *endorsements)
{
	RTLS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;
	sev_evidence_t *sev_evidence = (sev_evidence_t *)(evidence->sev.report);

	/* SEV(-ES) do NOT support self-defined user_data, therefore we skip the
	 * hash verify.
	 */

	/*  Generate ask and ark cert */
	amd_cert ask_cert;
	amd_cert ark_cert;
	enum ePSP_DEVICE_TYPE device_type = sev_evidence->device_type;
	if (generate_ark_ask_cert(&ask_cert, &ark_cert, device_type) == -1) {
		RTLS_ERR("failed to load ASK cert\n");
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}

	err = validate_cert_chain(sev_evidence, &ark_cert, &ask_cert);
	if (err != ENCLAVE_VERIFIER_ERR_NONE)
		RTLS_ERR("failed to verify snp attestation report\n");

	return err;
}
