/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <rats-tls/log.h>
#include <rats-tls/verifier.h>
#include "../../attesters/sev-snp/sev_snp.h"
#include "sevapi.h"
#include "x509cert.h"
#include "crypto.h"
#include "utils.h"

char *vcek_pem_path = SEV_SNP_DEFAULT_DIR VCEK_PEM_FILENAME;
char *ark_pem_path = SEV_SNP_DEFAULT_DIR VCEK_ARK_PEM_FILENAME;
char *ask_pem_path = SEV_SNP_DEFAULT_DIR VCEK_ASK_PEM_FILENAME;

int generate_vcek_pem(const uint8_t *chip_id, size_t chip_id_size, const snp_tcb_version_t *tcb)
{
	int cmd_ret = -1;
	struct stat st;

	if (stat(SEV_SNP_DEFAULT_DIR, &st) == -1) {
		if (mkdir(SEV_SNP_DEFAULT_DIR, S_IRWXU) == -1) {
			RTLS_ERR("failed to mkdir %s\n", SEV_SNP_DEFAULT_DIR);
			return cmd_ret;
		}
	}

	int count = 0;
	char cmdline_str[300] = {
		0,
	};
	char *vcek_der_path = SEV_SNP_DEFAULT_DIR VCEK_DER_FILENAME;

	/* 2 chars per byte +1 for null term */
	char id_buf[chip_id_size * 2 + 1];
	memset(id_buf, 0, sizeof(id_buf));
	for (uint8_t i = 0; i < chip_id_size; i++) {
		sprintf(id_buf + 2 * i * sizeof(uint8_t), "%02x", chip_id[i]);
	}
	count = snprintf(cmdline_str, sizeof(cmdline_str), "wget -O %s \"%sMilan/%s", vcek_der_path,
			 KDS_VCEK, id_buf);

	char *TCBStringArray[8];
	TCBStringArray[0] = "blSPL=";
	TCBStringArray[1] = "teeSPL=";
	TCBStringArray[2] = "reserved0SPL=";
	TCBStringArray[3] = "reserved1SPL=";
	TCBStringArray[4] = "reserved2SPL=";
	TCBStringArray[5] = "reserved3SPL=";
	TCBStringArray[6] = "snpSPL=";
	TCBStringArray[7] = "ucodeSPL=";

	/* Generate VCEK cert correspond to @chip_id and @tcb */
	count += snprintf((char *)&cmdline_str[count], sizeof(cmdline_str) - count,
			  "?%s%02u&%s%02u&%s%02u&%s%02u\"", TCBStringArray[0],
			  (unsigned)tcb->f.boot_loader, TCBStringArray[1], (unsigned)tcb->f.tee,
			  TCBStringArray[6], (unsigned)tcb->f.snp, TCBStringArray[7],
			  (unsigned)tcb->f.microcode);
	cmdline_str[count] = '\0';

	/* Don't re-download the VCEK from the KDS server if you already have it */
	if (get_file_size(vcek_der_path) == 0) {
		if (system(cmdline_str) != 0) {
			RTLS_ERR("failed to download %s\n", vcek_der_path);
			return cmd_ret;
		}
	}

	cmd_ret = convert_der_to_pem(vcek_der_path, vcek_pem_path);
	if (cmd_ret == -1)
		RTLS_ERR("failed to convert %s to %s\n", vcek_der_path, vcek_pem_path);

	return cmd_ret;
}

int generate_ark_ask_pem(void)
{
	int cmd_ret = -1;
	int count = 0;
	char cmdline_str[200] = {
		0,
	};
	char *cert_chain_pem_path = SEV_SNP_DEFAULT_DIR VCEK_CERT_CHAIN_PEM_FILENAME;

	count = snprintf(cmdline_str, sizeof(cmdline_str), "wget --no-proxy -O %s %sMilan/%s",
			 cert_chain_pem_path, KDS_VCEK, KDS_VCEK_CERT_CHAIN);
	cmdline_str[count] = '\0';

	/* Don't re-download the cert chain from the KDS server if you already have it */
	if (get_file_size(cert_chain_pem_path) == 0) {
		if (system(cmdline_str) != 0) {
			RTLS_ERR("failed to download %s\n", cert_chain_pem_path);
			return cmd_ret;
		}
	}

	/* Split cert_chain.pem to two pem files */
	count = snprintf(
		cmdline_str, sizeof(cmdline_str),
		"csplit -z -f cert_chain- %s '/-----BEGIN CERTIFICATE-----/' '{*}' 1> /dev/null 2> /dev/null",
		cert_chain_pem_path);
	cmdline_str[count] = '\0';

	if (system(cmdline_str) != 0) {
		RTLS_ERR("failed to split cert_chain.pem\n");
		return cmd_ret;
	}

	/* Rename the file from "cert_chain-00" to ask.pem */
	cmd_ret = rename("cert_chain-00", ask_pem_path);
	if (cmd_ret != 0) {
		RTLS_ERR("Error: renaming vcek cert chain file\n");
		return cmd_ret;
	}

	/* Rename the file from "cert_chain-01" to ark.pem */
	cmd_ret = rename("cert_chain-01", ark_pem_path);
	if (cmd_ret != 0) {
		RTLS_ERR("Error: renaming vcek cert chain file\n");
		return cmd_ret;
	}

	return cmd_ret;
}

enclave_verifier_err_t validate_cert_chain_vcek(snp_attestation_report_t *report, uint8_t *hash,
						uint32_t hash_len)
{
	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;

	/* Verify the hash value */
	if (memcmp(hash, report->report_data, hash_len) != 0) {
		RTLS_ERR("unmatched hash value in evidence.\n");
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}

	X509 *x509_ark = NULL;
	X509 *x509_ask = NULL;
	X509 *x509_vcek = NULL;
	EVP_PKEY *vcek_pub_key = NULL;
	bool ret = false;

	if (!read_pem_into_x509(ark_pem_path, &x509_ark))
		goto err;
	if (!read_pem_into_x509(ask_pem_path, &x509_ask))
		goto err;
	if (!read_pem_into_x509(vcek_pem_path, &x509_vcek))
		goto err;

	/* Extract the VCEK public key */
	vcek_pub_key = X509_get_pubkey(x509_vcek);
	if (!vcek_pub_key)
		goto err;

	/* Verify the ARK self-signed the ARK */
	ret = x509_validate_signature(x509_ark, NULL, x509_ark);
	if (!ret) {
		RTLS_ERR("failed to validate signature of x509_ark cert\n");
		err = -ENCLAVE_VERIFIER_ERR_INVALID;
		goto err;
	}

	/* Verify the ASK signed by ARK */
	ret = x509_validate_signature(x509_ask, NULL, x509_ark);
	if (!ret) {
		RTLS_ERR("failed to validate signature of x509_ask cert\n");
		err = -ENCLAVE_VERIFIER_ERR_INVALID;
		goto err;
	}

	/* Verify the VCEK signed by ASK */
	ret = x509_validate_signature(x509_vcek, x509_ask, x509_ark);
	if (!ret) {
		RTLS_ERR("failed to validate signature of x509_vcek cert\n");
		err = -ENCLAVE_VERIFIER_ERR_INVALID;
		goto err;
	}

	/* Verify the attestation report signed by VCEK */
	ret = verify_message((sev_sig *)&report->signature, &vcek_pub_key, (const uint8_t *)report,
			     offsetof(snp_attestation_report_t, signature),
			     SEV_SIG_ALGO_ECDSA_SHA384);
	if (!ret) {
		RTLS_ERR("failed to verify snp guest report\n");
		err = -ENCLAVE_VERIFIER_ERR_INVALID;
		goto err;
	}

	err = ENCLAVE_VERIFIER_ERR_NONE;

	RTLS_INFO("SEV-SNP attestation report validated successfully!\n");

err:
	X509_free(x509_ark);
	X509_free(x509_ask);
	X509_free(x509_vcek);
	EVP_PKEY_free(vcek_pub_key);

	return err;
}

enclave_verifier_err_t sev_snp_verify_evidence(enclave_verifier_ctx_t *ctx,
					       attestation_evidence_t *evidence, uint8_t *hash,
					       uint32_t hash_len,
					       __attribute__((unused))
					       attestation_endorsement_t *endorsements)
{
	RTLS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;
	snp_attestation_report_t *snp_report = (snp_attestation_report_t *)(evidence->snp.report);

	/* Generate ARK, ASK and VCEK pem files */
	int ret = generate_vcek_pem(snp_report->chip_id, sizeof(snp_report->chip_id),
				    &snp_report->platform_version);
	if (ret == -1) {
		RTLS_ERR("failed to generate vcek pem\n");
		return err;
	}

	ret = generate_ark_ask_pem();
	if (ret == -1) {
		RTLS_ERR("failed to generate ark ask pem\n");
		return err;
	}

	err = validate_cert_chain_vcek(snp_report, hash, hash_len);
	if (err != ENCLAVE_VERIFIER_ERR_NONE)
		RTLS_ERR("failed to verify snp attestation report\n");

	return err;
}
