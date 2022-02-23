/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <rats-tls/attester.h>
#include <rats-tls/log.h>

extern enclave_attester_err_t enclave_attester_register(enclave_attester_opts_t *opts);
extern enclave_attester_err_t sev_snp_attester_pre_init(void);
extern enclave_attester_err_t sev_snp_attester_init(enclave_attester_ctx_t *ctx,
						    rats_tls_cert_algo_t algo);
extern enclave_attester_err_t sev_snp_collect_evidence(enclave_attester_ctx_t *ctx,
						       attestation_evidence_t *evidence,
						       rats_tls_cert_algo_t algo, uint8_t *hash,
						       uint32_t hash_len);
extern enclave_attester_err_t sev_snp_attester_cleanup(enclave_attester_ctx_t *ctx);

static enclave_attester_opts_t sev_snp_attester_opts = {
	.api_version = ENCLAVE_ATTESTER_API_VERSION_DEFAULT,
	.flags = ENCLAVE_ATTESTER_OPTS_FLAGS_SNP_GUEST,
	.name = "sev_snp",
	.priority = 42,
	.pre_init = sev_snp_attester_pre_init,
	.init = sev_snp_attester_init,
	.collect_evidence = sev_snp_collect_evidence,
	.cleanup = sev_snp_attester_cleanup,
};

void __attribute__((constructor)) libattester_sev_snp_init(void)
{
	RTLS_DEBUG("called\n");

	enclave_attester_err_t err = enclave_attester_register(&sev_snp_attester_opts);
	if (err != ENCLAVE_ATTESTER_ERR_NONE)
		RTLS_DEBUG("failed to register the enclave attester 'sev_snp' %#x\n", err);
}
