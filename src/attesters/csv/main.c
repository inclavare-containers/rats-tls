/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <rats-tls/attester.h>
#include <rats-tls/log.h>

extern enclave_attester_err_t enclave_attester_register(enclave_attester_opts_t *opts);
extern enclave_attester_err_t csv_attester_pre_init(void);
extern enclave_attester_err_t csv_attester_init(enclave_attester_ctx_t *ctx,
						rats_tls_cert_algo_t algo);
extern enclave_attester_err_t csv_collect_evidence(enclave_attester_ctx_t *ctx,
						   attestation_evidence_t *evidence,
						   rats_tls_cert_algo_t algo, uint8_t *hash,
						   uint32_t hash_len);
extern enclave_attester_err_t csv_attester_cleanup(enclave_attester_ctx_t *ctx);

static enclave_attester_opts_t csv_attester_opts = {
	.api_version = ENCLAVE_ATTESTER_API_VERSION_DEFAULT,
	.flags = ENCLAVE_ATTESTER_OPTS_FLAGS_CSV_GUEST,
	.name = "csv",
	.priority = 20,
	.pre_init = csv_attester_pre_init,
	.init = csv_attester_init,
	.collect_evidence = csv_collect_evidence,
	.cleanup = csv_attester_cleanup,
};

void __attribute__((constructor)) libattester_csv_init(void)
{
	RTLS_DEBUG("called\n");

	enclave_attester_err_t err = enclave_attester_register(&csv_attester_opts);
	if (err != ENCLAVE_ATTESTER_ERR_NONE)
		RTLS_DEBUG("failed to register the enclave register 'csv' %#x\n", err);
}
