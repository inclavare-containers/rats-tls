/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/attester.h>

enclave_attester_err_t nullattester_collect_endorsements(enclave_attester_ctx_t *ctx,
							 attestation_evidence_t *evidence,
							 attestation_endorsement_t *endorsements)
{
	RTLS_DEBUG("ctx %p, evidence %p, endorsements %p\n", ctx, evidence, endorsements);

	return ENCLAVE_ATTESTER_ERR_NONE;
}
