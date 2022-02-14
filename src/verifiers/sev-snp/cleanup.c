/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/verifier.h>

enclave_verifier_err_t sev_snp_verifier_cleanup(enclave_verifier_ctx_t *ctx)
{
	RTLS_DEBUG("called\n");

	return ENCLAVE_VERIFIER_ERR_NONE;
}
