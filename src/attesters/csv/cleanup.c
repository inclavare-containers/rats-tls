/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/attester.h>
#include <rats-tls/log.h>

enclave_attester_err_t csv_attester_cleanup(enclave_attester_ctx_t *ctx)
{
	RTLS_DEBUG("called\n");

	return ENCLAVE_ATTESTER_ERR_NONE;
}
