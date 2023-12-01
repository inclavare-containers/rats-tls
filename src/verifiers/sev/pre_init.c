/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/verifier.h>

enclave_verifier_err_t sev_verifier_pre_init(void)
{
	RTLS_DEBUG("called\n");

	if (!system("wget -V >/dev/null 2>&1"))
		return ENCLAVE_VERIFIER_ERR_NONE;

	RTLS_ERR("Please install wget for sev verifier\n");

	return -ENCLAVE_VERIFIER_ERR_NO_TOOL;
}
