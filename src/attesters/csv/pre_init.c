/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/attester.h>
#include <rats-tls/log.h>

enclave_attester_err_t csv_attester_pre_init(void)
{
	RTLS_DEBUG("called\n");

	if (!system("wget -V >/dev/null 2>&1"))
		return ENCLAVE_ATTESTER_ERR_NONE;

	RTLS_ERR("Please install wget for csv attester\n");

	return -ENCLAVE_ATTESTER_ERR_NO_TOOL;
}
