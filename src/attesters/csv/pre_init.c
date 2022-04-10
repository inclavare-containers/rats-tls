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

	enclave_attester_err_t err = ENCLAVE_ATTESTER_ERR_NONE;

	char *cmdline_str = "which wget 1> /dev/null 2> /dev/null";
	if (system(cmdline_str) != 0) {
		RTLS_ERR("please install wget for csv attest\n");
		err = -ENCLAVE_ATTESTER_ERR_NO_TOOL;
	}

	return err;
}
