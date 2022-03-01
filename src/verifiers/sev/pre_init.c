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

	enclave_verifier_err_t err = ENCLAVE_VERIFIER_ERR_NONE;

	char *cmdline_str = "which wget 1> /dev/null 2> /dev/null";
	if (system(cmdline_str) != 0) {
		RTLS_ERR("please install wget for sev(-es) verify\n");
		err = -ENCLAVE_VERIFIER_ERR_NO_TOOL;
	}

	return err;
}
