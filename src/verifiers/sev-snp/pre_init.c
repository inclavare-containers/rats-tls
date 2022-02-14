/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/verifier.h>

#define TOOL_NUM  3
#define TOOL_NAME 10

enclave_verifier_err_t sev_snp_verifier_pre_init(void)
{
	RTLS_DEBUG("called\n");

	enclave_verifier_err_t err = ENCLAVE_VERIFIER_ERR_NONE;

	/* These tools are used to verify SEV-SNP report */
	char tools_name[TOOL_NUM][TOOL_NAME] = { "openssl", "wget", "csplit" };
	char cmdline_str[50] = {
		0,
	};

	for (int i = 0; i < TOOL_NUM; i++) {
		int count = snprintf(cmdline_str, sizeof(cmdline_str),
				     "which %s 1> /dev/null 2> /dev/null", tools_name[i]);
		cmdline_str[count] = '\0';

		if (system(cmdline_str) != 0) {
			RTLS_ERR("please install tool %s\n", tools_name[i]);
			err = -ENCLAVE_VERIFIER_ERR_NO_TOOL;
		}
	}

	return err;
}
