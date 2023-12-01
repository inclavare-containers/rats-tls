/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/verifier.h>

#define TOOL_NUM 3
#define TOOL_BUF 16

enclave_verifier_err_t sev_snp_verifier_pre_init(void)
{
	RTLS_DEBUG("called\n");

	/* These tools are used to verify SEV-SNP report */
	const char names[TOOL_NUM][TOOL_BUF] = { "openssl", "wget", "csplit" };
	const char parameters[TOOL_NUM][TOOL_BUF] = { "version", "-V", "--version" };

	for (unsigned int i = 0; i < TOOL_NUM; ++i) {
		char cmdline_str[64];

		snprintf(cmdline_str, sizeof(cmdline_str), "%s %s >/dev/null 2>&1", names[i],
			 parameters[i]);

		if (system(cmdline_str)) {
			RTLS_ERR("Please install %s for sev_snp verifier\n", names[i]);
			return -ENCLAVE_VERIFIER_ERR_NO_TOOL;
		}
	}

	return ENCLAVE_VERIFIER_ERR_NONE;
}
