/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stddef.h>
#include <rats-tls/log.h>
#include "../sev-snp/utils.c"

int read_file(const char *filename, void *buffer, size_t len)
{
	FILE *fp = NULL;
	size_t count = 0;

	if ((fp = fopen(filename, "r")) == NULL) {
		RTLS_ERR("failed to open %s\n", filename);
		return 0;
	}

	if ((count = fread(buffer, 1, len, fp)) != len) {
		fclose(fp);
		RTLS_ERR("failed to read %s with count %zu\n", filename, count);
		return 0;
	}

	fclose(fp);
	return count;
}
