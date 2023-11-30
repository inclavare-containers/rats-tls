/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2023 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _OPENSSL_HOOK_COMMON_H_
#define _OPENSSL_HOOK_COMMON_H_

#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <rats-tls/api.h>

extern rats_tls_handle global_rtls_handle;
extern int init_openssl_ctx();

inline static int dlsym_load(void **variable, const char *name_str)
{
	dlerror(); /* clear old errors */
	void *f = dlsym(RTLD_NEXT, name_str);
	char *e = dlerror();
	if (e != NULL) {
		fprintf(stderr, "Failed to find symbol with dlsym %s: %s\n", name_str, e);
		return 0;
	}
	if (f == NULL) {
		fprintf(stderr, "Symbol not resolved by dlsym %s\n", name_str);
		return 0;
	}
	*variable = f;
	return 1;
}

#endif
