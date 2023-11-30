/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2023 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common.h"

rats_tls_handle global_rtls_handle;

int user_callback(void *args)
{
	rtls_evidence_t *ev = (rtls_evidence_t *)args;

	fprintf(stderr, "verify_callback called, claims %p, claims_size %zu, args %p\n",
		ev->custom_claims, ev->custom_claims_length, args);
	for (size_t i = 0; i < ev->custom_claims_length; ++i) {
		fprintf(stderr, "custom_claims[%zu] -> name: '%s' value_size: %zu value: '%.*s'\n",
			i, ev->custom_claims[i].name, ev->custom_claims[i].value_size,
			(int)ev->custom_claims[i].value_size, ev->custom_claims[i].value);
	}
	return 1;
}

void init_rats_tls()
{
	char *env_ld_preload = getenv("LD_PRELOAD");
	char c = env_ld_preload[0];
	env_ld_preload[0] = '\0';
	// unsetenv("LD_PRELOAD");

	/* We will not link this code with rats_tls.so, since librats_tls.so uses __attribute__((constructor))
	 * for library initialization. When used with LD_PRELOAD, it becomes a fork bomb.
	 * Instead, we unset env LD_PRELOAD first, and then load librats_tls.so with dlopen(). The flag
	 * RTLD_GLOBAL is essential, since it makes symbols from librats_tls.so available for later symbol
	 * resolution of current library.
	 */

	void *rats_tls_lib_handle = dlopen("librats_tls.so", RTLD_LAZY | RTLD_GLOBAL);
	if (!rats_tls_lib_handle) {
		rats_tls_lib_handle =
			dlopen("/usr/local/lib/rats-tls/librats_tls.so", RTLD_LAZY | RTLD_GLOBAL);
	}
	if (!rats_tls_lib_handle) {
		fprintf(stderr, "Failed to load librats_tls.so: %s\n", dlerror());
		return;
	}

	rats_tls_conf_t conf;
	memset(&conf, 0, sizeof(conf));
	conf.log_level = RATS_TLS_LOG_LEVEL_DEBUG; // TODO: command line params or get from ENV
	strcpy(conf.attester_type, "\0");
	strcpy(conf.verifier_type, "tdx_ecdsa");
	strcpy(conf.crypto_type, "openssl");
	strcpy(conf.tls_type, "openssl");
	conf.cert_algo = RATS_TLS_CERT_ALGO_DEFAULT;
	// conf.flags |= RATS_TLS_CONF_FLAGS_MUTUAL;
	conf.flags |= RATS_TLS_CONF_FLAGS_PROVIDE_ENDORSEMENTS;

	rats_tls_err_t ret = rats_tls_init(&conf, &global_rtls_handle);
	if (ret != RATS_TLS_ERR_NONE) {
		fprintf(stderr, "Failed to initialize rats tls %#x\n", ret);
		return;
	}

	ret = rats_tls_set_verification_callback(&global_rtls_handle, user_callback);
	if (ret != RATS_TLS_ERR_NONE) {
		fprintf(stderr, "Failed to set verification callback %#x\n", ret);
		return;
	}

	env_ld_preload[0] = c;
}

__attribute__((constructor)) void init()
{
	printf("openssl-hook init()\n");
	if (init_openssl_ctx()) {
		init_rats_tls();
	}
}

__attribute__((destructor)) void fini()
{
	printf("openssl-hook fini()\n");
}
