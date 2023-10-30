
/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */
extern "C" {
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "rats-tls/api.h"
#include "rats-tls/log.h"
#include "rats-tls/claim.h"
#include "internal/core.h"
#include <sgx_urts.h>
#include <sgx_quote.h>
#include "sgx_stub_u.h"
}

#include <fuzzer/FuzzedDataProvider.h>
#include <vector>

#define CUSTOM_CLAIMS_SIZE 10
#define FUZZ_IP		   "127.0.0.1"
#define FUZZ_PORT	   1234

rats_tls_log_level_t global_log_level = RATS_TLS_LOG_LEVEL_DEFAULT;

#define ENCLAVE_FILENAME "sgx_stub_enclave.signed.so"

static sgx_enclave_id_t load_enclave(bool debug_enclave)
{
	sgx_launch_token_t t;

	memset(t, 0, sizeof(t));

	sgx_enclave_id_t eid;
	int updated = 0;
	int ret = sgx_create_enclave(ENCLAVE_FILENAME, debug_enclave, &t, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		RTLS_ERR("Failed to load enclave %d\n", ret);
		return 0;
	}

	RTLS_INFO("Success to load enclave with enclave id %ld\n", eid);

	return eid;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < sizeof(rats_tls_conf_t)) {
		return 0;
	}

	FuzzedDataProvider fuzzed_data(data, size);
	sgx_enclave_id_t enclave_id = load_enclave(fuzzed_data.ConsumeBool());
	if (enclave_id == 0) {
		RTLS_ERR("Failed to load sgx stub enclave\n");
		return -1;
	}

	char *fuzz_conf_bytes = NULL;

	uint32_t s_ip = inet_addr(FUZZ_IP);
	uint16_t s_port = htons((uint16_t)FUZZ_PORT);

	char *attester_type = (char *)malloc(20);
	if (attester_type == NULL) {
		return 0;
	}
	char *verifier_type = (char *)malloc(20);
	if (verifier_type == NULL) {
		return 0;
	}
	char *tls_type = (char *)malloc(20);
	if (tls_type == NULL) {
		return 0;
	}
	char *crypto_type = (char *)malloc(20);
	if (crypto_type == NULL) {
		return 0;
	}


	for (int i = 0; i < 9; i++) {
		for (int j = 0; j < 10; j++) {
			for (int k = 0; k < 4; k++) {
				for (int l = 0; l < 4; l++) {
					//TODO: other sgx type would support later
					strcpy(attester_type, "sgx_la");
					strcpy(verifier_type, "sgx_la");
					strcpy(tls_type, "openssl");
					strcpy(crypto_type, "openssl");

					unsigned long flags = fuzzed_data.ConsumeIntegral<long>();
					flags |= RATS_TLS_CONF_FLAGS_MUTUAL;
					int ret = 0;
					rats_tls_log_level_t log_level = RATS_TLS_LOG_LEVEL_INFO;

					int sgx_status = ecall_client_startup(
						(sgx_enclave_id_t)enclave_id, &ret, log_level,
						fuzz_conf_bytes, attester_type, verifier_type,
						tls_type, crypto_type, flags, s_ip, s_port);
					if (sgx_status != SGX_SUCCESS || ret) {
						RTLS_ERR(
							"failed to startup client: sgx status %#x return %#x\n",
							sgx_status, ret);
					}
				}
			}
		}
	}
	/*clean up*/
	free(fuzz_conf_bytes);
	free(attester_type);
	free(verifier_type);
	free(tls_type);
	free(crypto_type);

	return 0;
}
