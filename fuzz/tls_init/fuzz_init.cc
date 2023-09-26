/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */
extern "C" {
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "rats-tls/api.h"
#include "rats-tls/log.h"
#include "rats-tls/claim.h"
#include "internal/core.h"
}
#include <fuzzer/FuzzedDataProvider.h>
#include <vector>

#define CUSTOM_CLAIMS_SIZE 10

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	rats_tls_conf_t conf; // consume 192 bytes
	if (size < sizeof(rats_tls_conf_t) + 10 * sizeof(claim_t) + 50 * 10 + 100) {
		return 0;
	}
	FuzzedDataProvider fuzzed_data(data + sizeof(conf), size - sizeof(conf));

	char attester_types[10][25] = { "nullattester", "",	   "sgx_la",	"csv",
					"sev",		"sev_snp", "tdx_ecdsa", "sgx_ecdsa" };
	strcpy(attester_types[8], fuzzed_data.ConsumeBytesWithTerminator(20, '\0').data());
	if (fuzzed_data.remaining_bytes() < 0) {
		return 0;
	}
	for (int i = 0; i < 9; i++) {
		char verifier_types[10][25] = { "nullverifier", "",	     "sgx_la",
						"csv",		"sev",	     "sev_snp",
						"tdx_ecdsa",	"tdx_ecdsa", "sgx_ecdsa_qve" };
		strcpy(verifier_types[9], fuzzed_data.ConsumeBytesWithTerminator(20, '\0').data());
		if (fuzzed_data.remaining_bytes() < 0) {
			return 0;
		}
		for (int j = 0; j < 10; j++) {
			char tls_types[4][25] = { "nulltls", "", "openssl" };
			strcpy(tls_types[3],
			       fuzzed_data.ConsumeBytesWithTerminator(20, '\0').data());
			if (fuzzed_data.remaining_bytes() < 0) {
				return 0;
			}
			for (int k = 0; k < 4; k++) {
				char crypto_types[4][25] = { "nullcrypto", "", "openssl" };
				strcpy(crypto_types[3],
				       fuzzed_data.ConsumeBytesWithTerminator(20, '\0').data());
				if (fuzzed_data.remaining_bytes() < 0) {
					return 0;
				}
				for (int l = 0; l < 4; l++) {
					memcpy(&conf,
					       fuzzed_data.ConsumeBytes<uint8_t>(sizeof(conf))
						       .data(),
					       sizeof(conf));
					conf.log_level = RATS_TLS_LOG_LEVEL_DEFAULT;
					conf.api_version = 0;

					strcpy(conf.attester_type, attester_types[i]);
					strcpy(conf.verifier_type, verifier_types[j]);
					strcpy(conf.tls_type, tls_types[k]);
					strcpy(conf.crypto_type, crypto_types[l]);

					conf.cert_algo = RATS_TLS_CERT_ALGO_DEFAULT;
					conf.flags = fuzzed_data.ConsumeIntegral<long>();

					claim_t custom_claims[CUSTOM_CLAIMS_SIZE];
					std::vector<std::string> str_lists;
					for (int c = 0; c < CUSTOM_CLAIMS_SIZE; c++) {
						std::vector<char> vec_str =
							fuzzed_data.ConsumeBytesWithTerminator(
								50, '\0');
						std::string str(vec_str.begin(), vec_str.end());
						str_lists.push_back(str);
						custom_claims[c].value =
							(uint8_t *)str_lists[c].c_str();
						custom_claims[c].value_size =
							(strlen(str_lists[c].c_str()) + 1) *
							sizeof(char);
						if (fuzzed_data.remaining_bytes() <= 0) {
							for (int p = 0; p < c; p++) {
								free(custom_claims[p].name);
							}
							return 0;
						}
						custom_claims[c].name = (char *)malloc(15);
						strcpy(custom_claims[c].name,
						       fuzzed_data.ConsumeBytesAsString(10).c_str());
					}
					conf.custom_claims = (claim_t *)custom_claims;
					conf.custom_claims_length = CUSTOM_CLAIMS_SIZE;
					rats_tls_handle handle;
					rats_tls_err_t err = rats_tls_init(&conf, &handle);

					for (int c = 0; c < CUSTOM_CLAIMS_SIZE; c++) {
						free(custom_claims[c].name);
					}
					err = rats_tls_cleanup(handle);
					if (err != RATS_TLS_ERR_NONE)
						RTLS_ERR("Failed to cleanup %#x\n", err);
				}
			}
		}
	}

	return 0;
}