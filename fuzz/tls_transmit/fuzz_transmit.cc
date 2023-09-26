/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.1
 */

extern "C" {
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "rats-tls/api.h"
#include "rats-tls/log.h"
#include "rats-tls/claim.h"
}
#include <fuzzer/FuzzedDataProvider.h>
#define FUZZ_IP		   "127.0.0.1"
#define FUZZ_PORT	   1234
#define CUSTOM_CLAIMS_SIZE 10

int user_callback(void *args)
{
	rtls_evidence_t *ev = (rtls_evidence_t *)args;

	printf("verify_callback called, claims %p, claims_size %zu, args %p\n", ev->custom_claims,
	       ev->custom_claims_length, args);
	for (size_t i = 0; i < ev->custom_claims_length; ++i) {
		printf("custom_claims[%zu] -> name: '%s' value_size: %zu value: '%.*s'\n", i,
		       ev->custom_claims[i].name, ev->custom_claims[i].value_size,
		       (int)ev->custom_claims[i].value_size, ev->custom_claims[i].value);
	}
	return 1;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < sizeof(rats_tls_conf_t) + 10 * sizeof(claim_t) + 50 * 10 + 100) {
		return 0;
	}
	FuzzedDataProvider fuzzed_data(data + sizeof(rats_tls_conf_t),
				       size - sizeof(rats_tls_conf_t));

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
					rats_tls_conf_t conf;
					memcpy(&conf,
					       fuzzed_data.ConsumeBytes<uint8_t>(sizeof(conf))
						       .data(),
					       sizeof(conf));
					if (fuzzed_data.remaining_bytes() < 0) {
						return 0;
					}
					conf.log_level = RATS_TLS_LOG_LEVEL_INFO;
					conf.cert_algo = RATS_TLS_CERT_ALGO_DEFAULT;
					conf.api_version = 0;
					conf.flags = fuzzed_data.ConsumeIntegral<long>();

					strcpy(conf.attester_type, "nullattester");
					strcpy(conf.verifier_type, "nullverifier");
					strcpy(conf.tls_type, "nulltls");
					strcpy(conf.crypto_type, "nullcrypto");

					int sockfd = socket(AF_INET, SOCK_STREAM, 0);
					if (sockfd < 0) {
						RTLS_ERR("Socked create failed \n");
						close(sockfd);
						continue;
					}

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

					struct sockaddr_in s_addr;
					memset(&s_addr, 0, sizeof(s_addr));
					s_addr.sin_family = AF_INET;
					s_addr.sin_port = htons(FUZZ_PORT);

					if (inet_pton(AF_INET, FUZZ_IP, &s_addr.sin_addr) != 1) {
						continue;
					}

					if (connect(sockfd, (struct sockaddr *)&s_addr,
						    sizeof(s_addr)) == -1) {
						close(sockfd);
						for (int c = 0; c < CUSTOM_CLAIMS_SIZE; c++) {
							free(custom_claims[c].name);
						}
						continue;
					}

					rats_tls_handle handle;
					rats_tls_err_t err = rats_tls_init(&conf, &handle);
					if (err != RATS_TLS_ERR_NONE) {
						RTLS_ERR("Fail to init \n");
						rats_tls_cleanup(handle);
						close(sockfd);
						for (int c = 0; c < CUSTOM_CLAIMS_SIZE; c++) {
							free(custom_claims[c].name);
						}

						continue;
					}

					err = rats_tls_set_verification_callback(&handle,
										 user_callback);
					if (err != RATS_TLS_ERR_NONE) {
						rats_tls_cleanup(handle);
						for (int c = 0; c < CUSTOM_CLAIMS_SIZE; c++) {
							free(custom_claims[c].name);
						}
						close(sockfd);
					}

					err = rats_tls_negotiate(handle, sockfd);
					if (err != RATS_TLS_ERR_NONE) {
						rats_tls_cleanup(handle);
						for (int c = 0; c < CUSTOM_CLAIMS_SIZE; c++) {
							free(custom_claims[c].name);
						}
						close(sockfd);
						continue;
					}

					char *msg = (char *)malloc(25);
					strcpy(msg, fuzzed_data.ConsumeBytesAsString(20).c_str());
					if (fuzzed_data.remaining_bytes() < 0) {
						return 0;
					}

					size_t len = strlen(msg);
					err = rats_tls_transmit(handle, (void *)msg, &len);
					if (err != RATS_TLS_ERR_NONE || len != strlen(msg)) {
						RTLS_ERR("Failed to transmit %#x\n", err);
						rats_tls_cleanup(handle);
						for (int c = 0; c < CUSTOM_CLAIMS_SIZE; c++) {
							free(custom_claims[c].name);
						}
						free(msg);
						close(sockfd);
						continue;
					}

					char buf[256];
					len = sizeof(buf);
					err = rats_tls_receive(handle, buf, &len);
					if (err != RATS_TLS_ERR_NONE) {
						rats_tls_cleanup(handle);
						for (int c = 0; c < CUSTOM_CLAIMS_SIZE; c++) {
							free(custom_claims[c].name);
						}
						free(msg);
						close(sockfd);
						continue;
					}
					close(sockfd);
					free(msg);
				}
			}
		}
	}
	return 0;
}