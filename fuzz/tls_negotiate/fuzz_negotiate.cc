/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

extern "C"{
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
#include "internal/core.h"
#include "internal/crypto_wrapper.h"
#include "internal/attester.h"
#include "internal/verifier.h"
#include "internal/tls_wrapper.h"
}
#include <fuzzer/FuzzedDataProvider.h>

#define FUZZ_IP "127.0.0.1"
#define FUZZ_PORT 1234
#define CUSTOM_CLAIMS_SIZE 10

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size){
    
    if(size < sizeof(rats_tls_conf_t) + 10 * sizeof(claim_t) + 50 * 10){
        return 0;
    }
    rats_tls_conf_t conf;
    memcpy(&conf, data, sizeof(conf));
	conf.log_level = RATS_TLS_LOG_LEVEL_DEFAULT;
    conf.api_version = 0;

    strcpy(conf.attester_type, "nullattester");
    strcpy(conf.verifier_type, "nullverifier");
    strcpy(conf.tls_type, "nulltls");
    strcpy(conf.crypto_type, "nullcrypto");

	conf.cert_algo = RATS_TLS_CERT_ALGO_DEFAULT;
    conf.flags = RATS_TLS_CONF_FLAGS_MUTUAL;

    //claim_t custom_claims[2] = {
		//{ .name = "key_0", .value = (uint8_t *)"value_0", .value_size = sizeof("value_0") },
		//{ .name = "key_1", .value = (uint8_t *)"value_1", .value_size = sizeof("value_1") },
	//};
	//conf.custom_claims = (claim_t *)custom_claims;
	//conf.custom_claims_length = 2;

    FuzzedDataProvider fuzzed_data(data + sizeof(conf), size - sizeof(conf));
    claim_t custom_claims[CUSTOM_CLAIMS_SIZE];
    std::vector<std::string> str_lists;
    for(int i=0;i<CUSTOM_CLAIMS_SIZE;i++){
        std::vector<char> vec_str = fuzzed_data.ConsumeBytesWithTerminator(50,'\0');
        std::string str(vec_str.begin(),vec_str.end());
        str_lists.push_back(str);
        custom_claims[i].value = (uint8_t *)str_lists[i].c_str();
        custom_claims[i].value_size = (strlen(str_lists[i].c_str()) + 1) *sizeof(char);
     
        if(fuzzed_data.remaining_bytes() <= 0 ){
            return 0;
        }
        custom_claims[i].name = "key";

    }
    conf.custom_claims = (claim_t *)custom_claims;
    conf.custom_claims_length = CUSTOM_CLAIMS_SIZE; 

	/* Create a socket that uses an internet IPv4 address,
	 * Sets the socket to be stream based (TCP),
	 * 0 means choose the default protocol.
	 */
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		return 0;
	}

	struct sockaddr_in s_addr;
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(FUZZ_PORT);

	/* Get the server IPv4 address from the command line call */
	if (inet_pton(AF_INET, FUZZ_IP, &s_addr.sin_addr) != 1) {
		return 0;
	}

	/* Connect to the server */
	if (connect(sockfd, (struct sockaddr *)&s_addr, sizeof(s_addr)) == -1) {
		return 0;
	}

	rats_tls_handle handle;
	rats_tls_err_t ret = rats_tls_init(&conf, &handle);
	if (ret != RATS_TLS_ERR_NONE) {
		return 0;
	}

    rats_tls_negotiate(handle,sockfd);


    return 0;

}