/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */
extern "C"{
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
using namespace std;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size){
    rats_tls_conf_t conf; // consume 192 bytes
    // conf | claim_array | random char *  in claim_array
    if(size < sizeof(rats_tls_conf_t) + 10 * sizeof(claim_t) + 50 * 10){
        return 0;
    }
    memcpy(&conf, data, sizeof(conf));
    conf.log_level  = RATS_TLS_LOG_LEVEL_DEFAULT;
    conf.api_version = 0;
    
    /*fuzz log level*/
    /*fuzz round could not be too huge, that leads to unexpected log_level*/
    strcpy(conf.attester_type, "nullattester");
    strcpy(conf.verifier_type, "nullverifier");
    strcpy(conf.tls_type, "nulltls");
    strcpy(conf.crypto_type, "nullcrypto");
    
    conf.cert_algo = RATS_TLS_CERT_ALGO_DEFAULT;
    conf.flags = RATS_TLS_CONF_FLAGS_MUTUAL;

    FuzzedDataProvider fuzzed_data(data + sizeof(conf), size - sizeof(conf));
    claim_t custom_claims[CUSTOM_CLAIMS_SIZE];
    std::vector<std::string> str_lists;
    for(int i=0;i<CUSTOM_CLAIMS_SIZE;i++){
        //const char * str = fuzzed_data.ConsumeBytesWithTerminator(50,'\0').data();
        /*这里不能使用上面的方法,否则会有空悬指针的问题*/
        std::vector<char> vec_str = fuzzed_data.ConsumeBytesWithTerminator(50,'\0');
        std::string str(vec_str.begin(),vec_str.end());
        str_lists.push_back(str);
        custom_claims[i].value = (uint8_t *)str_lists[i].c_str();
        //custom_claims[i].value_size = 51; // \0 also need 1 byte 
        custom_claims[i].value_size = (strlen(str_lists[i].c_str()) + 1) *sizeof(char);
        /*
            there exist a question, when I use strlen(str) to get 
            the size of used byte, Fuzzer warn I trigger `heap-use-after-free` 
            here, so I use a const number to assign to the value_size 
        */
        if(fuzzed_data.remaining_bytes() <= 0 ){
            return 0;
        }
        custom_claims[i].name = "key";

    }
    conf.custom_claims = (claim_t *)custom_claims;
    conf.custom_claims_length = CUSTOM_CLAIMS_SIZE;

    //claim_t custom_claims[2] = {
		//{ .name = "key_0", .value = (uint8_t *)"value_0", .value_size = sizeof("value_0") },
		//{ .name = "key_1", .value = (uint8_t *)"value_1", .value_size = sizeof("value_1") },
	//};
	//conf.custom_claims = (claim_t *)custom_claims;
	//conf.custom_claims_length = 2;

    rats_tls_handle handle;
    rats_tls_err_t err = rats_tls_init(&conf,&handle);
    return 0;
    

}