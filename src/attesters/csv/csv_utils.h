/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

void gen_random_bytes(void *buf, size_t len);
int sm3_hash(const unsigned char *data, size_t len, unsigned char *hash, size_t expected_hash_len);
int sm3_hmac(const char *key, size_t key_len, const unsigned char *data, size_t data_len,
	     unsigned char *hmac, size_t expected_hmac_len);
