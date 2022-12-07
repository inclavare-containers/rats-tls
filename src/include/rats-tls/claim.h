/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _RATS_TLS_CLAIM_H_
#define _RATS_TLS_CLAIM_H_

#include <stddef.h>
#include <stdint.h>

/**
 * Claims struct used for claims parameters.
 */
typedef struct claim claim_t;
struct claim {
	char *name;
	uint8_t *value;
	size_t value_size;
} __attribute__((packed));

void free_claims_list(claim_t *claims, size_t claims_length);
claim_t *clone_claims_list(claim_t *claims, size_t claims_length);

#endif /* _RATS_TLS_CLAIM_H_ */
