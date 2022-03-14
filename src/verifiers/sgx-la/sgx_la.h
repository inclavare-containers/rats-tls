/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _SGX_LA_H
#define _SGX_LA_H

#include "sgx_eid.h"

#define LA_REPORT_OID "1.2.840.113741.1337.14"

typedef struct {
	sgx_enclave_id_t eid;
} sgx_la_ctx_t;

#endif
