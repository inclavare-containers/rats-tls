/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _INTERNAL_CPU_H
#define _INTERNAL_CPU_H

#include <stdbool.h>

#define SGX_CPUID 0x12
#define TDX_CPUID 0x21

#define SGX_DEVICE_MAJOR_NUM 10

#define SGX1_STRING 0x00000001
#define SGX2_STRING 0x00000002

#define SEV_STATUS_MSR 0xc0010131
#define SEV_FLAG       0
#define SEV_ES_FLAG    1
#define SEV_SNP_FLAG   2

extern bool is_sgx1_supported(void);
extern bool is_sgx2_supported(void);
extern bool is_tdguest_supported(void);
extern bool is_snpguest_supported(void);
extern bool is_sevguest_supported(void);
extern bool is_csvguest_supported(void);

#endif /* _INTERNAL_CPU_H */
