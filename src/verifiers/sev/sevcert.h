/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _SEVCERT_H
#define _SEVCERT_H

#include "sev_utils.h"

bool verify_sev_cert(const sev_cert *child_cert, const sev_cert *parent_cert1,
		     const sev_cert *parent_cert2);
bool validate_attestation(sev_cert *pek, sev_attestation_report *report);

#endif /* _SEVCERT_H */
