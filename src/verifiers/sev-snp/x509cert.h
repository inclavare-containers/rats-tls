/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _X509CERT_H
#define _X509CERT_H

#include <stdbool.h>

int convert_der_to_pem(char *in_file_name, char *out_file_name);
bool read_pem_into_x509(char *file_name, X509 **x509_cert);
bool x509_validate_signature(X509 *child_cert, X509 *intermediate_cert, X509 *parent_cert);

#endif /* _X509CERT_H */
