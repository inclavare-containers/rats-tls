/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _UTILS_H
#define _UTILS_H

#include <stdbool.h>
#include <stdint.h>

/* Store the SEV-SNP certs downloaded from AMD KDS */
#define SEV_SNP_DEFAULT_DIR "/opt/sev-snp/"

#define KDS_CERT_SITE "https://kdsintf.amd.com"
#define KDS_CEK	      KDS_CERT_SITE "/cek/id/"
#define KDS_VCEK      KDS_CERT_SITE "/vcek/v1/"

#define KDS_VCEK_CERT_CHAIN	     "cert_chain"
#define VCEK_CERT_CHAIN_PEM_FILENAME "cert_chain.pem"
#define VCEK_DER_FILENAME	     "vcek.der"
#define VCEK_PEM_FILENAME	     "vcek.pem"
#define VCEK_ASK_PEM_FILENAME	     "ask.pem"
#define VCEK_ARK_PEM_FILENAME	     "ark.pem"

int get_file_size(char *name);
bool reverse_bytes(uint8_t *bytes, size_t size);

#endif /* _UTILS_H */
