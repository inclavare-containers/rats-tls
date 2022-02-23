/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _SEV_SNP_H
#define _SEV_SNP_H

#include <stdint.h>
#include <stdio.h>
#include <rats-tls/api.h>

/* The following structures are defined by AMD, please refer to
 * https://www.amd.com/system/files/TechDocs/56860.pdf for details.
 */

/* 2.2 TCB Version
 * A version string that represents the version of the firmware
 */
typedef union snp_tcb_version {
	struct {
		/* SVN of PSP bootloader */
		uint8_t boot_loader;
		/* SVN of PSP operating system */
		uint8_t tee;
		uint8_t reserved[4];
		/* SVN of PSP firmware */
		uint8_t snp;
		/* Lowest current patch level of all the cores */
		uint8_t microcode;
	} __attribute__((packed)) f;
	uint64_t val;
} __attribute__((packed)) snp_tcb_version_t;

typedef struct signature {
	uint8_t r[72];
	uint8_t s[72];
	uint8_t reserved[368];
} __attribute__((packed)) signature_t;

/* Table 21. ATTESTATION_REPORT Structure */
typedef struct snp_attestation_report {
	uint32_t version; /* 0x000 */
	uint32_t guest_svn; /* 0x004 */
	uint64_t policy; /* 0x008 */
	uint8_t family_id[16]; /* 0x010 */
	uint8_t image_id[16]; /* 0x020 */
	uint32_t vmpl; /* 0x030 */
	uint32_t signature_algo; /* 0x034 */
	snp_tcb_version_t platform_version; /* 0x038 */
	uint64_t platform_info; /* 0x040 */
	uint32_t flags; /* 0x048 */
	uint32_t reserved0; /* 0x04C */
	uint8_t report_data[64]; /* 0x050 */
	uint8_t measurement[48]; /* 0x090 */
	uint8_t host_data[32]; /* 0x0C0 */
	uint8_t id_key_digest[48]; /* 0x0E0 */
	uint8_t author_key_digest[48]; /* 0x110 */
	uint8_t report_id[32]; /* 0x140 */
	uint8_t report_id_ma[32]; /* 0x160 */
	snp_tcb_version_t reported_tcb; /* 0x180 */
	uint8_t reserved1[24]; /* 0x188 */
	uint8_t chip_id[64]; /* 0x1A0 */
	uint8_t reserved2[192]; /* 0x1E0 */
	signature_t signature; /* 0x2A0 */
} __attribute__((packed)) snp_attestation_report_t;

/* Table 23. MSG_REPORT_RSP Message Structure */
typedef struct snp_msg_report_rsp {
	uint32_t status;
	uint32_t report_size;
	uint8_t reserved[0x20 - 0x08];
	snp_attestation_report_t report;
} __attribute__((packed)) snp_msg_report_rsp_t;

#endif /* _SEV_SNP_H */
