/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <rats-tls/log.h>
#include <rats-tls/attester.h>
#include <stddef.h>
#include <stdio.h>
#include "../../verifiers/tdx-ecdsa/tdx-ecdsa.h"

#define VSOCK

// clang-format off
#ifdef VSOCK
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <tdx_attest.h>
#endif
// clang-format on

#define TDEL_INFO "/sys/firmware/acpi/tables/TDEL"
#define TDEL_DATA "/sys/firmware/acpi/tables/data/TDEL"

static int tdx_get_report(const tdx_report_data_t *report_data, tdx_report_t *tdx_report)
{
	/* Get report by tdcall */
	if (tdx_att_get_report(report_data, tdx_report) != TDX_ATTEST_SUCCESS) {
		RTLS_ERR("failed to ioctl get tdx report data.\n");
		return -1;
	}

	return 0;
}

enclave_attester_err_t tdx_get_tdel_info(enclave_attester_ctx_t *ctx,
					 attestation_evidence_t *evidence, int *tdel_info_len)
{
	RTLS_DEBUG("ctx %p, evidence %p\n", ctx, evidence);

	int fd = open(TDEL_INFO, O_RDONLY);
	if (fd < 0) {
		RTLS_INFO("failed to open TDEL info device\n");
		/* TDEL is optional */
		return ENCLAVE_ATTESTER_ERR_NONE;
	}

	unsigned char tdel_info[TDEL_INFO_SZ];
	int tdel_info_sz = read(fd, tdel_info, sizeof(tdel_info));
	if (tdel_info_sz != sizeof(tdel_info)) {
		close(fd);
		RTLS_ERR("failed to read TDEL info\n");
		return -ENCLAVE_ATTESTER_ERR_INVALID;
	}

	*tdel_info_len = tdel_info_sz;
	memcpy(&(evidence->tdx.quote[TDX_ECDSA_QUOTE_SZ]), tdel_info, tdel_info_sz);

	close(fd);

	RTLS_DEBUG("TDEL info size %d-byte\n", tdel_info_sz);

	return ENCLAVE_ATTESTER_ERR_NONE;
}

enclave_attester_err_t tdx_get_tdel_data(enclave_attester_ctx_t *ctx,
					 attestation_evidence_t *evidence, int *tdel_data_len)
{
	RTLS_DEBUG("ctx %p, evidence %p\n", ctx, evidence);

	int fd = open(TDEL_DATA, O_RDONLY);
	if (fd < 0) {
		RTLS_ERR("failed to open TDEL info device\n");
		return -ENCLAVE_ATTESTER_ERR_INVALID;
	}

	unsigned char tdel_data[TDEL_DATA_SZ];
	int tdel_data_sz = read(fd, tdel_data, sizeof(tdel_data));
	if (tdel_data_sz <= 0) {
		close(fd);
		RTLS_INFO("failed to read TDEL data\n");
		return -ENCLAVE_ATTESTER_ERR_INVALID;
	}

	if (tdel_data_sz == sizeof(tdel_data))
		RTLS_WARN("TDEL data buffer (%d-byte) may be too small\n", sizeof(tdel_data));

	*tdel_data_len = tdel_data_sz;
	memcpy(&(evidence->tdx.quote[TDX_ECDSA_QUOTE_SZ + TDEL_INFO_SZ]), tdel_data, tdel_data_sz);

	close(fd);

	RTLS_DEBUG("TDEL data size %d-byte\n", tdel_data_sz);

	return ENCLAVE_ATTESTER_ERR_NONE;
}

static int tdx_gen_quote(uint8_t *hash, uint32_t hash_len, uint8_t *quote_buf, uint32_t *quote_size)
{
	if (hash == NULL) {
		RTLS_ERR("empty hash pointer.\n");
		return -1;
	}

	tdx_report_t tdx_report = { { 0 } };
	tdx_report_data_t report_data = { { 0 } };
	if (sizeof(report_data.d) < hash_len) {
		RTLS_ERR("hash_len(%u) shall be smaller than user-data filed size (%zu)\n",
			 hash_len, sizeof(report_data.d));
		return -1;
	}
	memcpy(report_data.d, hash, hash_len);
	int ret = tdx_get_report(&report_data, &tdx_report);
	if (ret != 0) {
		RTLS_ERR("failed to get tdx report.\n");
		return -1;
	}

#ifdef VSOCK
	tdx_uuid_t selected_att_key_id = { { 0 } };
	uint8_t *p_quote = NULL;
	uint32_t p_quote_size = 0;
	if (tdx_att_get_quote(&report_data, NULL, 0, &selected_att_key_id, &p_quote, &p_quote_size,
			      0) != TDX_ATTEST_SUCCESS) {
		RTLS_ERR("failed to get tdx quote.\n");
		return -1;
	}

	if (p_quote_size > *quote_size) {
		RTLS_ERR("quote buffer is too small (%d-byte vs %d-byte).\n", p_quote_size,
			 *quote_size);
		tdx_att_free_quote(p_quote);
		return -1;
	}

	memcpy(quote_buf, p_quote, p_quote_size);
	*quote_size = p_quote_size;
	tdx_att_free_quote(p_quote);
#else
	/* This branch is for getting quote size and quote by tdcall,
	 * it depends on the implemetation in qemu.
	 */
	#error "using tdcall to retrieve TD quote is still not supported!"
#endif

	return 0;
}

enclave_attester_err_t tdx_ecdsa_collect_evidence(enclave_attester_ctx_t *ctx,
						  attestation_evidence_t *evidence,
						  rats_tls_cert_algo_t algo, uint8_t *hash,
						  uint32_t hash_len)
{
	RTLS_DEBUG("ctx %p, evidence %p, algo %d, hash %p, hash_len: %u\n", ctx, evidence, algo,
		   hash, hash_len);

	evidence->tdx.quote_len = sizeof(evidence->tdx.quote);
	if (tdx_gen_quote(hash, hash_len, evidence->tdx.quote, &evidence->tdx.quote_len)) {
		RTLS_ERR("failed to generate quote\n");
		return -ENCLAVE_ATTESTER_ERR_INVALID;
	}

	RTLS_DEBUG("Succeed to generate the quote!\n");

	int tdel_info_len = 0;
	if (tdx_get_tdel_info(ctx, evidence, &tdel_info_len) != ENCLAVE_ATTESTER_ERR_NONE)
		return -ENCLAVE_ATTESTER_ERR_INVALID;

	/* TDEL information is optional */
	int tdel_data_len = 0;
	if (tdel_info_len &&
	    tdx_get_tdel_data(ctx, evidence, &tdel_data_len) != ENCLAVE_ATTESTER_ERR_NONE)
		return -ENCLAVE_ATTESTER_ERR_INVALID;

	/* Essentially speaking, QGS generates the same
	 * format of quote as sgx_ecdsa.
	 */
	snprintf(evidence->type, sizeof(evidence->type), "tdx_ecdsa");
	evidence->tdx.tdel_info_len = tdel_info_len;
	evidence->tdx.tdel_data_len = tdel_data_len;

	RTLS_DEBUG("ctx %p, evidence %p, quote_size %d\n", ctx, evidence, evidence->tdx.quote_len);

	return ENCLAVE_ATTESTER_ERR_NONE;
}
