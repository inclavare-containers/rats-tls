/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/sev-guest.h>
#include <rats-tls/attester.h>
#include <rats-tls/log.h>
#include "sev_snp.h"

#define SEV_GUEST_DEVICE "/dev/sev-guest"

static int snp_get_report(const uint8_t *data, size_t data_size, snp_attestation_report_t *report)
{
	struct snp_report_req req;
	struct snp_report_resp resp;
	struct snp_guest_request_ioctl guest_req;
	snp_msg_report_rsp_t *report_resp = (struct msg_report_resp *)&resp.data;

	if (data && (data_size > sizeof(req.user_data) || data_size == 0) || !data || !report)
		return -1;

	/* Initialize data structures */
	memset(&req, 0, sizeof(req));
	req.vmpl = 1;
	if (data)
		memcpy(&req.user_data, data, data_size);

	memset(&resp, 0, sizeof(resp));

	memset(&guest_req, 0, sizeof(guest_req));
	guest_req.msg_version = 1;
	guest_req.req_data = (__u64)&req;
	guest_req.resp_data = (__u64)&resp;

	/* Open the sev-guest device */
	int fd = open(SEV_GUEST_DEVICE, O_RDWR);
	if (fd == -1) {
		RTLS_ERR("failed to open %s\n", SEV_GUEST_DEVICE);
		return -1;
	}

	/* Issue the guest request IOCTL */
	if (ioctl(fd, SNP_GET_REPORT, &guest_req) == -1) {
		RTLS_ERR("failed to issue SNP_GET_REPORT ioctl, firmware error %llu\n",
			 guest_req.fw_err);
		goto out_close;
	}

	close(fd);

	/* Check that the report was successfully generated */
	if (report_resp->status != 0) {
		RTLS_ERR("firmware error %#x\n", report_resp->status);
		goto out_close;
	}

	if (report_resp->report_size != sizeof(*report)) {
		RTLS_ERR("report size is %u bytes (expected %lu)!\n", report_resp->report_size,
			 sizeof(*report));
		goto out_close;
	}

	memcpy(report, &report_resp->report, report_resp->report_size);

	return 0;

out_close:
	close(fd);

	return -1;
}

enclave_attester_err_t sev_snp_collect_evidence(enclave_attester_ctx_t *ctx,
						attestation_evidence_t *evidence,
						rats_tls_cert_algo_t algo, uint8_t *hash,
						uint32_t hash_len)
{
	RTLS_DEBUG("ctx %p, evidence %p, algo %d, hash %p\n", ctx, evidence, algo, hash);

	snp_attestation_report_t report;
	memset(&report, 0, sizeof(report));

	if (snp_get_report(hash, hash_len, &report)) {
		RTLS_ERR("failed to get snp report\n");
		return -ENCLAVE_ATTESTER_ERR_INVALID;
	}

	snp_attestation_evidence_t *snp_report = &evidence->snp;
	memcpy(snp_report->report, &report, sizeof(report));
	snp_report->report_len = sizeof(report);

	snprintf(evidence->type, sizeof(evidence->type), "sev_snp");

	RTLS_DEBUG("ctx %p, evidence %p, report_len %d\n", ctx, evidence, evidence->snp.report_len);

	return ENCLAVE_ATTESTER_ERR_NONE;
}
