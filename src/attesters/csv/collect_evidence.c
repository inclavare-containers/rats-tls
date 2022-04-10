/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <rats-tls/log.h>
#include <rats-tls/attester.h>
#include <rats-tls/csv.h>
#include "csv_utils.h"
#include "../../verifiers/sev/sev_utils.c"

#define PAGE_MAP_FILENAME   "/proc/self/pagemap"
#define PAGE_MAP_PFN_MASK   0x007fffffffffffffUL
#define PAGE_MAP_PAGE_SHIFT 12
#define PAGE_MAP_PAGE_SIZE  (1UL << PAGE_MAP_PAGE_SHIFT)
#define PAGE_MAP_ENTRY_SIZE sizeof(uint64_t)
typedef uint64_t page_map_entry_t;

/**
 * Translate the virtual address of app to physical address
 *
 * Params:
 * 	va [in]: virtual address in app address space
 * Return:
 * 	physical address correspond to @va: success
 * 	NULL: fail
 */
static void *gva_to_gpa(void *va)
{
	int fd = -1;
	void *pa = NULL;
	uint64_t paging_entry_offset;
	page_map_entry_t entry;

	fd = open(PAGE_MAP_FILENAME, O_RDONLY);
	if (fd == -1) {
		RTLS_ERR("failed to open %s\n", PAGE_MAP_FILENAME);
		return NULL;
	}

	paging_entry_offset = ((uint64_t)va >> PAGE_MAP_PAGE_SHIFT) * PAGE_MAP_ENTRY_SIZE;
	if (lseek(fd, paging_entry_offset, SEEK_SET) == -1) {
		RTLS_ERR("failed to seek\n");
		goto err_close_fd;
	}

	if (read(fd, &entry, sizeof(entry)) != sizeof(entry)) {
		RTLS_ERR("failed to read pagemap entry\n");
		goto err_close_fd;
	}

	if (!(entry & (1ul << 63))) {
		RTLS_ERR("page doesn't present\n");
		goto err_close_fd;
	}

	pa = (void *)((entry & PAGE_MAP_PFN_MASK) << PAGE_MAP_PAGE_SHIFT) +
	     ((uint64_t)va % PAGE_MAP_PAGE_SIZE);

	RTLS_DEBUG("offset %#016lx, entry %#016lx, pa %#016lx\n",
		   (unsigned long)paging_entry_offset, (unsigned long)entry, (unsigned long)pa);

err_close_fd:
	close(fd);

	return pa;
}

static int do_hypercall(unsigned int p1, unsigned long p2, unsigned long p3)
{
	long ret = 0;

	asm volatile("vmmcall" : "=a"(ret) : "a"(p1), "b"(p2), "c"(p3) : "memory");

	return (int)ret;
}

/**
 * Download HSK and CEK cert, and then save them to @hsk_cek_cert.
 *
 * Params:
 * 	hsk_cek_cert [in]: the buffer to save HSK and CEK cert
 * 	chip_id      [in]: platform's ChipId
 * Return:
 * 	0: success
 * 	otherwise error
 */
static int load_hsk_cek_cert(uint8_t *hsk_cek_cert, const char *chip_id)
{
	/* Download HSK and CEK cert by ChipId */
	const char filename[] = HYGON_HSK_CEK_CERT_FILENAME;
	char cmdline_str[200] = {
		0,
	};
	int count = snprintf(cmdline_str, sizeof(cmdline_str), "wget -O %s %s%s",
			     filename, HYGON_KDS_SERVER_SITE, chip_id);
	cmdline_str[count] = '\0';

	if (system(cmdline_str) != 0) {
		RTLS_ERR("failed to download %s by %s\n", filename, chip_id);
		return -1;
	}

	size_t read_len = HYGON_HSK_CEK_CERT_SIZE;
	if (read_file(filename, hsk_cek_cert, read_len) != read_len) {
		RTLS_ERR("read %s fail\n", filename);
		return -1;
	}

	return 0;
}

#define CSV_GUEST_MAP_LEN	 4096
#define KVM_HC_VM_ATTESTATION	 12	/* Specific to HYGON CPU */

typedef struct {
	unsigned char data[CSV_ATTESTATION_USER_DATA_SIZE];
	unsigned char mnonce[CSV_ATTESTATION_MNONCE_SIZE];
	hash_block_t hash;
} csv_attester_user_data_t;

/**
 * Initiate ATTESTATION from guest, and save evidence to @evidence.
 * The report size of csv_attestation_evidence_t is large enough to hold
 * CSV attestation report, CEK cert and HSK cert.
 * 		.----------------------------.
 * 		|   CSV attestation report   |
 * 		|   Platform's CEK cert      |
 * 		|   Vendor's HSK cert        |
 * 		'----------------------------'
 *
 * The components of CSV attestation report are shown below:
 * 		.------------------------------------------.
 * 		|   CSV environment claims and signature   |
 * 		|   Platform's PEK cert                    |
 * 		|   Platform's ChipId                      |
 * 		|   ...                                    |
 * 		|   hmac of PEK cert, ChipId, ...          |
 * 		'------------------------------------------'
 * Params:
 * 	hash     [in]: hash of TLS pubkey
 * 	evidence [in]: address of csv attestation evidence
 * Return:
 * 	0: success
 * 	otherwise error
 */
static int collect_attestation_evidence(uint8_t *hash, uint32_t hash_len,
					csv_attestation_evidence_t *evidence)
{
	int ret = 0;
	uint64_t user_data_pa;
	csv_attester_user_data_t *user_data = NULL;

	/* Request an private page which is used to communicate with CSV firmware.
	 * When attester want collect claims from CSV firmware, it will set user
	 * data to this private page. If CSV firmware returns successfully, it will
	 * save claims to this private page.
	 *
	 * TODO: pin the mmapped page in this attester.
	 */
	user_data = mmap(NULL, CSV_GUEST_MAP_LEN, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (user_data == MAP_FAILED) {
		RTLS_ERR("failed to mmap\n");
		return -1;
	}
	RTLS_DEBUG("mmap [%#016lx - %#016lx)\n", (unsigned long)user_data,
		   (unsigned long)user_data + CSV_GUEST_MAP_LEN);
	memset((void *)user_data, 0, CSV_GUEST_MAP_LEN);

	/* Prepare user defined data (challenge and mnonce) */
	memcpy(user_data->data, hash,
	       hash_len <= CSV_ATTESTATION_USER_DATA_SIZE ? hash_len : CSV_ATTESTATION_USER_DATA_SIZE);
	gen_random_bytes(user_data->mnonce, CSV_ATTESTATION_MNONCE_SIZE);

	/* Prepare hash of user defined data */
	ret = sm3_hash((const unsigned char *)user_data,
		       CSV_ATTESTATION_USER_DATA_SIZE + CSV_ATTESTATION_MNONCE_SIZE,
		       (unsigned char *)(&user_data->hash), sizeof(hash_block_t));
	if (ret) {
		RTLS_ERR("failed to compute sm3 hash\n");
		goto err_munmap;
	}

	/* Request ATTESTATION */
	user_data_pa = (uint64_t)gva_to_gpa(user_data);
	ret = do_hypercall(KVM_HC_VM_ATTESTATION, (unsigned long)user_data_pa, CSV_GUEST_MAP_LEN);
	if (ret) {
		RTLS_ERR("failed to save attestation report to %#016lx (ret:%d)\n", ret, user_data_pa);
		goto err_munmap;
	}

	/* Fill evidence buffer with attestation report */
	assert(sizeof(csv_attestation_report) <= CSV_GUEST_MAP_LEN);
	memcpy(evidence->report, (void *)user_data, sizeof(csv_attestation_report));

	/* Fill in CEK cert and HSK cert */
	csv_evidence *evidence_buffer = (csv_evidence *)evidence->report;

	assert(sizeof(csv_evidence) <= sizeof(evidence->report));
	if (load_hsk_cek_cert(evidence_buffer->hsk_cek_cert,
			      (const char *)evidence_buffer->attestation_report.chip_id)) {
		RTLS_ERR("failed to load HSK and CEK cert\n");
		goto err_munmap;
	}
	evidence->report_len = sizeof(csv_evidence);

	ret = 0;

err_munmap:
	munmap(user_data, CSV_GUEST_MAP_LEN);

	return ret;
}

enclave_attester_err_t csv_collect_evidence(enclave_attester_ctx_t *ctx,
					    attestation_evidence_t *evidence,
					    rats_tls_cert_algo_t algo, uint8_t *hash,
					    __attribute__((unused)) uint32_t hash_len)
{
	RTLS_DEBUG("ctx %p, evidence %p, algo %d, hash %p\n", ctx, evidence, algo, hash);

	csv_attestation_evidence_t *c_evidence = &evidence->csv;
	if (collect_attestation_evidence(hash, hash_len, c_evidence)) {
		RTLS_ERR("failed to get attestation_evidence\n");
		return -ENCLAVE_ATTESTER_ERR_INVALID;
	}

	RTLS_DEBUG("Success to generate attestation_evidence\n");

	snprintf(evidence->type, sizeof(evidence->type), "csv");

	RTLS_DEBUG("ctx %p, evidence %p, report_len %d\n", ctx, evidence, evidence->csv.report_len);

	return ENCLAVE_ATTESTER_ERR_NONE;
}
