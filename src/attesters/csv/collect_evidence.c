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
#include <curl/curl.h>
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

static size_t curl_writefunc_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	csv_evidence *evidence = (csv_evidence *)userp;

	if (evidence->hsk_cek_cert_len + realsize > HYGON_HSK_CEK_CERT_SIZE) {
		RTLS_ERR("hsk_cek size is large than %d bytes.", HYGON_HSK_CEK_CERT_SIZE);
		return 0;
	}
	memcpy(&(evidence->hsk_cek_cert[evidence->hsk_cek_cert_len]), contents, realsize);
	evidence->hsk_cek_cert_len += realsize;

	return realsize;
}

static int read_hsk_cek_cert_from_localfs(const char *chip_id, csv_evidence *evidence_buffer)
{
	int count = 0;
	char cert_path[200] = {
		0,
	};

	count = snprintf(cert_path, sizeof(cert_path), "%s/%s/%s", CSV_HSK_CEK_DEFAULT_DIR, chip_id,
			 HYGON_HSK_CEK_CERT_FILENAME);
	cert_path[count] = '\0';

	if (get_file_size(cert_path) != HYGON_HSK_CEK_CERT_SIZE)
		return -1;

	if (read_file(cert_path, evidence_buffer->hsk_cek_cert, HYGON_HSK_CEK_CERT_SIZE) !=
	    HYGON_HSK_CEK_CERT_SIZE)
		return -1;

	evidence_buffer->hsk_cek_cert_len = HYGON_HSK_CEK_CERT_SIZE;
	return 0;
}

static int download_hsk_cek_cert(const char *chip_id, csv_evidence *evidence_buffer)
{
	/* Download HSK and CEK cert by ChipId */
	char url[200] = {
		0,
	};
	int count = snprintf(url, sizeof(url), "%s%s", HYGON_KDS_SERVER_SITE, chip_id);
	url[count] = '\0';
	// init curl
	CURLcode curl_ret = CURLE_OK;
	CURL *curl = curl_easy_init();
	if (!curl) {
		RTLS_ERR("failed to init curl.");
		return -1;
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writefunc_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)evidence_buffer);
	for (int i = 0; i < 5; i++) {
		evidence_buffer->hsk_cek_cert_len = 0;
		if ((curl_ret = curl_easy_perform(curl)) == CURLE_OK) {
			break;
		}
		RTLS_DEBUG("failed to download hsk_cek, try again.");
	}
	curl_easy_cleanup(curl);
	if (curl_ret != CURLE_OK) {
		RTLS_ERR("failed to download hsk_cek after 5 retries, %s\n",
			 curl_easy_strerror(curl_ret));
		return -1;
	}

	return 0;
}

/**
 * Download HSK and CEK cert, and then save them to @hsk_cek_cert.
 *
 * Params:
 * 	chip_id         [in]: platform's ChipId
 * 	evidence_buffer [in]: the buffer to save HSK and CEK cert, which follows the attestation
 * 			      report
 * Return:
 * 	0: success
 * 	otherwise error
 */
static int csv_get_hsk_cek_cert(const char *chip_id, csv_evidence *evidence_buffer)
{
	/* First read hsk_cek cert from local file system, and then download
	 * hsk_cek cert through network when the reading fails */
	if (read_hsk_cek_cert_from_localfs(chip_id, evidence_buffer))
		return download_hsk_cek_cert(chip_id, evidence_buffer);

	return 0;
}

#define CSV_GUEST_MAP_LEN     4096
#define KVM_HC_VM_ATTESTATION 100 /* Specific to HYGON CPU */

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

	// clang-fomat off
	/* Prepare user defined data (challenge and mnonce) */
	memcpy(user_data->data, hash,
	       hash_len <= CSV_ATTESTATION_USER_DATA_SIZE ? hash_len :
							    CSV_ATTESTATION_USER_DATA_SIZE);
	// clang-format on

	gen_random_bytes(user_data->mnonce, CSV_ATTESTATION_MNONCE_SIZE);

	/* Prepare hash of user defined data */
	ret = sm3_hash((const unsigned char *)user_data,
		       CSV_ATTESTATION_USER_DATA_SIZE + CSV_ATTESTATION_MNONCE_SIZE,
		       (unsigned char *)(&user_data->hash), sizeof(hash_block_t));
	if (ret) {
		RTLS_ERR("failed to compute sm3 hash\n");
		goto err_munmap;
	}

	/* Save user_data->mnonce to check the timeliness of attestation report later */
	unsigned char cur_mnonce[CSV_ATTESTATION_MNONCE_SIZE];
	memcpy(cur_mnonce, user_data->mnonce, CSV_ATTESTATION_MNONCE_SIZE);

	/* Request ATTESTATION */
	user_data_pa = (uint64_t)gva_to_gpa(user_data);
	ret = do_hypercall(KVM_HC_VM_ATTESTATION, (unsigned long)user_data_pa, CSV_GUEST_MAP_LEN);
	if (ret) {
		RTLS_ERR("failed to save attestation report to %#016lx (ret:%d)\n", user_data_pa,
			 ret);
		goto err_munmap;
	}

	/* Check whether the attestation report is fresh */
	unsigned char report_mnonce[CSV_ATTESTATION_MNONCE_SIZE];
	csv_attestation_report *attestation_report = (csv_attestation_report *)user_data;
	int i;

	for (i = 0; i < CSV_ATTESTATION_MNONCE_SIZE / sizeof(uint32_t); i++)
		((uint32_t *)report_mnonce)[i] = ((uint32_t *)attestation_report->mnonce)[i] ^
						 attestation_report->anonce;
	ret = memcmp(cur_mnonce, report_mnonce, CSV_ATTESTATION_MNONCE_SIZE);
	if (ret) {
		RTLS_ERR("mnonce is not fresh\n");
		goto err_munmap;
	}

	/* Fill evidence buffer with attestation report */
	assert(sizeof(csv_attestation_report) <= CSV_GUEST_MAP_LEN);

	/* The PEK and ChipId are stored in csv_attestation_report, it's necessary
	 * to validate PEK and ChipId before transfer to verifier.
	 */
	hash_block_t hmac;

	memset((void *)&hmac, 0, sizeof(hash_block_t));
	ret = sm3_hmac((const char *)report_mnonce, CSV_ATTESTATION_MNONCE_SIZE,
		       (const unsigned char *)attestation_report +
			       CSV_ATTESTATION_REPORT_HMAC_DATA_OFFSET,
		       CSV_ATTESTATION_REPORT_HMAC_DATA_SIZE, (unsigned char *)&hmac,
		       sizeof(hash_block_t));
	if (ret) {
		RTLS_ERR("failed to compute sm3 hmac\n");
		goto err_munmap;
	}
	ret = memcmp(&hmac, &attestation_report->hmac, sizeof(hash_block_t));
	if (ret) {
		RTLS_ERR("PEK and ChipId may have been tampered with\n");
		goto err_munmap;
	}
	RTLS_DEBUG("check PEK and ChipId successfully\n");

	/* Reserved1 field should be filled with 0 */
	memset(attestation_report->reserved1, 0, sizeof(attestation_report->reserved1));

	memcpy(evidence->report, (void *)user_data, sizeof(csv_attestation_report));

	/* Fill in CEK cert and HSK cert */
	csv_evidence *evidence_buffer = (csv_evidence *)evidence->report;

	assert(sizeof(csv_evidence) <= sizeof(evidence->report));

	/* Retreive ChipId from attestation report */
	uint8_t chip_id[CSV_ATTESTATION_CHIP_SN_SIZE + 1] = {
		0,
	};
	attestation_report = &evidence_buffer->attestation_report;

	for (i = 0; i < CSV_ATTESTATION_CHIP_SN_SIZE / sizeof(uint32_t); i++)
		((uint32_t *)chip_id)[i] = ((uint32_t *)attestation_report->chip_id)[i] ^
					   attestation_report->anonce;

	if (csv_get_hsk_cek_cert((const char *)chip_id, evidence_buffer)) {
		RTLS_ERR("failed to load HSK and CEK cert\n");
		ret = -1;
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
