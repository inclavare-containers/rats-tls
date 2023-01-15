/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _RATS_TLS_DICE_H
#define _RATS_TLS_DICE_H

#include <rats-tls/cert.h>
#include <rats-tls/endorsement.h>
#include <rats-tls/claim.h>

/* Intel TEE quote, including all SGX (both EPID and ECDSA) and TDX (ECDSA) quote types */
#define OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE 0x1a7501 /* rats01 */
/* Intel TEE report (TDX report or SGX report type 2) */
#define OCBR_TAG_EVIDENCE_INTEL_TEE_REPORT 0x1a7502
/* SGX report (legacy, generated by EREPORT) */
#define OCBR_TAG_EVIDENCE_INTEL_SGX_LEGACY_REPORT 0x1a7503
#define OCBR_TAG_EVIDENCE_SEV_SNP		  0x1a7504
#define OCBR_TAG_EVIDENCE_SEV			  0x1a7505
#define OCBR_TAG_EVIDENCE_CSV			  0x1a7506
#define OCBR_TAG_EVIDENCE_MIN			  OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE
#define OCBR_TAG_EVIDENCE_MAX			  OCBR_TAG_EVIDENCE_CSV

#define CLAIM_PUBLIC_KEY_HASH "pubkey-hash"
#define CLAIM_NONCE	      "nonce"

#define TCG_DICE_TAGGED_EVIDENCE_OID	  "2.23.133.5.4.9"
#define TCG_DICE_ENDORSEMENT_MANIFEST_OID "2.23.133.5.4.2"

uint64_t tag_of_evidence_type(const char *type);

const uint8_t *evidence_get_raw_as_ref(const attestation_evidence_t *evidence, size_t *size);

int evidence_from_raw(const uint8_t *data, size_t size, uint64_t tag,
		      attestation_evidence_t *evidence);

enclave_attester_err_t dice_generate_claims_buffer(const uint8_t *pubkey_hash,
						   const claim_t *custom_claims,
						   size_t custom_claims_length,
						   uint8_t **claims_buffer_out,
						   size_t *claims_buffer_size_out);

enclave_attester_err_t dice_generate_evidence_buffer_with_tag(
	const attestation_evidence_t *evidence, const uint8_t *claims_buffer,
	const size_t claims_buffer_size, uint8_t **evidence_buffer_out,
	size_t *evidence_buffer_size_out);

enclave_attester_err_t dice_generate_endorsements_buffer_with_tag(
	const char *type, const attestation_endorsement_t *endorsements,
	uint8_t **endorsements_buffer_out, size_t *endorsements_buffer_size_out);

enclave_verifier_err_t dice_parse_evidence_buffer_with_tag(const uint8_t *evidence_buffer,
							   size_t evidence_buffer_size,
							   attestation_evidence_t *evidence,
							   uint8_t **claims_buffer_out,
							   size_t *claims_buffer_size_out);

enclave_verifier_err_t
dice_parse_endorsements_buffer_with_tag(const char *type, const uint8_t *endorsements_buffer,
					size_t endorsements_buffer_size,
					attestation_endorsement_t *endorsements);

enclave_verifier_err_t dice_parse_and_verify_claims_buffer(const uint8_t *pubkey_hash,
							   const uint8_t *claims_buffer,
							   size_t claims_buffer_size,
							   claim_t **custom_claims_out,
							   size_t *custom_claims_length_out);

#endif
