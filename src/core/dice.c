/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <rats-tls/err.h>
#include <rats-tls/log.h>
#include <internal/dice.h>
#include <rats-tls/cert.h>
#include <rats-tls/endorsement.h>
#include <cbor.h>

uint64_t tag_of_evidence_type(const char *type)
{
	if (!strcmp(type, "sgx_ecdsa")) {
		return OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE;
	} else if (!strcmp(type, "tdx_ecdsa")) {
		return OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE;
	} else if (!strcmp(type, "sgx_la")) {
		return OCBR_TAG_EVIDENCE_INTEL_SGX_LEGACY_REPORT;
	} else if (!strcmp(type, "sev_snp")) {
		return OCBR_TAG_EVIDENCE_SEV_SNP;
	} else if (!strcmp(type, "sev")) {
		return OCBR_TAG_EVIDENCE_SEV;
	} else if (!strcmp(type, "csv")) {
		return OCBR_TAG_EVIDENCE_CSV;
	}

	RTLS_FATAL("Unhandled evidence type '%s'\n", type);
	return 0;
}

bool tag_is_valid(uint64_t tag)
{
	return OCBR_TAG_EVIDENCE_MIN <= tag && tag <= OCBR_TAG_EVIDENCE_MAX;
}

const uint8_t *evidence_get_raw_as_ref(const attestation_evidence_t *evidence, size_t *size_out)
{
	const uint8_t *data = NULL;
	size_t size = 0;

	if (!strcmp(evidence->type, "sgx_ecdsa")) {
		data = (const uint8_t *)&evidence->ecdsa.quote;
		size = evidence->ecdsa.quote_len;
	} else if (!strcmp(evidence->type, "tdx_ecdsa")) {
		data = (const uint8_t *)&evidence->tdx.quote;
		size = evidence->tdx.quote_len;
	} else if (!strcmp(evidence->type, "sgx_la")) {
		data = (const uint8_t *)&evidence->la.report;
		size = evidence->la.report_len;
	} else if (!strcmp(evidence->type, "sev_snp")) {
		data = (const uint8_t *)&evidence->snp.report;
		size = evidence->snp.report_len;
	} else if (!strcmp(evidence->type, "sev")) {
		data = (const uint8_t *)&evidence->sev.report;
		size = evidence->sev.report_len;
	} else if (!strcmp(evidence->type, "csv")) {
		data = (const uint8_t *)&evidence->csv.report;
		size = evidence->csv.report_len;
	} else {
		RTLS_FATAL("Unhandled evidence type '%s'\n", evidence->type);
		*size_out = 0;
		return NULL;
	}
	*size_out = (size_t)size;
	if (size >= 16)
		RTLS_DEBUG(
			"evidence raw data [%zu] %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x...\n",
			size, data[0], data[1], data[2], data[3], data[4], data[5], data[6],
			data[7], data[8], data[9], data[10], data[11], data[12], data[13], data[14],
			data[15]);
	return data;
}

int evidence_from_raw(const uint8_t *data, size_t size, uint64_t tag,
		      attestation_evidence_t *evidence)
{
	if (size >= 16)
		RTLS_DEBUG(
			"evidence raw data [%zu] %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x...\n",
			size, data[0], data[1], data[2], data[3], data[4], data[5], data[6],
			data[7], data[8], data[9], data[10], data[11], data[12], data[13], data[14],
			data[15]);

	if (!tag_is_valid(tag)) {
		RTLS_FATAL("Invalid cbor tag: 0x%zx\n", tag);
		return 1;
	}

	if (size > sizeof(attestation_evidence_t) - offsetof(attestation_evidence_t, ecdsa)) {
		RTLS_FATAL("Invalid evidence: evidence length %zu is too large\n", size);
		return 1;
	}

	memset(evidence, 0, sizeof(attestation_evidence_t));

	if (tag == OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE) {
		/* Use a simplified header structure to distinguish between SGX (EPID and ECDSA) and TDX (ECDSA) quote types */
		typedef struct {
			uint16_t version;
			uint16_t att_key_type;
			uint32_t tee_type;
		} sgx_quote_header_part_t;
		if (size < sizeof(sgx_quote_header_part_t)) {
			RTLS_FATAL("Invalid evidence: evidence length %zu is too short\n", size);
			return 1;
		}
		sgx_quote_header_part_t *header = (sgx_quote_header_part_t *)data;
		if ((header->version == 3 &&
		     (header->att_key_type == 2 || header->att_key_type == 3)) ||
		    (header->version == 4 && header->tee_type == 0)) {
			memcpy(evidence->type, "sgx_ecdsa", sizeof("sgx_ecdsa"));
			memcpy((uint8_t *)&evidence->ecdsa.quote, data, size);
			evidence->ecdsa.quote_len = size;
		} else if (header->version == 4 && header->tee_type == 0x81) {
			memcpy(evidence->type, "tdx_ecdsa", sizeof("tdx_ecdsa"));
			memcpy((uint8_t *)&evidence->tdx.quote, data, size);
			evidence->tdx.quote_len = size;
		} else if (header->version == 2 ||
			   (header->version == 3 && header->att_key_type == 0)) {
			RTLS_FATAL("Unsupported evidence type: SGX EPID quote\n");
			return 1;
		} else {
			RTLS_FATAL("Unsupported evidence type: unknown recognized\n");
			return 1;
		}
	} else if (tag == OCBR_TAG_EVIDENCE_INTEL_TEE_REPORT) {
		RTLS_FATAL(
			"Unsupported evidence type: Intel TEE report (TDX report or SGX report type 2)\n");
		return 1;
	} else if (tag == OCBR_TAG_EVIDENCE_INTEL_SGX_LEGACY_REPORT) {
		memcpy(evidence->type, "sgx_la", sizeof("sgx_la"));
		memcpy((uint8_t *)&evidence->la.report, data, size);
		evidence->la.report_len = size;
	} else if (tag == OCBR_TAG_EVIDENCE_SEV_SNP) {
		memcpy(evidence->type, "sev_snp", sizeof("sev_snp"));
		memcpy((uint8_t *)&evidence->snp.report, data, size);
		evidence->snp.report_len = size;
	} else if (tag == OCBR_TAG_EVIDENCE_SEV) {
		memcpy(evidence->type, "sev", sizeof("sev"));
		memcpy((uint8_t *)&evidence->sev.report, data, size);
		evidence->sev.report_len = size;
	} else if (tag == OCBR_TAG_EVIDENCE_CSV) {
		memcpy(evidence->type, "csv", sizeof("csv"));
		memcpy((uint8_t *)&evidence->csv.report, data, size);
		evidence->csv.report_len = size;
	}

	return 0;
}

/*
* DICE related attester functions
*/

enclave_attester_err_t dice_generate_pubkey_hash_value_buffer(hash_algo_t pubkey_hash_algo,
							      const uint8_t *pubkey_hash,
							      uint8_t **pubkey_hash_value_buffer,
							      size_t *pubkey_hash_value_buffer_size)
{
	enclave_attester_err_t ret;
	cbor_item_t *root = NULL;

	*pubkey_hash_value_buffer = NULL;
	*pubkey_hash_value_buffer_size = 0;

	/* The `pubkey-hash` value is a byte string of the definite-length encoded CBOR array `hash-entry` */
	/* pubkey-hash-value: [ hash-alg-id, hash-value ] */
	ret = ENCLAVE_ATTESTER_ERR_NO_MEM;
	root = cbor_new_definite_array(2);
	if (!root)
		goto err;
	/* Note that since IANA assigns range of 0-63 to the hash function id, we can assume that uint8 is sufficient */
	if (!cbor_array_push(root, cbor_move(cbor_build_uint8(pubkey_hash_algo))))
		goto err;

	size_t hash_size = hash_size_of_algo(pubkey_hash_algo);
	if (hash_size == 0) {
		RTLS_FATAL(
			"failed to generate pubkey-hash-value buffer: unsupported hash algo id: %u\n",
			pubkey_hash_algo);
		ret = ENCLAVE_ATTESTER_ERR_INVALID;
		goto err;
	}

	if (!cbor_array_push(root, cbor_move(cbor_build_bytestring(pubkey_hash, hash_size))))
		goto err;

	*pubkey_hash_value_buffer_size = cbor_serialize_alloc(root, pubkey_hash_value_buffer, NULL);
	if (!*pubkey_hash_value_buffer_size)
		goto err;

	ret = ENCLAVE_ATTESTER_ERR_NONE;
err:
	if (root)
		cbor_decref(&root);
	return ret;
}

enclave_attester_err_t
dice_generate_claims_buffer(hash_algo_t pubkey_hash_algo, const uint8_t *pubkey_hash,
			    const claim_t *custom_claims, size_t custom_claims_length,
			    uint8_t **claims_buffer_out, size_t *claims_buffer_size_out)
{
	enclave_attester_err_t ret;
	cbor_item_t *root = NULL;
	uint8_t *pubkey_hash_value_buffer = NULL;
	size_t pubkey_hash_value_buffer_size = 0;

	/* claims-buffer: { "pubkey-hash" : h'<pubkey-hash-value>', "nonce" : h'<nonce-value>'} */
	/* Note that the nonce is optional, it's for per-session freshness, which we don't support it yet. */
	ret = ENCLAVE_ATTESTER_ERR_NO_MEM;
	root = cbor_new_definite_map(1 + custom_claims_length);
	if (!root)
		goto err;

	/* Prepare custom claim `pubkey-hash` and add to map */
	ret = dice_generate_pubkey_hash_value_buffer(pubkey_hash_algo, pubkey_hash,
						     &pubkey_hash_value_buffer,
						     &pubkey_hash_value_buffer_size);
	if (ret != ENCLAVE_ATTESTER_ERR_NONE)
		goto err;

	ret = ENCLAVE_ATTESTER_ERR_NO_MEM;
	if (!cbor_map_add(root, (struct cbor_pair) {
					.key = cbor_move(cbor_build_string(CLAIM_PUBLIC_KEY_HASH)),
					.value = cbor_move(cbor_build_bytestring(
						pubkey_hash_value_buffer,
						pubkey_hash_value_buffer_size)) }))
		goto err;
	free(pubkey_hash_value_buffer);
	pubkey_hash_value_buffer = NULL;

	/* Add all user-defined claims to map */
	ret = ENCLAVE_ATTESTER_ERR_NO_MEM;
	for (size_t i = 0; i < custom_claims_length; i++) {
		if (!cbor_map_add(root,
				  (struct cbor_pair) { .key = cbor_move(cbor_build_string(
							       custom_claims[i].name)),
						       .value = cbor_move(cbor_build_bytestring(
							       custom_claims[i].value,
							       custom_claims[i].value_size)) }))
			goto err;
	}

	/* Generate claims buffer */
	ret = ENCLAVE_ATTESTER_ERR_NO_MEM;
	*claims_buffer_size_out = cbor_serialize_alloc(root, claims_buffer_out, NULL);
	if (!*claims_buffer_size_out)
		goto err;

	ret = ENCLAVE_ATTESTER_ERR_NONE;
err:
	if (root)
		cbor_decref(&root);
	if (pubkey_hash_value_buffer)
		free(pubkey_hash_value_buffer);
	return ret;
}

enclave_attester_err_t dice_generate_evidence_buffer_with_tag(
	const attestation_evidence_t *evidence, const uint8_t *claims_buffer,
	const size_t claims_buffer_size, uint8_t **evidence_buffer_out,
	size_t *evidence_buffer_size_out)
{
	enclave_attester_err_t ret;
	cbor_item_t *root = NULL;
	cbor_item_t *array = NULL;

	/* evidence_buffer is a tagged CBOR definite-length array with two entries */
	/* evidence_buffer: <tag1>([ TEE_ECDSA_quote(customs-buffer-hash), claims-buffer ]) */
	ret = ENCLAVE_ATTESTER_ERR_INVALID;
	uint64_t tag_value = tag_of_evidence_type(evidence->type);
	if (!tag_value)
		goto err;

	ret = ENCLAVE_ATTESTER_ERR_NO_MEM;
	root = cbor_new_tag(tag_value);
	if (!root)
		goto err;
	array = cbor_new_definite_array(2);
	if (!array)
		goto err;

	ret = ENCLAVE_ATTESTER_ERR_INVALID;
	size_t evidence_raw_size = 0;
	const uint8_t *evidence_raw_ref = evidence_get_raw_as_ref(evidence, &evidence_raw_size);
	if (!evidence_raw_ref)
		goto err;

	ret = ENCLAVE_ATTESTER_ERR_NO_MEM;
	if (!cbor_array_push(array,
			     cbor_move(cbor_build_bytestring(evidence_raw_ref, evidence_raw_size))))
		goto err;
	if (!cbor_array_push(array,
			     cbor_move(cbor_build_bytestring(claims_buffer, claims_buffer_size))))
		goto err;
	cbor_tag_set_item(root, array);
	*evidence_buffer_size_out = cbor_serialize_alloc(root, evidence_buffer_out, NULL);
	if (!*evidence_buffer_size_out)
		goto err;

	ret = ENCLAVE_ATTESTER_ERR_NONE;
err:
	if (root)
		cbor_decref(&root);
	if (array)
		cbor_decref(&array);
	return ret;
}

enclave_attester_err_t dice_generate_endorsements_buffer_with_tag(
	const char *type, const attestation_endorsement_t *endorsements,
	uint8_t **endorsements_buffer_out, size_t *endorsements_buffer_size_out)
{
	enclave_attester_err_t ret;
	cbor_item_t *root = NULL;
	cbor_item_t *array = NULL;

	/* Currently we only support endorsements for SGX/TDX ECDSA mode */
	if (!strcmp(type, "sgx_ecdsa") || !strcmp(type, "tdx_ecdsa")) {
		/* endorsements_buffer is a tagged CBOR definite-length array with 8 or 9 entries. */
		/* endorsements_buffer: <tag1>([h'<VERSION>', h'<TCB_INFO>', h'<TCB_ISSUER_CHAIN>', h'<CRL_PCK_CERT>', h'<CRL_PCK_PROC_CA>', h'<CRL_ISSUER_CHAIN_PCK_CERT>', h'<QE_ID_INFO>', h'<QE_ID_ISSUER_CHAIN>', h'<CREATION_DATETIME>']) */
		ret = ENCLAVE_ATTESTER_ERR_INVALID;
		uint64_t tag_value = tag_of_evidence_type(type);
		if (!tag_value)
			goto err;

		ret = ENCLAVE_ATTESTER_ERR_NO_MEM;
		root = cbor_new_tag(tag_value);
		if (!root)
			goto err;

		/* For SGX/TDX ECDSA, the array contains 8 or 9 entries. However, we always generate 8 entries,
		 * since we currently do not support h'<CREATION_DATETIME>'. */
		array = cbor_new_definite_array(8);
		if (!array)
			goto err;

		/* h'<VERSION>' */
		if (!cbor_array_push(array,
				     cbor_move(cbor_build_uint32(endorsements->ecdsa.version))))
			goto err;
		/* h'<TCB_INFO>' */
		if (!cbor_array_push(array, cbor_move(cbor_build_bytestring(
						    (cbor_data)endorsements->ecdsa.tcb_info,
						    endorsements->ecdsa.tcb_info_size))))
			goto err;
		/* h'<TCB_ISSUER_CHAIN>' */
		if (!cbor_array_push(array,
				     cbor_move(cbor_build_bytestring(
					     (cbor_data)endorsements->ecdsa.tcb_info_issuer_chain,
					     endorsements->ecdsa.tcb_info_issuer_chain_size))))
			goto err;
		/* h'<CRL_PCK_CERT>' */
		if (!cbor_array_push(array, cbor_move(cbor_build_bytestring(
						    (cbor_data)endorsements->ecdsa.pck_crl,
						    endorsements->ecdsa.pck_crl_size))))
			goto err;
		/* h'<CRL_PCK_PROC_CA>' */
		if (!cbor_array_push(array, cbor_move(cbor_build_bytestring(
						    (cbor_data)endorsements->ecdsa.root_ca_crl,
						    endorsements->ecdsa.root_ca_crl_size))))
			goto err;
		/* h'<CRL_ISSUER_CHAIN_PCK_CERT>' */
		if (!cbor_array_push(array,
				     cbor_move(cbor_build_bytestring(
					     (cbor_data)endorsements->ecdsa.pck_crl_issuer_chain,
					     endorsements->ecdsa.pck_crl_issuer_chain_size))))
			goto err;
		/* h'<QE_ID_INFO>' */
		if (!cbor_array_push(array, cbor_move(cbor_build_bytestring(
						    (cbor_data)endorsements->ecdsa.qe_identity,
						    endorsements->ecdsa.qe_identity_size))))
			goto err;
		/* h'<QE_ID_ISSUER_CHAIN>' */
		if (!cbor_array_push(
			    array, cbor_move(cbor_build_bytestring(
					   (cbor_data)endorsements->ecdsa.qe_identity_issuer_chain,
					   endorsements->ecdsa.qe_identity_issuer_chain_size))))
			goto err;

		cbor_tag_set_item(root, array);
		*endorsements_buffer_size_out =
			cbor_serialize_alloc(root, endorsements_buffer_out, NULL);
		if (!*endorsements_buffer_size_out)
			goto err;
	} else {
		RTLS_FATAL(
			"Failed to generate endorsements buffer: unsupported evidence type: %s\n",
			type);
		ret = ENCLAVE_ATTESTER_ERR_INVALID;
		goto err;
	}

	ret = ENCLAVE_ATTESTER_ERR_NONE;
err:
	if (root)
		cbor_decref(&root);
	if (array)
		cbor_decref(&array);
	return ret;
}

/*
* DICE related verifier functions
*/

#define RATS_VERIFIER_CBOR_ASSERT_GOTO(statement, label)                             \
	{                                                                            \
		if (!(statement)) {                                                  \
			RTLS_ERR("Bad cbor data: assert '" #statement "' failed\n"); \
			ret = ENCLAVE_VERIFIER_ERR_CBOR;                             \
			goto label;                                                  \
		}                                                                    \
	}

#define RATS_VERIFIER_CBOR_ASSERT(statement) RATS_VERIFIER_CBOR_ASSERT_GOTO(statement, err)

#define RATS_VERIFIER_CBOR_COPY_BYTE_STRINGS(buffer_field, buffer_size_field, cbor_object)    \
	{                                                                                     \
		RATS_VERIFIER_CBOR_ASSERT(cbor_isa_bytestring(cbor_object));                  \
		RATS_VERIFIER_CBOR_ASSERT(cbor_bytestring_is_definite(cbor_object));          \
		buffer_size_field = cbor_bytestring_length(cbor_object);                      \
		buffer_field = malloc(buffer_size_field);                                     \
		if (!buffer_field) {                                                          \
			ret = ENCLAVE_VERIFIER_ERR_NO_MEM;                                    \
			goto err;                                                             \
		}                                                                             \
		memcpy(buffer_field, cbor_bytestring_handle(cbor_object), buffer_size_field); \
	}

enclave_verifier_err_t dice_parse_evidence_buffer_with_tag(const uint8_t *evidence_buffer,
							   size_t evidence_buffer_size,
							   attestation_evidence_t *evidence,
							   uint8_t **claims_buffer_out,
							   size_t *claims_buffer_size_out)
{
	enclave_verifier_err_t ret = ENCLAVE_VERIFIER_ERR_CBOR;

	cbor_item_t *root = NULL;
	cbor_item_t *array = NULL;
	cbor_item_t *array_0 = NULL;
	cbor_item_t *array_1 = NULL;
	uint8_t *claims_buffer = NULL;
	size_t claims_buffer_size = 0;

	*claims_buffer_out = NULL;
	*claims_buffer_size_out = 0;

	/* Parse evidence_buffer as cbor data: an encoded tagged CBOR definite-length array with two entries. */
	struct cbor_load_result result;
	root = cbor_load(evidence_buffer, evidence_buffer_size, &result);
	if (result.error.code != CBOR_ERR_NONE) {
		ret = result.error.code == CBOR_ERR_MEMERROR ? ENCLAVE_VERIFIER_ERR_NO_MEM :
							       ENCLAVE_VERIFIER_ERR_CBOR;
		RTLS_ERR("Failed to parse evidence_buffer as cbor data. pos: %zu\n",
			 result.error.position);
		goto err;
	}

	/* Check cbor tag */
	RATS_VERIFIER_CBOR_ASSERT(cbor_isa_tag(root));
	if (!tag_is_valid(cbor_tag_value(root))) {
		RTLS_ERR("Bad cbor data: invalid cbor tag got: 0x%zx\n", cbor_tag_value(root));
		goto err;
	}

	/* Size of array should be 2 */
	array = cbor_tag_item(root);
	RATS_VERIFIER_CBOR_ASSERT(cbor_isa_array(array));
	RATS_VERIFIER_CBOR_ASSERT(cbor_array_is_definite(array));

	ret = ENCLAVE_VERIFIER_ERR_CBOR;
	if (cbor_array_size(array) != 2) {
		RTLS_ERR("Bad cbor data: invalid evidence array length: %zu, should be 2\n",
			 cbor_array_size(array));
	}

	/* Recover evidence data */
	array_0 = cbor_array_get(array, 0);
	RATS_VERIFIER_CBOR_ASSERT(cbor_isa_bytestring(array_0));
	RATS_VERIFIER_CBOR_ASSERT(cbor_bytestring_is_definite(array_0));
	ret = ENCLAVE_VERIFIER_ERR_INVALID;
	if (evidence_from_raw(cbor_bytestring_handle(array_0), cbor_bytestring_length(array_0),
			      cbor_tag_value(root), evidence) != 0)
		goto err;

	/* The 2nd element is claims_buffer */
	array_1 = cbor_array_get(array, 1);
	RATS_VERIFIER_CBOR_ASSERT(cbor_isa_bytestring(array_1));
	RATS_VERIFIER_CBOR_ASSERT(cbor_bytestring_is_definite(array_1));
	claims_buffer_size = cbor_bytestring_length(array_1);

	claims_buffer = malloc(claims_buffer_size);
	if (!claims_buffer) {
		ret = ENCLAVE_VERIFIER_ERR_NO_MEM;
		goto err;
	}
	memcpy(claims_buffer, cbor_bytestring_handle(array_1), claims_buffer_size);

	*claims_buffer_out = claims_buffer;
	claims_buffer = NULL;
	*claims_buffer_size_out = claims_buffer_size;

	ret = ENCLAVE_VERIFIER_ERR_NONE;
err:
	if (array_0)
		cbor_decref(&array_0);
	if (array_1)
		cbor_decref(&array_1);
	if (array)
		cbor_decref(&array);
	if (root)
		cbor_decref(&root);
	if (claims_buffer)
		free(claims_buffer);
	return ret;
}

enclave_verifier_err_t
dice_parse_endorsements_buffer_with_tag(const char *type, const uint8_t *endorsements_buffer,
					size_t endorsements_buffer_size,
					attestation_endorsement_t *endorsements)
{
	enclave_verifier_err_t ret = ENCLAVE_VERIFIER_ERR_CBOR;

	cbor_item_t *root = NULL;
	cbor_item_t *array = NULL;
	cbor_item_t *array_i = NULL;

	/* Currently we only support endorsements for SGX/TDX ECDSA mode */
	if (!strcmp(type, "sgx_ecdsa") || !strcmp(type, "tdx_ecdsa")) {
		/* Parse endorsements_buffer as cbor data: an encoded tagged CBOR definite-length array with 8 entries. */
		struct cbor_load_result result;
		root = cbor_load(endorsements_buffer, endorsements_buffer_size, &result);
		if (result.error.code != CBOR_ERR_NONE) {
			ret = result.error.code == CBOR_ERR_MEMERROR ? ENCLAVE_VERIFIER_ERR_NO_MEM :
								       ENCLAVE_VERIFIER_ERR_CBOR;
			RTLS_ERR("Failed to parse endorsements_buffer as cbor data. pos: %zu\n",
				 result.error.position);
			goto err;
		}

		/* Check cbor tag */
		RATS_VERIFIER_CBOR_ASSERT(cbor_isa_tag(root));
		if (cbor_tag_value(root) != OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE) {
			/* We currently only support endorsements for SGX/TDX ECDSA. */
			RTLS_ERR("Bad cbor data: invalid cbor tag got: 0x%zx, 0x%zx expected\n",
				 cbor_tag_value(root), (uint64_t)OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE);
			goto err;
		}

		/* Size of array should be 8 or 9 */
		array = cbor_tag_item(root);
		RATS_VERIFIER_CBOR_ASSERT(cbor_isa_array(array));
		RATS_VERIFIER_CBOR_ASSERT(cbor_array_is_definite(array));

		ret = ENCLAVE_VERIFIER_ERR_CBOR;
		if (cbor_array_size(array) != 8 && cbor_array_size(array) != 9) {
			RTLS_ERR(
				"Bad cbor data: invalid endorsements array length: %zu, should be 8 or 9\n",
				cbor_array_size(array));
		}

		/* h'<VERSION>' */
		array_i = cbor_array_get(array, 0);
		RATS_VERIFIER_CBOR_ASSERT(cbor_isa_uint(array_i));
		RATS_VERIFIER_CBOR_ASSERT(cbor_int_get_width(array_i) == CBOR_INT_32);
		endorsements->ecdsa.version = cbor_get_uint32(array_i);
		cbor_decref(&array_i);

		/* h'<TCB_INFO>' */
		array_i = cbor_array_get(array, 1);
		RATS_VERIFIER_CBOR_COPY_BYTE_STRINGS(endorsements->ecdsa.tcb_info,
						     endorsements->ecdsa.tcb_info_size, array_i);
		cbor_decref(&array_i);

		/* h'<TCB_ISSUER_CHAIN>' */
		array_i = cbor_array_get(array, 2);
		RATS_VERIFIER_CBOR_COPY_BYTE_STRINGS(endorsements->ecdsa.tcb_info_issuer_chain,
						     endorsements->ecdsa.tcb_info_issuer_chain_size,
						     array_i);
		cbor_decref(&array_i);

		/* h'<CRL_PCK_CERT>' */
		array_i = cbor_array_get(array, 3);
		RATS_VERIFIER_CBOR_COPY_BYTE_STRINGS(endorsements->ecdsa.pck_crl,
						     endorsements->ecdsa.pck_crl_size, array_i);
		cbor_decref(&array_i);

		/* h'<CRL_PCK_PROC_CA>' */
		array_i = cbor_array_get(array, 4);
		RATS_VERIFIER_CBOR_COPY_BYTE_STRINGS(endorsements->ecdsa.root_ca_crl,
						     endorsements->ecdsa.root_ca_crl_size, array_i);
		cbor_decref(&array_i);

		/* h'<CRL_ISSUER_CHAIN_PCK_CERT>' */
		array_i = cbor_array_get(array, 5);
		RATS_VERIFIER_CBOR_COPY_BYTE_STRINGS(endorsements->ecdsa.pck_crl_issuer_chain,
						     endorsements->ecdsa.pck_crl_issuer_chain_size,
						     array_i);
		cbor_decref(&array_i);

		/* h'<QE_ID_INFO>' */
		array_i = cbor_array_get(array, 6);
		RATS_VERIFIER_CBOR_COPY_BYTE_STRINGS(endorsements->ecdsa.qe_identity,
						     endorsements->ecdsa.qe_identity_size, array_i);
		cbor_decref(&array_i);

		/* h'<QE_ID_ISSUER_CHAIN>' */
		array_i = cbor_array_get(array, 7);
		RATS_VERIFIER_CBOR_COPY_BYTE_STRINGS(
			endorsements->ecdsa.qe_identity_issuer_chain,
			endorsements->ecdsa.qe_identity_issuer_chain_size, array_i);
		cbor_decref(&array_i);

		/* We do'not support h'<CREATION_DATETIME>' here. */

		ret = ENCLAVE_VERIFIER_ERR_INVALID;
		uint64_t tag_value = tag_of_evidence_type(type);
		if (!tag_value)
			goto err;
	} else {
		RTLS_FATAL(
			"Failed to generate endorsements buffer: unsupported evidence type: %s\n",
			type);
		return ENCLAVE_VERIFIER_ERR_INVALID;
	}

	ret = ENCLAVE_VERIFIER_ERR_NONE;
err:
	if (ret != ENCLAVE_VERIFIER_ERR_NONE)
		/* When we fail, we need to do a cleanup. As this function is responsible for allocating memory for the endorsements. */
		free_endorsements(type, endorsements);
	if (array_i)
		cbor_decref(&array_i);
	if (array)
		cbor_decref(&array);
	if (root)
		cbor_decref(&root);
	return ret;
}

enclave_verifier_err_t dice_parse_pubkey_hash_value_buffer(const uint8_t *pubkey_hash_value_buffer,
							   size_t pubkey_hash_value_buffer_size,
							   hash_algo_t *pubkey_hash_algo_out,
							   uint8_t *pubkey_hash_out)
{
	enclave_verifier_err_t ret;
	cbor_item_t *root = NULL;
	cbor_item_t *array_0 = NULL;
	cbor_item_t *array_1 = NULL;

	/* The `pubkey-hash` value is a byte string of the definite-length encoded CBOR array `hash-entry` */
	struct cbor_load_result result;
	root = cbor_load(pubkey_hash_value_buffer, pubkey_hash_value_buffer_size, &result);
	if (result.error.code != CBOR_ERR_NONE) {
		ret = result.error.code == CBOR_ERR_MEMERROR ? ENCLAVE_VERIFIER_ERR_NO_MEM :
							       ENCLAVE_VERIFIER_ERR_CBOR;
		RTLS_ERR("Failed to parse pubkey_hash_value_buffer as cbor data. pos: %zu\n",
			 result.error.position);
		goto err;
	}
	RATS_VERIFIER_CBOR_ASSERT(cbor_isa_array(root));
	RATS_VERIFIER_CBOR_ASSERT(cbor_array_is_definite(root));

	ret = ENCLAVE_VERIFIER_ERR_CBOR;
	if (cbor_array_size(root) != 2) {
		RTLS_ERR(
			"Bad cbor data: invalid pubkey-hash-value array length: %zu, should be 2\n",
			cbor_array_size(root));
		goto err;
	}

	array_0 = cbor_array_get(root, 0);
	RATS_VERIFIER_CBOR_ASSERT(cbor_isa_uint(array_0));
	uint64_t hash_algo_id = cbor_get_int(array_0);

	size_t hash_size = hash_size_of_algo(hash_algo_id);
	if (hash_size == 0) {
		RTLS_ERR(
			"unsupported hash-alg-id: %lu, sha-256(1), sha-384(7), sha-512(8) are expected\n",
			hash_algo_id);
		ret = ENCLAVE_ATTESTER_ERR_INVALID;
		goto err;
	}

	array_1 = cbor_array_get(root, 1);
	RATS_VERIFIER_CBOR_ASSERT(cbor_isa_bytestring(array_1));
	RATS_VERIFIER_CBOR_ASSERT(cbor_bytestring_is_definite(array_1));

	if (cbor_bytestring_length(array_1) != hash_size) { /* sha256 */
		RTLS_ERR("unmatched hash value length: %zu, %zu expected\n",
			 cbor_bytestring_length(array_1), hash_size);
		ret = ENCLAVE_VERIFIER_ERR_INVALID;
		goto err;
	}

	memcpy(pubkey_hash_out, cbor_bytestring_handle(array_1), hash_size);
	*pubkey_hash_algo_out = hash_algo_id;

	ret = ENCLAVE_VERIFIER_ERR_NONE;
err:
	if (array_0)
		cbor_decref(&array_0);
	if (array_1)
		cbor_decref(&array_1);
	if (root)
		cbor_decref(&root);
	return ret;
}

/* Parse the claims buffer and return the custom claims and pubkey hash. Note that
 * the content of the claims buffer is untrusted user input, and its format match
 * the format defined by Interoperable RA-TLS.
 * 
 * claims_buffer: The claims buffer to be parsed.
 * claims_buffer_size: Size of claims buffer in bytes.
 * pubkey_hash_algo_out: The `hash_algo_id` of pubkey `hash-entry`
 * pubkey_hash_out: A buffer for writing pubkey hash to, should be large enough
 *     (MAX_HASH_SIZE) to write the hash.
 * custom_claims_out: The list of claims stored in the claims buffer, user-defined
 *     custom claims included only. The caller should manage its memory.
 * custom_claims_length_out: The length of claims list.
 *  */
enclave_verifier_err_t
dice_parse_claims_buffer(const uint8_t *claims_buffer, size_t claims_buffer_size,
			 hash_algo_t *pubkey_hash_algo_out, uint8_t *pubkey_hash_out,
			 claim_t **custom_claims_out, size_t *custom_claims_length_out)
{
	enclave_verifier_err_t ret;

	claim_t *custom_claims = NULL;
	size_t custom_claims_length = 0;

	*pubkey_hash_algo_out = HASH_ALGO_RESERVED;
	*custom_claims_out = NULL;
	*custom_claims_length_out = 0;

	cbor_item_t *root = NULL;

	/* Parse claims_buffer as cbor data: definite-length encoded CBOR map of one or two custom
	 * claims, with each claim name in text string format, and its value in byte string format. */
	struct cbor_load_result result;
	root = cbor_load(claims_buffer, claims_buffer_size, &result);
	if (result.error.code != CBOR_ERR_NONE) {
		ret = result.error.code == CBOR_ERR_MEMERROR ? ENCLAVE_VERIFIER_ERR_NO_MEM :
							       ENCLAVE_VERIFIER_ERR_CBOR;
		RTLS_ERR("Failed to parse claims_buffer as cbor data. pos: %zu\n",
			 result.error.position);
		goto err;
	}
	RATS_VERIFIER_CBOR_ASSERT(cbor_isa_map(root));
	RATS_VERIFIER_CBOR_ASSERT(cbor_map_is_definite(root));

	{
		bool found_pubkey_hash = false;

		/* Get claims from claims buffer */
		claim_t claims[cbor_map_size(root)];
		size_t count_claims = 0;
		struct cbor_pair *map_pairs = cbor_map_handle(root);
		for (size_t i = 0; i < cbor_map_size(root); i++) {
			cbor_item_t *key = map_pairs[i].key;
			cbor_item_t *value = map_pairs[i].value;
			RATS_VERIFIER_CBOR_ASSERT_GOTO(cbor_isa_string(key), err_claims);
			RATS_VERIFIER_CBOR_ASSERT_GOTO(cbor_string_is_definite(key), err_claims);
			RATS_VERIFIER_CBOR_ASSERT_GOTO(cbor_isa_bytestring(value), err_claims);
			RATS_VERIFIER_CBOR_ASSERT_GOTO(cbor_bytestring_is_definite(value),
						       err_claims);

			unsigned char *key_handle = cbor_string_handle(key);
			size_t key_length = cbor_string_length(key);
			unsigned char *value_handle = cbor_bytestring_handle(value);
			size_t value_length = cbor_bytestring_length(value);

			/* Check pubkey-hash */
			if (key_length == sizeof(CLAIM_PUBLIC_KEY_HASH) - 1 &&
			    !strncmp((char *)key_handle, CLAIM_PUBLIC_KEY_HASH, key_length)) {
				found_pubkey_hash = true;

				ret = dice_parse_pubkey_hash_value_buffer(value_handle,
									  value_length,
									  pubkey_hash_algo_out,
									  pubkey_hash_out);
				if (ret != ENCLAVE_VERIFIER_ERR_NONE)
					goto err_claims;

				/* The "pubkey-hash" is a internal claim and should not be returned to the user
				 * of rats-tls. So we "continue" here. */
				continue;
			}

			/* Put user-defined custom claims into the custom_claims list. */
			claim_t *claim = &claims[count_claims];
			/* NOTE: The cbor_string_handle(key) returns a non-null terminated string. And the
			 * cbor_string_length(key) doesn't count the terminating '\0' byte. */
			claim->name = (char *)malloc(key_length + 1);
			claim->value = (uint8_t *)malloc(value_length);
			if (!claim->name || !claim->value) {
				if (claim->name)
					free(claim->name);
				if (claim->value)
					free(claim->value);
				ret = ENCLAVE_VERIFIER_ERR_NO_MEM;
				RTLS_ERR(
					"failed to add claim from claims buffer with name '%.*s' length %zu\n",
					(int)key_length, key_handle, value_length);
				goto err_claims;
			}
			memcpy(claim->name, key_handle, key_length);
			claim->name[key_length] = '\0';
			memcpy(claim->value, value_handle, value_length);
			claim->value_size = value_length;

			count_claims++;
		}

		if (!found_pubkey_hash) {
			RTLS_ERR(
				"failed to find claim with name '%s' from claims list with length %zu\n",
				CLAIM_PUBLIC_KEY_HASH, cbor_map_size(root));
			ret = ENCLAVE_VERIFIER_ERR_INVALID;
			goto err_claims;
		}

		custom_claims = malloc(count_claims * sizeof(claim_t));
		if (!custom_claims) {
			ret = ENCLAVE_VERIFIER_ERR_NO_MEM;
			goto err_claims;
		}
		memcpy(custom_claims, claims, count_claims * sizeof(claim_t));
		custom_claims_length = count_claims;
		count_claims = 0;

		ret = ENCLAVE_VERIFIER_ERR_NONE;
	err_claims:
		for (size_t i = 0; i < count_claims; i++) {
			free(claims[i].name);
			free(claims[i].value);
		}
		if (ret != ENCLAVE_VERIFIER_ERR_NONE)
			goto err;
	}

	*custom_claims_out = custom_claims;
	custom_claims = NULL;
	*custom_claims_length_out = custom_claims_length;

	ret = ENCLAVE_VERIFIER_ERR_NONE;
err:
	if (custom_claims)
		free_claims_list(custom_claims, custom_claims_length);
	if (root)
		cbor_decref(&root);
	return ret;
}
