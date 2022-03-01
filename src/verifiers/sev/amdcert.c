/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include "amdcert.h"
#include "../sev-snp/utils.h"
#include "../sev-snp/crypto.c"

/* Return the size of amd cert in Bytes, NOT bits */
size_t amd_cert_get_size(const amd_cert *cert)
{
	size_t size = 0;
	uint32_t fixed_offset = offsetof(amd_cert, pub_exp);

	if (cert)
		size = fixed_offset + (cert->pub_exp_size + 2 * cert->modulus_size) / 8;

	return size;
}

/* Check key size in Bits, NOT Bytes */
static bool key_size_is_valid(size_t size)
{
	return (size == AMD_CERT_KEY_BITS_2K) || (size == AMD_CERT_KEY_BITS_4K);
}

int amd_cert_init(amd_cert *cert, const uint8_t *buffer)
{
	if (!cert || !buffer)
		return -1;

	memset(cert, 0, sizeof(*cert));

	/* 64 bytes */
	uint32_t pub_exp_offset = offsetof(amd_cert, pub_exp);
	memcpy(cert, buffer, pub_exp_offset);

	uint32_t modulus_offset = pub_exp_offset + (cert->pub_exp_size / 8);
	uint32_t sig_offset = modulus_offset + (cert->modulus_size / 8);

	/* Initialize the remainder of the certificate */
	memcpy(&cert->pub_exp, (void *)(buffer + pub_exp_offset), cert->pub_exp_size / 8);
	memcpy(&cert->modulus, (void *)(buffer + modulus_offset), cert->modulus_size / 8);
	memcpy(&cert->sig, (void *)(buffer + sig_offset), cert->modulus_size / 8);

	return 0;
}

static bool amd_cert_validate_sig(const amd_cert *cert, const amd_cert *parent,
				  enum ePSP_DEVICE_TYPE device_type)
{
	bool is_valid = false;

	if (!cert || !parent)
		return is_valid;

	hmac_sha_256 sha_digest_256;
	hmac_sha_512 sha_digest_384;
	SHA_TYPE algo = SHA_ALGO_256;
	uint8_t *sha_digest = NULL;
	size_t sha_length = 0;

	/* Set SHA_TYPE to 256 bit or 384 bit depending on device_type */
	switch (device_type) {
	case PSP_DEVICE_TYPE_NAPLES:
		algo = SHA_ALGO_256;
		sha_digest = sha_digest_256;
		sha_length = sizeof(hmac_sha_256);
		break;
	case PSP_DEVICE_TYPE_ROME:
	case PSP_DEVICE_TYPE_MILAN:
		algo = SHA_ALGO_384;
		sha_digest = sha_digest_384;
		sha_length = sizeof(hmac_sha_512);
		break;
	default:
		RTLS_ERR("unsupported device type\n");
		return is_valid;
	}

	memset(sha_digest, 0, sha_length);

	RSA *rsa_pub_key = RSA_new();

	/* Convert the parent to an RSA key to pass into RSA_verify */
	BIGNUM *modulus = BN_lebin2bn((uint8_t *)&parent->modulus, parent->modulus_size / 8, NULL);
	BIGNUM *pub_exp = BN_lebin2bn((uint8_t *)&parent->pub_exp, parent->pub_exp_size / 8, NULL);

	if (RSA_set0_key(rsa_pub_key, modulus, pub_exp, NULL) != 1)
		goto err;

	uint32_t digest_len = 0;
	uint32_t fixed_offset = offsetof(amd_cert, pub_exp);
	EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
	if (EVP_DigestInit(md_ctx, (algo == SHA_ALGO_256) ? EVP_sha256() : EVP_sha384()) <= 0)
		goto err;
	if (EVP_DigestUpdate(md_ctx, cert, fixed_offset) <= 0)
		goto err;
	if (EVP_DigestUpdate(md_ctx, &cert->pub_exp, cert->pub_exp_size / 8) <= 0)
		goto err;
	if (EVP_DigestUpdate(md_ctx, &cert->modulus, cert->modulus_size / 8) <= 0)
		goto err;
	EVP_DigestFinal(md_ctx, sha_digest, &digest_len);

	/* Swap the bytes of the signature */
	uint8_t signature[AMD_CERT_KEY_BYTES_4K] = { 0 };
	memcpy(signature, &cert->sig, parent->modulus_size / 8);
	if (!reverse_bytes(signature, parent->modulus_size / 8))
		goto err;

	uint8_t decrypted[AMD_CERT_KEY_BYTES_4K] = { 0 };
	/* Verify the signature. Start by a RAW decrypt of the signature */
	if (RSA_public_decrypt(cert->modulus_size / 8, signature, decrypted, rsa_pub_key,
			       RSA_NO_PADDING) == -1)
		goto err;

	/* Verify the data. SLen of -2 means salt length is recovered from the signature. */
	if (RSA_verify_PKCS1_PSS(rsa_pub_key, sha_digest,
				 (algo == SHA_ALGO_256) ? EVP_sha256() : EVP_sha384(), decrypted,
				 -2) != 1)
		goto err;

	is_valid = true;

err:
	if (rsa_pub_key)
		RSA_free(rsa_pub_key);

	if (md_ctx)
		EVP_MD_CTX_free(md_ctx);

	return is_valid;
}

static bool amd_cert_validate_common(const amd_cert *cert)
{
	if (!cert)
		return false;

	if (cert->version != AMD_CERT_VERSION || !key_size_is_valid(cert->modulus_size) ||
	    !key_size_is_valid(cert->pub_exp_size))
		return false;

	return true;
}

static bool amd_cert_validate(const amd_cert *cert, const amd_cert *parent,
			      AMD_SIG_USAGE expected_usage, enum ePSP_DEVICE_TYPE device_type)
{
	if (!cert || !parent || cert->key_usage != expected_usage)
		return false;

	/* Validate the signature before using any certificate fields */
	if (!amd_cert_validate_sig(cert, parent, device_type)) {
		RTLS_ERR("failed to validate signature of amd cert\n");
		return false;
	}

	/* Validate the fixed data */
	if (!amd_cert_validate_common(cert)) {
		RTLS_ERR("failed to validate fixed data of amd cert\n");
		return false;
	}

	return true;
}

bool amd_cert_validate_ask(const amd_cert *ask, const amd_cert *ark,
			   enum ePSP_DEVICE_TYPE device_type)
{
	if (!ask || !ark)
		return false;

	return amd_cert_validate(ask, ark, AMD_USAGE_ASK, device_type);
}

bool amd_cert_validate_ark(const amd_cert *ark, enum ePSP_DEVICE_TYPE device_type)
{
	if (!ark)
		return false;

	/* Validate the certificate. Check for self-signed ARK */
	if (!amd_cert_validate(ark, ark, AMD_USAGE_ARK, device_type)) {
		/* For Naples, not a self-signed ARK. Check the ARK without a signature. */
		if (!amd_cert_validate(ark, NULL, AMD_USAGE_ARK, device_type))
			return false;
	}

	const uint8_t *amd_root_key_id = NULL;
	if (device_type == PSP_DEVICE_TYPE_NAPLES)
		amd_root_key_id = amd_root_key_id_naples;
	else if (device_type == PSP_DEVICE_TYPE_ROME)
		amd_root_key_id = amd_root_key_id_rome;
	else if (device_type == PSP_DEVICE_TYPE_MILAN)
		amd_root_key_id = amd_root_key_id_milan;
	else {
		RTLS_ERR("unsupported device type %d\n", device_type);
		return false;
	}

	if (memcmp(&ark->key_id_0, amd_root_key_id, sizeof(ark->key_id_0 + ark->key_id_1)) != 0)
		return false;

	return true;
}

/* The verify_sev_cert function takes in a parent of an sev_cert not
 *   an amd_cert, so need to pull the pubkey out of the amd_cert and
 *   place it into a tmp sev_cert to help validate the cek
 */
int amd_cert_export_pub_key(const amd_cert *cert, sev_cert *pub_key_cert)
{
	if (!cert || !pub_key_cert) {
		return -1;
	}

	memset(pub_key_cert, 0, sizeof(*pub_key_cert));

	if (cert->modulus_size == AMD_CERT_KEY_BITS_2K) {
		pub_key_cert->pub_key_algo = SEV_SIG_ALGO_RSA_SHA256;
	} else if (cert->modulus_size == AMD_CERT_KEY_BITS_4K) {
		pub_key_cert->pub_key_algo = SEV_SIG_ALGO_RSA_SHA384;
	} else {
		RTLS_ERR("unsupported modulus size\n");
		return -1;
	}

	pub_key_cert->pub_key_usage = cert->key_usage;
	pub_key_cert->pub_key.rsa.modulus_size = cert->modulus_size;
	memcpy(pub_key_cert->pub_key.rsa.pub_exp, &cert->pub_exp, cert->pub_exp_size / 8);
	memcpy(pub_key_cert->pub_key.rsa.modulus, &cert->modulus, cert->modulus_size / 8);

	return 0;
}
