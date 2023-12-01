/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/ts.h>
#include <openssl/ecdh.h>
#include <rats-tls/log.h>
#include <rats-tls/attester.h>
#include "sevcert.h"
#include "../sev-snp/crypto.h"
#include "../sev-snp/utils.h"

#define SEV_CERT_MAX_SIGNATURES 2
#define SEV_CERT_MAX_VERSION	1

static bool validate_usage(uint32_t usage)
{
	switch (usage) {
	case SEV_USAGE_ARK:
	case SEV_USAGE_ASK:
	case SEV_USAGE_OCA:
	case SEV_USAGE_PEK:
	case SEV_USAGE_PDH:
	case SEV_USAGE_CEK:
		return true;
	default:
		RTLS_ERR("unsupported sev usage\n");
	}

	return false;
}

/* Validates the body (version through and including reserved1) of
 * an sev_cert. Separate functions are used to validate the pubkey
 * and the sigs.
 */
static bool validate_body(const sev_cert *cert)
{
	if (!cert)
		return false;

	if ((cert->version == 0) || (cert->version > SEV_CERT_MAX_VERSION)) {
		RTLS_ERR("invalid sev certificate version %d\n", cert->version);
		return false;
	}

	return true;
}

/* When a .cert file is imported, the PubKey is in sev_cert format. This
 * function converts that format into a EVP_PKEY format where it can be
 * used by other openssl functions.
 */
static int compile_public_key_from_certificate(const sev_cert *cert, EVP_PKEY *evp_pub_key)
{
	int cmd_ret = -1;
	if (!cert || !evp_pub_key)
		return cmd_ret;

	RSA *rsa_pub_key = NULL;
	EC_KEY *ec_pub_key = NULL;
	BIGNUM *x_big_num = NULL;
	BIGNUM *y_big_num = NULL;
	BIGNUM *modulus = NULL;
	BIGNUM *pub_exp = NULL;

	switch (cert->pub_key_algo) {
	case SEV_SIG_ALGO_RSA_SHA256:
	case SEV_SIG_ALGO_RSA_SHA384:
		rsa_pub_key = RSA_new();

		modulus = BN_lebin2bn((uint8_t *)&cert->pub_key.rsa.modulus,
				      cert->pub_key.rsa.modulus_size / 8, NULL);
		pub_exp = BN_lebin2bn((uint8_t *)&cert->pub_key.rsa.pub_exp,
				      cert->pub_key.rsa.modulus_size / 8, NULL); // e
		if (RSA_set0_key(rsa_pub_key, modulus, pub_exp, NULL) != 1)
			goto err;

		/* Create a public EVP_PKEY from the public RSA_KEY
         * This function links evp_pub_key to rsa_pub_key, so when evp_pub_key
         * is freed, rsa_pub_key is freed. We don't want the user to have to
         * manage 2 keys, so just return EVP_PKEY and make sure user free's it
         */
		if (EVP_PKEY_assign_RSA(evp_pub_key, rsa_pub_key) != 1)
			goto err;
		break;
	case SEV_SIG_ALGO_ECDSA_SHA256:
	case SEV_SIG_ALGO_ECDSA_SHA384:
	case SEV_SIG_ALGO_ECDH_SHA256:
	case SEV_SIG_ALGO_ECDH_SHA384:
		if ((cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA256) ||
		    (cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA384)) {
			x_big_num = BN_lebin2bn(cert->pub_key.ecdsa.qx,
						sizeof(cert->pub_key.ecdsa.qx), NULL);
			y_big_num = BN_lebin2bn(cert->pub_key.ecdsa.qy,
						sizeof(cert->pub_key.ecdsa.qy), NULL);
		} else if ((cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA256) ||
			   (cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA384)) {
			x_big_num = BN_lebin2bn(cert->pub_key.ecdh.qx,
						sizeof(cert->pub_key.ecdh.qx), NULL);
			y_big_num = BN_lebin2bn(cert->pub_key.ecdh.qy,
						sizeof(cert->pub_key.ecdh.qy), NULL);
		}

		int nid = EC_curve_nist2nid("P-384");

		/* Create/allocate memory for an EC_KEY object using the NID above */
		if (!(ec_pub_key = EC_KEY_new_by_curve_name(nid)))
			goto err;
		/* Store the x and y coordinates of the public key */
		if (EC_KEY_set_public_key_affine_coordinates(ec_pub_key, x_big_num, y_big_num) != 1)
			goto err;
		/* Make sure the key is good */
		if (EC_KEY_check_key(ec_pub_key) != 1)
			goto err;

		/* Create a public EVP_PKEY from the public EC_KEY
         * This function links evp_pub_key to ec_pub_key, so when evp_pub_key
         *  is freed, ec_pub_key is freed. We don't want the user to have to
         *  manage 2 keys, so just return EVP_PKEY and make sure user free's it
         */
		if (EVP_PKEY_assign_EC_KEY(evp_pub_key, ec_pub_key) != 1)
			goto err;
		break;
	default:
		RTLS_ERR("unsupported sev sig algo\n");
		goto err;
	}

	if (!evp_pub_key)
		goto err;

	cmd_ret = 0;

err:
	/* Free memory if it was allocated.
	 * Don't free modulus and pub_exp here. 
	 * RSA key is associated with these.
	 */
	BN_free(y_big_num);
	BN_free(x_big_num);

	return cmd_ret;
}

/* [child_cert] is which we want to validate the signature of.
 * [parent_cert] tells us the algo used to sign the child cert
 * [parent_signing_key] used to validate the hash of the child cert
 * for example: child_cert = PEK. parent_cert = OCA. parent_signing_key = OCA PubKey
 */
static bool validate_signature(const sev_cert *child_cert, const sev_cert *parent_cert,
			       EVP_PKEY *parent_signing_key)
{
	if (!child_cert || !parent_cert || !parent_signing_key)
		return false;

	sev_sig cert_sig[SEV_CERT_MAX_SIGNATURES] = { child_cert->sig_1, child_cert->sig_2 };
	uint32_t cert_sig_algo[SEV_CERT_MAX_SIGNATURES] = { child_cert->sig_1_algo,
							    child_cert->sig_2_algo };
	uint32_t cert_sig_usage[SEV_CERT_MAX_SIGNATURES] = { child_cert->sig_1_usage,
							     child_cert->sig_2_usage };
	hmac_sha_256 sha256_digest;
	hmac_sha_384 sha384_digest;
	SHA_TYPE hash_algo;
	uint8_t *hash = NULL;
	size_t hash_len = 0;

	/* Determine if SHA_TYPE is 256 bit or 384 bit */
	switch (parent_cert->pub_key_algo) {
	case SEV_SIG_ALGO_RSA_SHA256:
	case SEV_SIG_ALGO_ECDSA_SHA256:
	case SEV_SIG_ALGO_ECDH_SHA256:
		hash_algo = SHA_ALGO_256;
		hash = sha256_digest;
		hash_len = sizeof(hmac_sha_256);
		break;
	case SEV_SIG_ALGO_RSA_SHA384:
	case SEV_SIG_ALGO_ECDSA_SHA384:
	case SEV_SIG_ALGO_ECDH_SHA384:
		hash_algo = SHA_ALGO_384;
		hash = sha384_digest;
		hash_len = sizeof(hmac_sha_384);
		break;
	default:
		RTLS_ERR("unsupported signing key algo! %x\n", parent_cert->pub_key_algo);
		return false;
	}

	uint32_t pub_key_offset = offsetof(sev_cert, sig_1_usage);
	if (!digest_sha((uint8_t *)child_cert, pub_key_offset, hash, hash_len, hash_algo))
		return false;

	/* Use the pub_key in sig[i] arg to decrypt the sig in child_cert arg
	 * Try both sigs in child_cert, to see if either of them match. 
	 * In PEK, CEK and OCA can be in any order
	 */
	bool found_match = false;
	int i = 0;
	for (i = 0; i < SEV_CERT_MAX_SIGNATURES; i++) {
		if ((parent_cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA256) ||
		    (parent_cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA384)) {
			uint32_t sig_len = parent_cert->pub_key.rsa.modulus_size / 8;
			uint8_t decrypted[4096] = { 0 };
			uint8_t signature[4096] = { 0 };

			RSA *rsa_pub_key = EVP_PKEY_get1_RSA(parent_signing_key);
			if (!rsa_pub_key) {
				RTLS_ERR("bad parent signing key\n");
				break;
			}

			/* Swap the bytes of the signature */
			memcpy(signature, &cert_sig[i].rsa,
			       parent_cert->pub_key.rsa.modulus_size / 8);
			if (!reverse_bytes(signature, parent_cert->pub_key.rsa.modulus_size / 8))
				break;

			if (RSA_public_decrypt(sig_len, signature, decrypted, rsa_pub_key,
					       RSA_NO_PADDING) == -1)
				break;

			if (RSA_verify_PKCS1_PSS(rsa_pub_key, hash,
						 (parent_cert->pub_key_algo ==
						  SEV_SIG_ALGO_RSA_SHA256) ?
							 EVP_sha256() :
							 EVP_sha384(),
						 decrypted, -2) != 1) {
				RSA_free(rsa_pub_key);
				continue;
			}

			found_match = true;
			RSA_free(rsa_pub_key);
			break;
		} else if ((parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA256) ||
			   (parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA384) ||
			   (parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA256) ||
			   (parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA384)) {
			ECDSA_SIG *tmp_ecdsa_sig = ECDSA_SIG_new();
			BIGNUM *r_big_num = BN_new();
			BIGNUM *s_big_num = BN_new();

			r_big_num = BN_lebin2bn(cert_sig[i].ecdsa.r, 72, r_big_num);
			s_big_num = BN_lebin2bn(cert_sig[i].ecdsa.s, 72, s_big_num);

			/* Calling ECDSA_SIG_set0() transfers the memory management of the values to
			 * the ECDSA_SIG object, and therefore the values that have been passed
			 * in should not be freed directly after this function has been called。
			 */
			if (ECDSA_SIG_set0(tmp_ecdsa_sig, r_big_num, s_big_num) != 1) {
				BN_free(s_big_num);
				BN_free(r_big_num);
				ECDSA_SIG_free(tmp_ecdsa_sig);
				continue;
			}
			EC_KEY *tmp_ec_key = EVP_PKEY_get1_EC_KEY(parent_signing_key);
			if (ECDSA_do_verify(hash, (uint32_t)hash_len, tmp_ecdsa_sig, tmp_ec_key) !=
			    1) {
				EC_KEY_free(tmp_ec_key);
				ECDSA_SIG_free(tmp_ecdsa_sig);
				continue;
			}

			found_match = true;
			EC_KEY_free(tmp_ec_key);
			ECDSA_SIG_free(tmp_ecdsa_sig);
			break;
		} else {
			RTLS_ERR("unsupported signing key algo! %x\n", parent_cert->pub_key_algo);
			return false;
		}
	}

	if (!found_match)
		return false;

	if ((cert_sig_algo[i] != parent_cert->pub_key_algo) ||
	    (cert_sig_usage[i] != parent_cert->pub_key_usage))
		return false;

	return true;
}

/* [parent_cert1][parent_cert2] these are used to validate the 1 or 2 signatures in the child cert.
 * Assumes parent_cert1 is always valid, and parent_cert2 may be valid.
 */
bool verify_sev_cert(const sev_cert *child_cert, const sev_cert *parent_cert1,
		     const sev_cert *parent_cert2)
{
	RTLS_DEBUG("child_cert %p, parent_cert1 %p, parent_cert2 %p\n", child_cert, parent_cert1,
		   parent_cert2);

	bool is_valid = false;

	if (!child_cert || !parent_cert1)
		return is_valid;

	EVP_PKEY *parent_pub_key[SEV_CERT_MAX_SIGNATURES] = { NULL };
	const sev_cert *parent_cert[SEV_CERT_MAX_SIGNATURES] = { parent_cert1, parent_cert2 };

	/* Get the public key from parent certs */
	int i = 0;
	int numSigs = (parent_cert1 && parent_cert2) ? 2 : 1;

	for (i = 0; i < numSigs; i++) {
		if (!(parent_pub_key[i] = EVP_PKEY_new()))
			goto err;

		/* This function allocates memory and attaches an EC_Key
		 * to your EVP_PKEY so, to prevent mem leaks, make sure
		 * the EVP_PKEY is freed at the end of this function.
		 */
		if (compile_public_key_from_certificate(parent_cert[i], parent_pub_key[i]) != 0)
			goto err;

		/* Validate the signature */
		if (!validate_signature(child_cert, parent_cert[i], parent_pub_key[i])) {
			RTLS_ERR("failed to validate signature\n");
			goto err;
		}
	}

	if (i != numSigs)
		goto err;

	/* Validate the certificate body */
	if (!validate_body(child_cert))
		goto err;

	// Although the signature was valid, ensure that the certificate
	// was signed with the proper key(s) in the correct order
	switch (child_cert->pub_key_usage) {
	case SEV_USAGE_PDH:
		/* The PDH certificate must be signed by the PEK */
		if (parent_cert1->pub_key_usage != SEV_USAGE_PEK)
			goto err;
		break;
	case SEV_USAGE_PEK:
		/* The PEK certificate must be signed by the CEK and the OCA */
		if (((parent_cert1->pub_key_usage != SEV_USAGE_OCA) &&
		     (parent_cert2->pub_key_usage != SEV_USAGE_CEK)) &&
		    ((parent_cert2->pub_key_usage != SEV_USAGE_OCA) &&
		     (parent_cert1->pub_key_usage != SEV_USAGE_CEK)))
			goto err;
		break;
	case SEV_USAGE_OCA:
		/* The OCA certificate must be self-signed */
		if (parent_cert1->pub_key_usage != SEV_USAGE_OCA)
			goto err;
		break;
	case SEV_USAGE_CEK:
		/* The CEK must be signed by the ASK */
		if (parent_cert1->pub_key_usage != SEV_USAGE_ASK)
			goto err;
		break;
	default:
		RTLS_ERR("unsupported pub_key_usage %d\n", child_cert->pub_key_usage);
		goto err;
	}

	is_valid = true;

err:
	/* Free memory */
	for (int i = 0; i < SEV_CERT_MAX_SIGNATURES; i++) {
		EVP_PKEY_free(parent_pub_key[i]);
	}

	return is_valid;
}

bool validate_attestation(sev_cert *pek, sev_attestation_report *report)
{
	bool is_valid = false;

	EVP_PKEY *pek_pub_key = NULL;
	if (!(pek_pub_key = EVP_PKEY_new()))
		return is_valid;

	/* This function allocates memory and attaches an EC_Key
	 * to your EVP_PKEY so, to prevent mem leaks, make sure
	 * the EVP_PKEY is freed at the end of this function.
	 */
	if (compile_public_key_from_certificate(pek, pek_pub_key) != 0)
		goto err;

	/* Validate the attestation report */
	if (!verify_message((sev_sig *)&report->sig1, &pek_pub_key, (const uint8_t *)report,
			    offsetof(sev_attestation_report, sig_usage), SEV_SIG_ALGO_ECDSA_SHA256))
		goto err;

	is_valid = true;

err:
	EVP_PKEY_free(pek_pub_key);

	return is_valid;
}
