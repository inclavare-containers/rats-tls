/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rats-tls/log.h>
#include <rats-tls/attester.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include "hygoncert.h"

/*********************************************************************
 **************   SM2 interface from BabaSSL/openssl   ***************
 *********************************************************************/

// SM2 function codes.
#define SM2_F_PKEY_SM2_COPY		115
#define SM2_F_PKEY_SM2_CTRL		109
#define SM2_F_PKEY_SM2_CTRL_STR		110
#define SM2_F_PKEY_SM2_DIGEST_CUSTOM	114
#define SM2_F_PKEY_SM2_INIT		111
#define SM2_F_PKEY_SM2_SIGN		112
#define SM2_F_SM2_COMPUTE_KEY		116
#define SM2_F_SM2_COMPUTE_MSG_HASH	100
#define SM2_F_SM2_COMPUTE_USERID_DIGEST 101
#define SM2_F_SM2_COMPUTE_Z_DIGEST	113
#define SM2_F_SM2_DECRYPT		102
#define SM2_F_SM2_ENCRYPT		103
#define SM2_F_SM2_PLAINTEXT_SIZE	104
#define SM2_F_SM2_SIGN			105
#define SM2_F_SM2_SIG_GEN		106
#define SM2_F_SM2_SIG_VERIFY		107
#define SM2_F_SM2_VERIFY		108

// SM2 reason codes.
#define SM2_R_ASN1_ERROR	  100
#define SM2_R_BAD_SIGNATURE	  101
#define SM2_R_BUFFER_TOO_SMALL	  107
#define SM2_R_DIST_ID_TOO_LARGE	  110
#define SM2_R_ID_NOT_SET	  112
#define SM2_R_ID_TOO_LARGE	  111
#define SM2_R_INVALID_CURVE	  108
#define SM2_R_INVALID_DIGEST	  102
#define SM2_R_INVALID_DIGEST_TYPE 103
#define SM2_R_INVALID_ENCODING	  104
#define SM2_R_INVALID_FIELD	  105
#define SM2_R_NO_PARAMETERS_SET	  109
#define SM2_R_NO_PRIVATE_VALUE	  113
#define SM2_R_USER_ID_TOO_LARGE	  106

/**
 * copy from BabaSSL
 *
 * Params:
 * 	out    [out]:
 * 	digest  [in]:
 * 	id      [in]:
 * 	id_len  [in]:
 * 	key     [in]:
 * Return:
 * 	1: success
 * 	0: fail
 */
int sm2_compute_z_digest(uint8_t *out, const EVP_MD *digest, const uint8_t *id, const size_t id_len,
			 const EC_KEY *key)
{
	int rc = 0;
	const EC_GROUP *group = EC_KEY_get0_group(key);
	BN_CTX *ctx = NULL;
	EVP_MD_CTX *hash = NULL;
	BIGNUM *p = NULL;
	BIGNUM *a = NULL;
	BIGNUM *b = NULL;
	BIGNUM *xG = NULL;
	BIGNUM *yG = NULL;
	BIGNUM *xA = NULL;
	BIGNUM *yA = NULL;
	int p_bytes = 0;
	uint8_t *buf = NULL;
	uint16_t entl = 0;
	uint8_t e_byte = 0;

	hash = EVP_MD_CTX_new();
	ctx = BN_CTX_new();
	if (hash == NULL || ctx == NULL) {
		SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
		goto done;
	}

	p = BN_CTX_get(ctx);
	a = BN_CTX_get(ctx);
	b = BN_CTX_get(ctx);
	xG = BN_CTX_get(ctx);
	yG = BN_CTX_get(ctx);
	xA = BN_CTX_get(ctx);
	yA = BN_CTX_get(ctx);

	if (yA == NULL) {
		SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
		goto done;
	}

	if (!EVP_DigestInit(hash, digest)) {
		SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
		goto done;
	}

	/* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */

	if (id_len >= (UINT16_MAX / 8)) {
		/* too large */
		SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, SM2_R_ID_TOO_LARGE);
		goto done;
	}

	entl = (uint16_t)(8 * id_len);

	e_byte = entl >> 8;
	if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
		SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
		goto done;
	}
	e_byte = entl & 0xFF;
	if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
		SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
		goto done;
	}

	if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
		SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
		goto done;
	}

	if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
		SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EC_LIB);
		goto done;
	}

	p_bytes = BN_num_bytes(p);
	buf = OPENSSL_zalloc(p_bytes);
	if (buf == NULL) {
		SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
		goto done;
	}

	if (BN_bn2binpad(a, buf, p_bytes) < 0 || !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    BN_bn2binpad(b, buf, p_bytes) < 0 || !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    !EC_POINT_get_affine_coordinates(group, EC_GROUP_get0_generator(group), xG, yG, ctx) ||
	    BN_bn2binpad(xG, buf, p_bytes) < 0 || !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    BN_bn2binpad(yG, buf, p_bytes) < 0 || !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    !EC_POINT_get_affine_coordinates(group, EC_KEY_get0_public_key(key), xA, yA, ctx) ||
	    BN_bn2binpad(xA, buf, p_bytes) < 0 || !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    BN_bn2binpad(yA, buf, p_bytes) < 0 || !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    !EVP_DigestFinal(hash, out, NULL)) {
		SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_INTERNAL_ERROR);
		goto done;
	}

	rc = 1;

	RTLS_DEBUG("[VERIFY] %s %d: ret %d\n", __func__, __LINE__, rc);
done:
	OPENSSL_free(buf);
	BN_CTX_free(ctx);
	EVP_MD_CTX_free(hash);
	return rc;
}

/**
 * Copy from BabaSSL
 *
 * Params:
 * 	key [in]:
 * 	sig [in]:
 * 	e   [in]:
 * Return:
 * 	1: success
 * 	0: fail
 */
static int sm2_sig_verify(const EC_KEY *key, const ECDSA_SIG *sig, const BIGNUM *e)
{
	int ret = 0;
	const EC_GROUP *group = EC_KEY_get0_group(key);
	const BIGNUM *order = EC_GROUP_get0_order(group);
	BN_CTX *ctx = NULL;
	EC_POINT *pt = NULL;
	BIGNUM *t = NULL;
	BIGNUM *x1 = NULL;
	const BIGNUM *r = NULL;
	const BIGNUM *s = NULL;

	ctx = BN_CTX_new();
	pt = EC_POINT_new(group);
	if (ctx == NULL || pt == NULL) {
		SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_MALLOC_FAILURE);
		goto done;
	}

	BN_CTX_start(ctx);
	t = BN_CTX_get(ctx);
	x1 = BN_CTX_get(ctx);
	if (x1 == NULL) {
		SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_MALLOC_FAILURE);
		goto done;
	}

	/*
     * B1: verify whether r' in [1,n-1], verification failed if not
     * B2: verify whether s' in [1,n-1], verification failed if not
     * B3: set M'~=ZA || M'
     * B4: calculate e'=Hv(M'~)
     * B5: calculate t = (r' + s') modn, verification failed if t=0
     * B6: calculate the point (x1', y1')=[s']G + [t]PA
     * B7: calculate R=(e'+x1') modn, verification pass if yes, otherwise failed
     */

	ECDSA_SIG_get0(sig, &r, &s);

	if (BN_cmp(r, BN_value_one()) < 0 || BN_cmp(s, BN_value_one()) < 0 ||
	    BN_cmp(order, r) <= 0 || BN_cmp(order, s) <= 0) {
		SM2err(SM2_F_SM2_SIG_VERIFY, SM2_R_BAD_SIGNATURE);
		goto done;
	}

	if (!BN_mod_add(t, r, s, order, ctx)) {
		SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_BN_LIB);
		goto done;
	}

	if (BN_is_zero(t)) {
		SM2err(SM2_F_SM2_SIG_VERIFY, SM2_R_BAD_SIGNATURE);
		goto done;
	}

	if (!EC_POINT_mul(group, pt, s, EC_KEY_get0_public_key(key), t, ctx) ||
	    !EC_POINT_get_affine_coordinates(group, pt, x1, NULL, ctx)) {
		SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_EC_LIB);
		goto done;
	}

	if (!BN_mod_add(t, e, x1, order, ctx)) {
		SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_BN_LIB);
		goto done;
	}

	if (BN_cmp(r, t) == 0)
		ret = 1;

	RTLS_DEBUG("[VERIFY] %s %d: ret %d\n", __func__, __LINE__, ret);
done:
	EC_POINT_free(pt);
	BN_CTX_free(ctx);
	return ret;
}

/**
 * Copy from BabaSSL
 *
 * Params:
 * 	digest  [in]:
 * 	key     [in]:
 * 	id      [in]:
 * 	id_len  [in]:
 * 	msg     [in]:
 * 	msg_len [in]:
 * Return:
 * 	BIGNUM point: success
 * 	        NULL: fail
 */
static BIGNUM *sm2_compute_msg_hash(const EVP_MD *digest, const EC_KEY *key, const uint8_t *id,
				    const size_t id_len, const uint8_t *msg, size_t msg_len)
{
	EVP_MD_CTX *hash = EVP_MD_CTX_new();
	const int md_size = EVP_MD_size(digest);
	uint8_t *z = NULL;
	BIGNUM *e = NULL;

	if (md_size < 0) {
		SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, SM2_R_INVALID_DIGEST);
		goto done;
	}

	z = OPENSSL_zalloc(md_size);
	if (hash == NULL || z == NULL) {
		SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, ERR_R_MALLOC_FAILURE);
		goto done;
	}

	if (!sm2_compute_z_digest(z, digest, id, id_len, key)) {
		/* SM2err already called */
		goto done;
	}

	if (!EVP_DigestInit(hash, digest) || !EVP_DigestUpdate(hash, z, md_size) ||
	    !EVP_DigestUpdate(hash, msg, msg_len)
	    /* reuse z buffer to hold H(Z || M) */
	    || !EVP_DigestFinal(hash, z, NULL)) {
		SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, ERR_R_EVP_LIB);
		goto done;
	}

	e = BN_bin2bn(z, md_size, NULL);
	if (e == NULL)
		SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, ERR_R_INTERNAL_ERROR);

	RTLS_DEBUG("[VERIFY] %s %d: BIGNUM e=%p\n", __func__, __LINE__, e);
done:
	OPENSSL_free(z);
	EVP_MD_CTX_free(hash);
	return e;
}

/**
 * Copy from BabaSSL
 *
 * Params:
 * 	key [in]:
 * 	digest [in]:
 * 	sig [in]:
 * 	id [in]:
 * 	id_len [in]:
 * 	msg [in]:
 * 	msg_len [in]:
 * Return:
 * 	1: success
 * 	0: fail
 */
int sm2_do_verify(const EC_KEY *key, const EVP_MD *digest, const ECDSA_SIG *sig, const uint8_t *id,
		  const size_t id_len, const uint8_t *msg, size_t msg_len)
{
	BIGNUM *e = NULL;
	int ret = 0;

	e = sm2_compute_msg_hash(digest, key, id, id_len, msg, msg_len);
	if (e == NULL) {
		/* SM2err already called */
		goto done;
	}

	ret = sm2_sig_verify(key, sig, e);

	RTLS_DEBUG("[VERIFY] %s %d: ret %d\n", __func__, __LINE__, ret);
done:
	BN_free(e);
	return ret;
}

typedef struct {
	int field_type; /* either NID_X9_62_prime_field or NID_X9_62_characteristic_two_field */
	int seed_len;
	int param_len;
	unsigned int cofactor; /* promoted to BN_ULONG */
} EC_CURVE_DATA;

static const struct {
	EC_CURVE_DATA h;
	unsigned char data[0 + 32 * 6];
} _EC_sm2p256v1 = { { NID_X9_62_prime_field, 0, 32, 1 },
		    {
			    /* no seed */

			    /* p */
			    0xff,
			    0xff,
			    0xff,
			    0xfe,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0x00,
			    0x00,
			    0x00,
			    0x00,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    /* a */
			    0xff,
			    0xff,
			    0xff,
			    0xfe,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0x00,
			    0x00,
			    0x00,
			    0x00,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xfc,
			    /* b */
			    0x28,
			    0xe9,
			    0xfa,
			    0x9e,
			    0x9d,
			    0x9f,
			    0x5e,
			    0x34,
			    0x4d,
			    0x5a,
			    0x9e,
			    0x4b,
			    0xcf,
			    0x65,
			    0x09,
			    0xa7,
			    0xf3,
			    0x97,
			    0x89,
			    0xf5,
			    0x15,
			    0xab,
			    0x8f,
			    0x92,
			    0xdd,
			    0xbc,
			    0xbd,
			    0x41,
			    0x4d,
			    0x94,
			    0x0e,
			    0x93,
			    /* x */
			    0x32,
			    0xc4,
			    0xae,
			    0x2c,
			    0x1f,
			    0x19,
			    0x81,
			    0x19,
			    0x5f,
			    0x99,
			    0x04,
			    0x46,
			    0x6a,
			    0x39,
			    0xc9,
			    0x94,
			    0x8f,
			    0xe3,
			    0x0b,
			    0xbf,
			    0xf2,
			    0x66,
			    0x0b,
			    0xe1,
			    0x71,
			    0x5a,
			    0x45,
			    0x89,
			    0x33,
			    0x4c,
			    0x74,
			    0xc7,
			    /* y */
			    0xbc,
			    0x37,
			    0x36,
			    0xa2,
			    0xf4,
			    0xf6,
			    0x77,
			    0x9c,
			    0x59,
			    0xbd,
			    0xce,
			    0xe3,
			    0x6b,
			    0x69,
			    0x21,
			    0x53,
			    0xd0,
			    0xa9,
			    0x87,
			    0x7c,
			    0xc6,
			    0x2a,
			    0x47,
			    0x40,
			    0x02,
			    0xdf,
			    0x32,
			    0xe5,
			    0x21,
			    0x39,
			    0xf0,
			    0xa0,
			    /* order */
			    0xff,
			    0xff,
			    0xff,
			    0xfe,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0xff,
			    0x72,
			    0x03,
			    0xdf,
			    0x6b,
			    0x21,
			    0xc6,
			    0x05,
			    0x2b,
			    0x53,
			    0xbb,
			    0xf4,
			    0x09,
			    0x39,
			    0xd5,
			    0x41,
			    0x23,
		    } };

typedef struct _ec_list_element_st {
	int nid;
	const EC_CURVE_DATA *data;
	const EC_METHOD *(*meth)(void);
	const char *comment;
} ec_list_element;

static const ec_list_element sm2_curve = {
	NID_sm2,
	&_EC_sm2p256v1.h,
	0,
	"SM2 curve over a 256 bit prime field",
};

static EC_GROUP *ec_group_new_from_data(const ec_list_element curve)
{
	EC_GROUP *group = NULL;
	EC_POINT *P = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL, *order = NULL;
	int ok = 0;
	int seed_len, param_len;
	const EC_METHOD *meth;
	const EC_CURVE_DATA *data;
	const unsigned char *params;

	/* If no curve data curve method must handle everything */
	if (curve.data == NULL)
		return EC_GROUP_new(curve.meth != NULL ? curve.meth() : NULL);

	if ((ctx = BN_CTX_new()) == NULL) {
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	data = curve.data;
	seed_len = data->seed_len;
	param_len = data->param_len;
	params = (const unsigned char *)(data + 1); /* skip header */
	params += seed_len; /* skip seed */

	if ((p = BN_bin2bn(params + 0 * param_len, param_len, NULL)) == NULL ||
	    (a = BN_bin2bn(params + 1 * param_len, param_len, NULL)) == NULL ||
	    (b = BN_bin2bn(params + 2 * param_len, param_len, NULL)) == NULL) {
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
		goto err;
	}

	/*if (curve.meth != 0) {
        meth = curve.meth();
        if (((group = EC_GROUP_new(meth)) == NULL) ||
            (!(group->meth->group_set_curve(group, p, a, b, ctx)))) {
            ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
            goto err;
        }
    } else */
	if (data->field_type == NID_X9_62_prime_field) {
		if ((group = EC_GROUP_new_curve_GFp(p, a, b, ctx)) == NULL) {
			ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
			goto err;
		}
	}
	//#ifndef OPENSSL_NO_EC2M
	//    else {                      /* field_type ==
	//                                 * NID_X9_62_characteristic_two_field */
	//
	//        if ((group = EC_GROUP_new_curve_GF2m(p, a, b, ctx)) == NULL) {
	//            ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
	//            goto err;
	//        }
	//    }
	//#endif

	EC_GROUP_set_curve_name(group, curve.nid);

	if ((P = EC_POINT_new(group)) == NULL) {
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
		goto err;
	}

	if ((x = BN_bin2bn(params + 3 * param_len, param_len, NULL)) == NULL ||
	    (y = BN_bin2bn(params + 4 * param_len, param_len, NULL)) == NULL) {
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
		goto err;
	}
	if (!EC_POINT_set_affine_coordinates(group, P, x, y, ctx)) {
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
		goto err;
	}
	if ((order = BN_bin2bn(params + 5 * param_len, param_len, NULL)) == NULL ||
	    !BN_set_word(x, (BN_ULONG)data->cofactor)) {
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
		goto err;
	}
	if (!EC_GROUP_set_generator(group, P, order, x)) {
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
		goto err;
	}
	if (seed_len) {
		if (!EC_GROUP_set_seed(group, params - seed_len, seed_len)) {
			ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
			goto err;
		}
	}
	ok = 1;
err:
	if (!ok) {
		EC_GROUP_free(group);
		group = NULL;
	}
	EC_POINT_free(P);
	BN_CTX_free(ctx);
	BN_free(p);
	BN_free(a);
	BN_free(b);
	BN_free(order);
	BN_free(x);
	BN_free(y);
	return group;
}

const hygon_pubkey_t hrk_pubkey = {
	.curve_id = 0x03,

	.qx =
		{
		  0x2d, 0xf6, 0xc2, 0x92, 0x1d, 0xf2, 0xf5, 0x2a,
		  0x50, 0x1f, 0xcd, 0x85, 0xe7, 0x35, 0x09, 0xc8,
		  0x75, 0x3a, 0x56, 0x09, 0xdb, 0x02, 0xd7, 0xf3,
		  0x4c, 0xf1, 0xa4, 0x62, 0x4d, 0xe1, 0x62, 0xbe,
		  0x00,
		},
	.qy =
		{
		  0x46, 0xb9, 0x1e, 0xb4, 0x68, 0x4d, 0x74, 0x38,
		  0x47, 0x88, 0xbe, 0xb9, 0x10, 0x0c, 0x64, 0x4a,
		  0x38, 0x95, 0x4e, 0x16, 0x97, 0x8b, 0x4f, 0x58,
		  0x15, 0x70, 0xbb, 0x57, 0x3a, 0x12, 0xab, 0x3b,
		  0x00,
		},

	.userid_len = 0x0d,

	.userid =
		{
		  0x48, 0x59, 0x47, 0x4f, 0x4e, 0x2d, 0x53, 0x53,
		  0x44, 0x2d, 0x48, 0x52, 0x4b, 0x0,
		},
};

#define HYGON_SM2_POINT_SIZE 32
typedef struct {
	uint32_t curve_id;
	uint8_t qx[HYGON_SM2_POINT_SIZE];
	uint8_t qy[HYGON_SM2_POINT_SIZE];
} sm2_pubkey_t;
#define HYGON_SM2_SIGNATURE_SIZE 32
typedef struct {
	uint8_t r[HYGON_SM2_SIGNATURE_SIZE];
	uint8_t s[HYGON_SM2_SIGNATURE_SIZE];
} sm2_signature_t;

typedef struct {
	uint16_t len;
	uint8_t uid[HYGON_SM2_UID_SIZE - sizeof(uint16_t)];
} sm2_userid_t;

static void invert_endian(uint8_t *buf, size_t len)
{
	int i;
	uint8_t tmp;

	for (i = 0; i < len / 2; i++) {
		tmp = buf[i];
		buf[i] = buf[len - i - 1];
		buf[len - i - 1] = tmp;
	}
}

static void hygon_to_sm2_pubkey(hygon_pubkey_t *src_pubkey, sm2_pubkey_t *dst_pubkey)
{
	dst_pubkey->curve_id = src_pubkey->curve_id;

	memcpy(dst_pubkey->qx, src_pubkey->qx, sizeof(dst_pubkey->qx));
	memcpy(dst_pubkey->qy, src_pubkey->qy, sizeof(dst_pubkey->qy));

	invert_endian(dst_pubkey->qx, sizeof(dst_pubkey->qx));
	invert_endian(dst_pubkey->qy, sizeof(dst_pubkey->qy));
}

static void hygon_to_sm2_signature(hygon_signature_t *src_sig, sm2_signature_t *dst_sig)
{
	memcpy(dst_sig->r, src_sig->r, sizeof(dst_sig->r));
	memcpy(dst_sig->s, src_sig->s, sizeof(dst_sig->s));

	invert_endian(dst_sig->r, sizeof(dst_sig->r));
	invert_endian(dst_sig->s, sizeof(dst_sig->s));
}

static void hygon_to_sm2_userid(hygon_pubkey_t *pubkey, sm2_userid_t *userid)
{
	userid->len = (pubkey->userid_len > (256 - sizeof(uint16_t))) ? (256 - sizeof(uint16_t)) :
									pubkey->userid_len;

	memcpy(userid->uid, (uint8_t *)pubkey->userid, userid->len);
}

/**
 * Verify SM2 signature
 *
 * Params:
 * 	sm2_pubkey [in]: SM2 public key
 * 	msg        [in]: plain text
 * 	msg_len    [in]: plain text len
 * 	user_id    [in]: SM2 userid
 * 	sig        [in]: SM2 signature
 * Return:
 * 	1: success
 * 	otherwise fail
 */
static int sm2_verify_sig(const sm2_pubkey_t *sm2_pubkey, const uint8_t *msg, size_t msg_len,
			  const sm2_userid_t *user_id, const sm2_signature_t *sig)
{
	int ret = -1;
	EC_KEY *ec_key = NULL;
	EC_GROUP *group = NULL;
	ECDSA_SIG *ecdsa_sig = NULL;
	BIGNUM *bn_qx, *bn_qy, *bn_sig_r, *bn_sig_s;

	// convert @sm2_pubkey to EC_KEY
	if (!(ec_key = EC_KEY_new())) {
		RTLS_DEBUG("EC_KEY_new() fail\n");
		return -1;
	}
	if (!(bn_qx = BN_new())) {
		RTLS_DEBUG("BN_new() bn_qx fail\n");
		goto err_free_ec_key;
	}
	if (!(bn_qy = BN_new())) {
		RTLS_DEBUG("BN_new() bn_qy fail\n");
		goto err_free_bn_qx;
	}
	BN_bin2bn(sm2_pubkey->qx, HYGON_SM2_POINT_SIZE, bn_qx);
	BN_bin2bn(sm2_pubkey->qy, HYGON_SM2_POINT_SIZE, bn_qy);

	if (!(group = ec_group_new_from_data(sm2_curve))) {
		RTLS_DEBUG("EC_GROUP_new_by_curve_name() fail\n");
		goto err_free_bn_qy;
	}
	ret = EC_KEY_set_group(ec_key, group);
	if (ret != 1) {
		RTLS_DEBUG("EC_KEY_set_group() fail\n");
		goto err_free_group;
	}

	ret = EC_KEY_set_public_key_affine_coordinates(ec_key, bn_qx, bn_qy);
	if (ret != 1) {
		RTLS_DEBUG("EC_KEY_set_public_key_affine_coordinates() fail\n");
		goto err_free_group;
	}

	// convert @sig to ECDSA_SIG
	ret = -1;
	if (!(bn_sig_r = BN_new())) {
		RTLS_DEBUG("BN_new() bn_sig_r fail\n");
		goto err_free_group;
	}
	if (!(bn_sig_s = BN_new())) {
		RTLS_DEBUG("BN_new() bn_sig_s fail\n");
		goto err_free_bn_sig_r;
	}
	BN_bin2bn(sig->r, HYGON_SM2_SIGNATURE_SIZE, bn_sig_r);
	BN_bin2bn(sig->s, HYGON_SM2_SIGNATURE_SIZE, bn_sig_s);

	if (!(ecdsa_sig = ECDSA_SIG_new())) {
		RTLS_DEBUG("ECDSA_SIG_new() fail\n");
		goto err_free_bn_sig_s;
	}
	ret = ECDSA_SIG_set0(ecdsa_sig, bn_sig_r, bn_sig_s);
	if (ret != 1) {
		RTLS_DEBUG("ECDSA_SIG_set0() fail\n");
		goto err_free_ecdsa_sig;
	}

	// verify ECDSA_SIG
	ret = sm2_do_verify(ec_key, EVP_sm3(), ecdsa_sig, user_id->uid, user_id->len, msg, msg_len);
	if (ret != 1)
		RTLS_DEBUG("sm2_do_verify() ret %d\n", ret);

err_free_ecdsa_sig:
	// ECDSA_SIG_free will free bn_sig_r and bn_sig_s
	ECDSA_SIG_free(ecdsa_sig);
	goto err_free_group;
err_free_bn_sig_s:
	BN_free(bn_sig_s);
err_free_bn_sig_r:
	BN_free(bn_sig_r);
err_free_group:
	EC_GROUP_free(group);
err_free_bn_qy:
	BN_free(bn_qy);
err_free_bn_qx:
	BN_free(bn_qx);
err_free_ec_key:
	EC_KEY_free(ec_key);

	return ret;
}

static int verify_hsk_cert_signature(hygon_root_cert_t *hsk_cert)
{
	sm2_pubkey_t sm2_pubkey;
	sm2_signature_t sm2_sig;
	sm2_userid_t sm2_userid;

	hygon_to_sm2_pubkey((hygon_pubkey_t *)&hrk_pubkey, &sm2_pubkey);
	hygon_to_sm2_signature((hygon_signature_t *)hsk_cert->signature, &sm2_sig);
	hygon_to_sm2_userid((hygon_pubkey_t *)&hrk_pubkey, &sm2_userid);

	return sm2_verify_sig(&sm2_pubkey, (uint8_t *)hsk_cert, 64 + 512, &sm2_userid, &sm2_sig);
}

/**
 * Verify HSK cert through HRK public key
 *
 * Params:
 * 	hsk_cert [in]: HSK cert buffer
 * Return:
 * 	1: success
 * 	otherwise fail
 */
int verify_hsk_cert(hygon_root_cert_t *cert)
{
	if (cert->key_usage != KEY_USAGE_TYPE_HSK) {
		RTLS_ERR("HSK cert key usage type invalid\n");
		return -1;
	}

	return verify_hsk_cert_signature(cert);
}

static int verify_cek_cert_signature(hygon_root_cert_t *hsk_cert, csv_cert_t *cek_cert)
{
	sm2_pubkey_t sm2_pubkey;
	sm2_signature_t sm2_sig;
	sm2_userid_t sm2_userid;

	hygon_to_sm2_pubkey((hygon_pubkey_t *)hsk_cert->pubkey, &sm2_pubkey);

	if (cek_cert->sig1_usage == KEY_USAGE_TYPE_INVALID)
		hygon_to_sm2_signature((hygon_signature_t *)&cek_cert->ecc_sig2, &sm2_sig);
	else
		hygon_to_sm2_signature((hygon_signature_t *)&cek_cert->ecc_sig1, &sm2_sig);

	hygon_to_sm2_userid((hygon_pubkey_t *)hsk_cert->pubkey, &sm2_userid);

	return sm2_verify_sig(&sm2_pubkey, (uint8_t *)cek_cert, 16 + 1028, &sm2_userid, &sm2_sig);
}

/**
 * Verify CEK cert through HSK public key
 *
 * Params:
 * 	hsk_cert [in]: HSK cert buffer
 * 	cek_cert [in]: CEK cert buffer
 * Return:
 * 	1: success
 * 	otherwise fail
 */
int verify_cek_cert(hygon_root_cert_t *hsk_cert, csv_cert_t *cek_cert)
{
	if (cek_cert->pubkey_usage != KEY_USAGE_TYPE_CEK) {
		RTLS_ERR("CEK cert public key usage type invalid\n");
		return -1;
	}

	if (cek_cert->sig1_usage != KEY_USAGE_TYPE_HSK) {
		RTLS_ERR("CEK cert sig 1 usage type invalid\n");
		return -1;
	}

	if (cek_cert->sig2_usage != KEY_USAGE_TYPE_INVALID) {
		RTLS_ERR("CSV: CEK cert sig 2 usage type invalid\n");
		return -1;
	}

	return verify_cek_cert_signature(hsk_cert, cek_cert);
}

static int verify_pek_cert_signature(csv_cert_t *cek_cert, csv_cert_t *pek_cert)
{
	sm2_pubkey_t sm2_pubkey;
	sm2_signature_t sm2_sig;
	sm2_userid_t sm2_userid;

	hygon_to_sm2_pubkey((hygon_pubkey_t *)&cek_cert->sm2_pubkey, &sm2_pubkey);
	hygon_to_sm2_signature((hygon_signature_t *)&pek_cert->ecc_sig1, &sm2_sig);
	hygon_to_sm2_userid((hygon_pubkey_t *)&cek_cert->sm2_pubkey, &sm2_userid);

	return sm2_verify_sig(&sm2_pubkey, (uint8_t *)pek_cert, 16 + 1028, &sm2_userid, &sm2_sig);
}

/**
 * Verify PEK cert
 *
 * Params:
 * 	cek_cert [in]: CEK cert buffer
 * 	pek_cert [in]: PEK cert buffer
 * Return:
 * 	1: success
 * 	otherwise fail
 */
int verify_pek_cert(csv_cert_t *cek_cert, csv_cert_t *pek_cert)
{
	if (pek_cert->pubkey_usage != KEY_USAGE_TYPE_PEK) {
		RTLS_ERR("CSV: PEK cert public key usage type invalid\n");
		return -1;
	}

	if (pek_cert->sig1_usage != KEY_USAGE_TYPE_CEK) {
		RTLS_ERR("CSV: PEK cert sig 1 usage type invalid\n");
		return -1;
	}

	return verify_pek_cert_signature(cek_cert, pek_cert);
}

/**
 * Verify CSV attestation report
 *
 * Params:
 * 	pek_cert [in]: PEK cert buffer
 * 	report   [in]: CSV attestation report
 * Return:
 * 	1: success
 * 	otherwise fail
 */
int sm2_verify_attestation_report(csv_cert_t *pek_cert, csv_attestation_report *report)
{
	sm2_pubkey_t sm2_pubkey;
	sm2_signature_t sm2_sig;
	sm2_userid_t sm2_userid;

	hygon_to_sm2_pubkey((hygon_pubkey_t *)&pek_cert->sm2_pubkey, &sm2_pubkey);
	hygon_to_sm2_signature((hygon_signature_t *)&report->ecc_sig1, &sm2_sig);
	hygon_to_sm2_userid((hygon_pubkey_t *)&pek_cert->sm2_pubkey, &sm2_userid);

	return sm2_verify_sig(&sm2_pubkey,
			      (uint8_t *)report + CSV_ATTESTATION_REPORT_SIGN_DATA_OFFSET,
			      CSV_ATTESTATION_REPORT_SIGN_DATA_SIZE, &sm2_userid, &sm2_sig);
}
