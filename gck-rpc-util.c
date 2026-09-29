/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* p11-rpc-util.c - utilities for module and dispatcher

   Copyright (C) 2008, Stef Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gck-rpc-layer.h"
#include "gck-rpc-private.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static void do_log(const char *pref, const char *msg, va_list va)
{
	char buffer[1024];
	size_t len = 0;

	if (pref) {
		snprintf(buffer, sizeof(buffer), "%s: ", pref);
		len = strlen(buffer);
	}

	vsnprintf(buffer + len, sizeof(buffer) - len, msg, va);
	gck_rpc_log(buffer);
}

void gck_rpc_warn(const char *msg, ...)
{
	va_list va;
	va_start(va, msg);
	do_log("WARNING", msg, va);
	va_end(va);
}

void gck_rpc_debug(const char *msg, ...)
{
	va_list va;
	va_start(va, msg);
	do_log("DEBUG", msg, va);
	va_end(va);
}

int gck_rpc_mechanism_is_supported(CK_MECHANISM_TYPE mech)
{
	if (gck_rpc_mechanism_has_no_parameters(mech) ||
	    gck_rpc_mechanism_has_sane_parameters(mech) ||
	    gck_rpc_mechanism_context_kind(mech))
		return 1;
#ifdef GCK_RPC_HAVE_V32
	if (gck_rpc_param_desc_for_mechanism(mech))
		return 1;
#endif
	return 0;
}

/*
 * The v3.2 ML-DSA and SLH-DSA mechanisms take an optional additional
 * context structure holding a pointer to the context string, so they
 * can't be copied verbatim; they are serialized field by field instead.
 */
int gck_rpc_mechanism_context_kind(CK_MECHANISM_TYPE mech)
{
	switch (mech) {
#ifdef CKM_ML_DSA
	case CKM_HASH_ML_DSA:
	case CKM_HASH_SLH_DSA:
		return GCK_RPC_CONTEXT_HASH_SIGN;
	case CKM_ML_DSA:
	case CKM_HASH_ML_DSA_SHA224:
	case CKM_HASH_ML_DSA_SHA256:
	case CKM_HASH_ML_DSA_SHA384:
	case CKM_HASH_ML_DSA_SHA512:
	case CKM_HASH_ML_DSA_SHA3_224:
	case CKM_HASH_ML_DSA_SHA3_256:
	case CKM_HASH_ML_DSA_SHA3_384:
	case CKM_HASH_ML_DSA_SHA3_512:
	case CKM_HASH_ML_DSA_SHAKE128:
	case CKM_HASH_ML_DSA_SHAKE256:
	case CKM_SLH_DSA:
	case CKM_HASH_SLH_DSA_SHA224:
	case CKM_HASH_SLH_DSA_SHA256:
	case CKM_HASH_SLH_DSA_SHA384:
	case CKM_HASH_SLH_DSA_SHA512:
	case CKM_HASH_SLH_DSA_SHA3_224:
	case CKM_HASH_SLH_DSA_SHA3_256:
	case CKM_HASH_SLH_DSA_SHA3_384:
	case CKM_HASH_SLH_DSA_SHA3_512:
	case CKM_HASH_SLH_DSA_SHAKE128:
	case CKM_HASH_SLH_DSA_SHAKE256:
		return GCK_RPC_CONTEXT_SIGN;
#endif
	default:
		return 0;
	}
}

void
gck_rpc_mechanism_list_purge(CK_MECHANISM_TYPE_PTR mechs, CK_ULONG * n_mechs)
{
	int i;

	assert(mechs);
	assert(n_mechs);

	for (i = 0; i < (int)(*n_mechs); ++i) {
		if (!gck_rpc_mechanism_is_supported(mechs[i])) {

			/* Remove the mechanism from the list */
			memmove(&mechs[i], &mechs[i + 1],
				(*n_mechs - i) * sizeof(CK_MECHANISM_TYPE));

			--(*n_mechs);
			--i;
		}
	}
}

static int flat_param(CK_MECHANISM_TYPE mech, size_t *want, size_t *alt);

int gck_rpc_mechanism_has_sane_parameters(CK_MECHANISM_TYPE type)
{
	size_t want, alt;

	return flat_param(type, &want, &alt);
}

int gck_rpc_mechanism_has_no_parameters(CK_MECHANISM_TYPE mech)
{
	/* This list is incomplete */

	switch (mech) {
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
	case CKM_RSA_X9_31_KEY_PAIR_GEN:
	case CKM_RSA_PKCS:
	case CKM_RSA_9796:
	case CKM_RSA_X_509:
	case CKM_RSA_X9_31:
	case CKM_MD2_RSA_PKCS:
	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_RIPEMD128_RSA_PKCS:
	case CKM_RIPEMD160_RSA_PKCS:
	case CKM_SHA1_RSA_X9_31:
	case CKM_DSA_KEY_PAIR_GEN:
	case CKM_DSA_PARAMETER_GEN:
	case CKM_DSA:
	case CKM_DSA_SHA1:
	case CKM_FORTEZZA_TIMESTAMP:
	case CKM_EC_KEY_PAIR_GEN:
	case CKM_ECDSA:
	case CKM_ECDSA_SHA1:
	case CKM_DH_PKCS_KEY_PAIR_GEN:
	case CKM_DH_PKCS_PARAMETER_GEN:
	case CKM_X9_42_DH_KEY_PAIR_GEN:
	case CKM_X9_42_DH_PARAMETER_GEN:
	case CKM_KEA_KEY_PAIR_GEN:
	case CKM_GENERIC_SECRET_KEY_GEN:
	case CKM_RC2_KEY_GEN:
	case CKM_RC4_KEY_GEN:
	case CKM_RC4:
	case CKM_RC5_KEY_GEN:
	case CKM_AES_KEY_GEN:
	case CKM_AES_ECB:
	case CKM_AES_MAC:
	case CKM_DES_KEY_GEN:
	case CKM_DES2_KEY_GEN:
	case CKM_DES3_KEY_GEN:
	case CKM_CDMF_KEY_GEN:
	case CKM_CAST_KEY_GEN:
	case CKM_CAST3_KEY_GEN:
	case CKM_CAST128_KEY_GEN:
	case CKM_IDEA_KEY_GEN:
	case CKM_SKIPJACK_KEY_GEN:
	case CKM_BATON_KEY_GEN:
	case CKM_JUNIPER_KEY_GEN:
	case CKM_DES_ECB:
	case CKM_DES3_ECB:
	case CKM_CDMF_ECB:
	case CKM_CAST_ECB:
	case CKM_CAST3_ECB:
	case CKM_CAST128_ECB:
	case CKM_IDEA_ECB:
	case CKM_DES_MAC:
	case CKM_DES3_MAC:
	case CKM_CDMF_MAC:
	case CKM_CAST_MAC:
	case CKM_CAST3_MAC:
	case CKM_IDEA_MAC:
	case CKM_SKIPJACK_WRAP:
	case CKM_BATON_WRAP:
	case CKM_JUNIPER_WRAP:
	case CKM_MD2:
	case CKM_MD2_HMAC:
	case CKM_MD5:
	case CKM_MD5_HMAC:
	case CKM_SHA_1:
	case CKM_SHA_1_HMAC:
	case CKM_SHA256:
	case CKM_SHA256_HMAC:
	case CKM_SHA384:
	case CKM_SHA384_HMAC:
	case CKM_SHA512:
	case CKM_SHA512_HMAC:
	case CKM_FASTHASH:
	case CKM_RIPEMD128:
	case CKM_RIPEMD128_HMAC:
	case CKM_RIPEMD160:
	case CKM_RIPEMD160_HMAC:
	case CKM_KEY_WRAP_LYNKS:
	case CKM_AES_CMAC:
	case CKM_SHA224:
	case CKM_SHA224_HMAC:
	case CKM_SHA224_RSA_PKCS:
	case CKM_SHA3_224:
	case CKM_SHA3_224_HMAC:
	case CKM_SHA3_256:
	case CKM_SHA3_256_HMAC:
	case CKM_SHA3_384:
	case CKM_SHA3_384_HMAC:
	case CKM_SHA3_512:
	case CKM_SHA3_512_HMAC:
	case CKM_EC_EDWARDS_KEY_PAIR_GEN:
	case CKM_EC_MONTGOMERY_KEY_PAIR_GEN:
#ifdef CKM_ML_KEM
	case CKM_ML_KEM_KEY_PAIR_GEN:
	case CKM_ML_KEM:
	case CKM_ML_DSA_KEY_PAIR_GEN:
	case CKM_SLH_DSA_KEY_PAIR_GEN:
	case CKM_HSS_KEY_PAIR_GEN:
	case CKM_HSS:
	case CKM_XMSS_KEY_PAIR_GEN:
	case CKM_XMSSMT_KEY_PAIR_GEN:
	case CKM_XMSS:
	case CKM_XMSSMT:

	/* ECDSA / DSA with a hash, SHA-3 RSA, parameter generation */
	case CKM_ECDSA_SHA224:
	case CKM_ECDSA_SHA256:
	case CKM_ECDSA_SHA384:
	case CKM_ECDSA_SHA512:
	case CKM_ECDSA_SHA3_224:
	case CKM_ECDSA_SHA3_256:
	case CKM_ECDSA_SHA3_384:
	case CKM_ECDSA_SHA3_512:
	case CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS:
	case CKM_DSA_SHA224:
	case CKM_DSA_SHA256:
	case CKM_DSA_SHA384:
	case CKM_DSA_SHA512:
	case CKM_DSA_SHA3_224:
	case CKM_DSA_SHA3_256:
	case CKM_DSA_SHA3_384:
	case CKM_DSA_SHA3_512:
	case CKM_SHA3_224_RSA_PKCS:
	case CKM_SHA3_256_RSA_PKCS:
	case CKM_SHA3_384_RSA_PKCS:
	case CKM_SHA3_512_RSA_PKCS:

	/* digests, HMACs, key generation and key derivation */
	case CKM_SHA512_224:
	case CKM_SHA512_256:
	case CKM_SHA512_224_HMAC:
	case CKM_SHA512_256_HMAC:
	case CKM_SHA224_KEY_GEN:
	case CKM_SHA256_KEY_GEN:
	case CKM_SHA384_KEY_GEN:
	case CKM_SHA512_KEY_GEN:
	case CKM_SHA512_224_KEY_GEN:
	case CKM_SHA512_256_KEY_GEN:
	case CKM_SHA3_224_KEY_GEN:
	case CKM_SHA3_256_KEY_GEN:
	case CKM_SHA3_384_KEY_GEN:
	case CKM_SHA3_512_KEY_GEN:
	case CKM_SHA224_KEY_DERIVATION:
	case CKM_SHA256_KEY_DERIVATION:
	case CKM_SHA384_KEY_DERIVATION:
	case CKM_SHA512_KEY_DERIVATION:
	case CKM_SHA512_224_KEY_DERIVATION:
	case CKM_SHA512_256_KEY_DERIVATION:
	case CKM_SHA3_224_KEY_DERIVATION:
	case CKM_SHA3_256_KEY_DERIVATION:
	case CKM_SHA3_384_KEY_DERIVATION:
	case CKM_SHA3_512_KEY_DERIVATION:
	case CKM_SHAKE_128_KEY_DERIVATION:
	case CKM_SHAKE_256_KEY_DERIVATION:
	case CKM_MD2_KEY_DERIVATION:
	case CKM_MD5_KEY_DERIVATION:
	case CKM_BLAKE2B_160:
	case CKM_BLAKE2B_256:
	case CKM_BLAKE2B_384:
	case CKM_BLAKE2B_512:
	case CKM_BLAKE2B_160_HMAC:
	case CKM_BLAKE2B_256_HMAC:
	case CKM_BLAKE2B_384_HMAC:
	case CKM_BLAKE2B_512_HMAC:
	case CKM_BLAKE2B_160_KEY_GEN:
	case CKM_BLAKE2B_256_KEY_GEN:
	case CKM_BLAKE2B_384_KEY_GEN:
	case CKM_BLAKE2B_512_KEY_GEN:
	case CKM_BLAKE2B_160_KEY_DERIVE:
	case CKM_BLAKE2B_256_KEY_DERIVE:
	case CKM_BLAKE2B_384_KEY_DERIVE:
	case CKM_BLAKE2B_512_KEY_DERIVE:
	case CKM_HKDF_KEY_GEN:

	/* stream ciphers, MACs, other key generation */
	case CKM_POLY1305:
	case CKM_POLY1305_KEY_GEN:
	case CKM_CHACHA20_KEY_GEN:
	case CKM_SALSA20_KEY_GEN:
	case CKM_AES_XTS_KEY_GEN:
	case CKM_AES_XCBC_MAC:
	case CKM_AES_XCBC_MAC_96:
	case CKM_DES3_CMAC:
	case CKM_ARIA_MAC:
	case CKM_CAMELLIA_MAC:
	case CKM_SEED_MAC:
	case CKM_CAST5_MAC:
	case CKM_ARIA_ECB:
	case CKM_ARIA_KEY_GEN:
	case CKM_CAMELLIA_ECB:
	case CKM_CAMELLIA_KEY_GEN:
	case CKM_SEED_ECB:
	case CKM_SEED_KEY_GEN:
	case CKM_TWOFISH_KEY_GEN:
	case CKM_BLOWFISH_KEY_GEN:
	case CKM_PUB_KEY_FROM_PRIV_KEY:
	case CKM_NULL:
	case CKM_RSA_PKCS_TPM_1_1:
	case CKM_RSA_PKCS_OAEP_TPM_1_1:
	case CKM_GOSTR3410:
	case CKM_GOSTR3410_KEY_PAIR_GEN:
	case CKM_GOSTR3410_WITH_GOSTR3411:
	case CKM_GOSTR3411:
	case CKM_GOSTR3411_HMAC:
	case CKM_GOST28147_KEY_GEN:
	case CKM_GOST28147_ECB:
	case CKM_SHA1_KEY_DERIVATION:
	case CKM_SHA_1_KEY_GEN:
#endif
		return 1;
	default:
		return 0;
	};
}

/*
 * Mechanisms whose parameter is a flat (pointer-free) structure or byte
 * string that can be copied verbatim. Returns 0 for any other mechanism,
 * else the exact length wanted (and an alternative, or a maximum for the
 * variable-length ones). The daemon enforces this: the module reads that
 * many bytes from the buffer.
 */
#define FLAT_ANY ((size_t)-1)	/* any length up to FLAT_ANY_MAX */
#define FLAT_ANY_MAX 4096

static int flat_param(CK_MECHANISM_TYPE mech, size_t *want, size_t *alt)
{
	*alt = 0;
	switch (mech) {
	/* RSA-PSS */
	case CKM_RSA_PKCS_PSS:
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA224_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
	case CKM_SHA384_RSA_PKCS_PSS:
	case CKM_SHA512_RSA_PKCS_PSS:
#ifdef CKM_ML_KEM
	case CKM_SHA3_224_RSA_PKCS_PSS:
	case CKM_SHA3_256_RSA_PKCS_PSS:
	case CKM_SHA3_384_RSA_PKCS_PSS:
	case CKM_SHA3_512_RSA_PKCS_PSS:
#endif
		*want = sizeof(CK_RSA_PKCS_PSS_PARAMS);
		return 1;

	/* 16-byte IV */
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
#ifdef CKM_ML_KEM
	case CKM_AES_CTS:
	case CKM_AES_OFB:
	case CKM_AES_CFB128:
	case CKM_AES_CFB64:
	case CKM_AES_CFB8:
	case CKM_AES_CFB1:
	case CKM_ARIA_CBC:
	case CKM_ARIA_CBC_PAD:
	case CKM_CAMELLIA_CBC:
	case CKM_CAMELLIA_CBC_PAD:
	case CKM_SEED_CBC:
	case CKM_SEED_CBC_PAD:
	case CKM_TWOFISH_CBC:
	case CKM_TWOFISH_CBC_PAD:
#endif
		*want = 16;
		return 1;

	/* 8-byte IV */
	case CKM_DES_CBC:
	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC:
	case CKM_DES3_CBC_PAD:
#ifdef CKM_ML_KEM
	case CKM_DES_CFB64:
	case CKM_DES_CFB8:
	case CKM_DES_OFB64:
	case CKM_DES_OFB8:
	case CKM_BLOWFISH_CBC:
	case CKM_BLOWFISH_CBC_PAD:
	case CKM_CAST_CBC:
	case CKM_CAST_CBC_PAD:
	case CKM_CAST3_CBC:
	case CKM_CAST3_CBC_PAD:
	case CKM_CAST5_CBC:
	case CKM_CAST5_CBC_PAD:
	case CKM_IDEA_CBC:
	case CKM_IDEA_CBC_PAD:
	case CKM_CDMF_CBC:
	case CKM_CDMF_CBC_PAD:
#endif
		*want = 8;
		return 1;

	/* counter mode: CK_AES_CTR_PARAMS / CK_CAMELLIA_CTR_PARAMS */
	case CKM_AES_CTR:
#ifdef CKM_ML_KEM
	case CKM_CAMELLIA_CTR:
#endif
		*want = sizeof(CK_AES_CTR_PARAMS);
		return 1;

	/* key wrap: optional IV */
	case CKM_AES_KEY_WRAP:
		*want = 8;
		return 1;
	case CKM_AES_KEY_WRAP_PAD:
#ifdef CKM_ML_KEM
	case CKM_AES_KEY_WRAP_KWP:
	case CKM_AES_KEY_WRAP_PKCS7:
#endif
		*want = 4;
		*alt = 8;
		return 1;

#ifdef CKM_ML_KEM
	/* general-length MACs: a CK_ULONG (the MAC length) */
	case CKM_MD2_HMAC_GENERAL:
	case CKM_MD5_HMAC_GENERAL:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA224_HMAC_GENERAL:
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA512_HMAC_GENERAL:
	case CKM_SHA512_224_HMAC_GENERAL:
	case CKM_SHA512_256_HMAC_GENERAL:
	case CKM_SHA3_224_HMAC_GENERAL:
	case CKM_SHA3_256_HMAC_GENERAL:
	case CKM_SHA3_384_HMAC_GENERAL:
	case CKM_SHA3_512_HMAC_GENERAL:
	case CKM_RIPEMD128_HMAC_GENERAL:
	case CKM_RIPEMD160_HMAC_GENERAL:
	case CKM_BLAKE2B_160_HMAC_GENERAL:
	case CKM_BLAKE2B_256_HMAC_GENERAL:
	case CKM_BLAKE2B_384_HMAC_GENERAL:
	case CKM_BLAKE2B_512_HMAC_GENERAL:
	case CKM_AES_MAC_GENERAL:
	case CKM_AES_CMAC_GENERAL:
	case CKM_DES_MAC_GENERAL:
	case CKM_DES3_MAC_GENERAL:
	case CKM_DES3_CMAC_GENERAL:
	case CKM_ARIA_MAC_GENERAL:
	case CKM_CAMELLIA_MAC_GENERAL:
	case CKM_SEED_MAC_GENERAL:
	case CKM_CAST_MAC_GENERAL:
	case CKM_CAST3_MAC_GENERAL:
	case CKM_CAST5_MAC_GENERAL:
	case CKM_IDEA_MAC_GENERAL:
	case CKM_CDMF_MAC_GENERAL:
	/* a CK_ULONG: bit index / key handle / MAC size / effective bits */
	case CKM_EXTRACT_KEY_FROM_KEY:
	case CKM_CONCATENATE_BASE_AND_KEY:
	case CKM_RC2_ECB:
	case CKM_RC2_MAC:
	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:
		*want = sizeof(CK_ULONG);
		return 1;

	/* TLS MACs, EdDSA variants, SHA-512/t: small pointer-free structures */
	case CKM_TLS_MAC:
	case CKM_TLS12_MAC:
		*want = sizeof(CK_TLS_MAC_PARAMS);
		return 1;
	case CKM_TLS10_MAC_CLIENT:
	case CKM_TLS10_MAC_SERVER:
	case CKM_SHA512_T:
	case CKM_SHA512_T_HMAC:
	case CKM_SHA512_T_HMAC_GENERAL:
	case CKM_SHA512_T_KEY_DERIVATION:
	case CKM_SHA512_T_KEY_GEN:
		*want = sizeof(CK_ULONG);
		return 1;
	case CKM_XEDDSA:
		*want = sizeof(CK_XEDDSA_PARAMS);
		return 1;
	case CKM_WTLS_PRE_MASTER_KEY_GEN:
		*want = 1;
		return 1;
	case CKM_AES_XTS:
		*want = 16;		/* the tweak; some modules also take a key handle */
		*alt = 16 + sizeof(CK_OBJECT_HANDLE);
		return 1;
	case CKM_RC5_MAC_GENERAL:
		*want = sizeof(CK_RC5_MAC_GENERAL_PARAMS);
		return 1;

	/* legacy structures without pointers */
	case CKM_RC5_ECB:
	case CKM_RC5_MAC:
		*want = sizeof(CK_RC5_PARAMS);
		return 1;
	case CKM_RC2_CBC:
	case CKM_RC2_CBC_PAD:
		*want = sizeof(CK_RC2_CBC_PARAMS);
		return 1;
	case CKM_RC2_MAC_GENERAL:
		*want = sizeof(CK_RC2_MAC_GENERAL_PARAMS);
		return 1;
	case CKM_SSL3_PRE_MASTER_KEY_GEN:
	case CKM_TLS_PRE_MASTER_KEY_GEN:
		*want = sizeof(CK_VERSION);
		return 1;

	/* the other party's public value */
	case CKM_DH_PKCS_DERIVE:
		*want = FLAT_ANY;
		return 1;
#endif
	default:
		return 0;
	}
}

int gck_rpc_mechanism_flat_param_len_ok(CK_MECHANISM_TYPE mech, size_t len)
{
	size_t want, alt;

	if (!flat_param(mech, &want, &alt))
		return 0;
	if (len == 0)
		return 1;
	if (want == FLAT_ANY)
		return len <= FLAT_ANY_MAX;
	return len == want || (alt && len == alt);
}

int gck_rpc_attr_is_template(CK_ATTRIBUTE_TYPE type)
{
	switch (type) {
	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
	case CKA_DERIVE_TEMPLATE:
#ifdef CKA_ENCAPSULATE_TEMPLATE
	case CKA_ENCAPSULATE_TEMPLATE:
	case CKA_DECAPSULATE_TEMPLATE:
#endif
		return 1;
	default:
		return 0;
	}
}

/*
 * Attributes holding a CK_ATTRIBUTE array (wrap/unwrap/derive templates)
 * can't cross the wire as raw memory: the nested pointers mean nothing on the
 * other side. They travel as a blob, format:
 *
 *   values/response:  u32 count, then per attribute: u32 type, u8 valid,
 *                     [u32 length, u8 has_data, [data]]
 *   buffer request:   u32 count, then per attribute: u32 type, u8 has_buffer,
 *                     u32 capacity
 *
 * Templates don't nest.
 */
#define TPL_MAX_ATTRS	256
#define TPL_MAX_LEN	(1u << 20)

static int tpl_put(GckRpcTplBuf *b, const void *data, size_t n)
{
	if (b->err)
		return 0;
	if (n > b->cap - b->len) {
		size_t cap = b->cap ? b->cap : 64;
		unsigned char *p;

		while (cap - b->len < n) {
			if (cap > ((size_t)1 << 30)) { b->err = 1; return 0; }
			cap *= 2;
		}
		p = realloc(b->p, cap);
		if (!p) { b->err = 1; return 0; }
		b->p = p;
		b->cap = cap;
	}
	if (n)
		memcpy(b->p + b->len, data, n);
	b->len += n;
	return 1;
}

static int tpl_u32(GckRpcTplBuf *b, uint32_t v)
{
	unsigned char x[4] = { v >> 24, v >> 16, v >> 8, v };
	return tpl_put(b, x, 4);
}

static int tpl_u8(GckRpcTplBuf *b, unsigned char v)
{
	return tpl_put(b, &v, 1);
}

int gck_rpc_template_encode(GckRpcTplBuf *b, CK_ATTRIBUTE_PTR arr,
			    CK_ULONG n, int buffer_mode)
{
	CK_ULONG i;

	memset(b, 0, sizeof(*b));
	if (n > TPL_MAX_ATTRS || (n && !arr))
		return 0;
	tpl_u32(b, (uint32_t)n);
	for (i = 0; i < n; ++i) {
		CK_ATTRIBUTE_PTR a = &arr[i];

		if (gck_rpc_attr_is_template(a->type))
			goto fail;
		tpl_u32(b, (uint32_t)a->type);
		if (buffer_mode) {
			if (a->pValue && a->ulValueLen > TPL_MAX_LEN)
				goto fail;
			tpl_u8(b, a->pValue != NULL);
			tpl_u32(b, a->pValue ? (uint32_t)a->ulValueLen : 0);
		} else if ((CK_LONG)a->ulValueLen == -1) {
			tpl_u8(b, 0);
		} else {
			int has_data = a->pValue != NULL && a->ulValueLen > 0;

			if (a->ulValueLen > TPL_MAX_LEN)
				goto fail;
			tpl_u8(b, 1);
			tpl_u32(b, (uint32_t)a->ulValueLen);
			tpl_u8(b, has_data);
			if (has_data)
				tpl_put(b, a->pValue, a->ulValueLen);
		}
	}
	if (!b->err)
		return 1;
fail:
	free(b->p);
	memset(b, 0, sizeof(*b));
	return 0;
}

struct tpl_rd { const unsigned char *p; size_t len, pos; };

static int rd_u32(struct tpl_rd *r, uint32_t *v)
{
	if (r->len - r->pos < 4)
		return 0;
	*v = (uint32_t)r->p[r->pos] << 24 | (uint32_t)r->p[r->pos + 1] << 16 |
	     (uint32_t)r->p[r->pos + 2] << 8 | r->p[r->pos + 3];
	r->pos += 4;
	return 1;
}

static int rd_u8(struct tpl_rd *r, unsigned char *v)
{
	if (r->len - r->pos < 1)
		return 0;
	*v = r->p[r->pos++];
	return 1;
}

CK_RV gck_rpc_template_decode(const unsigned char *blob, size_t len,
			      int buffer_mode, void *(*alloc)(void *, size_t),
			      void *ctx, CK_ATTRIBUTE_PTR *out, CK_ULONG *count)
{
	struct tpl_rd r = { blob, len, 0 };
	CK_ATTRIBUTE_PTR arr = NULL;
	uint32_t n, i, type, vlen;
	unsigned char flag, has_data;

	*out = NULL;
	*count = 0;
	if (!rd_u32(&r, &n) || n > TPL_MAX_ATTRS)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	if (n) {
		arr = alloc(ctx, n * sizeof(CK_ATTRIBUTE));
		if (!arr)
			return CKR_DEVICE_MEMORY;
		memset(arr, 0, n * sizeof(CK_ATTRIBUTE));
	}
	for (i = 0; i < n; ++i) {
		if (!rd_u32(&r, &type) || !rd_u8(&r, &flag))
			return CKR_ATTRIBUTE_VALUE_INVALID;
		if (gck_rpc_attr_is_template(type))
			return CKR_ATTRIBUTE_VALUE_INVALID;
		arr[i].type = type;
		if (buffer_mode) {
			if (!rd_u32(&r, &vlen) || vlen > TPL_MAX_LEN)
				return CKR_ATTRIBUTE_VALUE_INVALID;
			if (flag) {
				arr[i].pValue = alloc(ctx, vlen ? vlen : 1);
				if (!arr[i].pValue)
					return CKR_DEVICE_MEMORY;
				memset(arr[i].pValue, 0, vlen ? vlen : 1);
				arr[i].ulValueLen = vlen;
			}
			continue;
		}
		if (!flag) {
			arr[i].ulValueLen = (CK_ULONG)-1;
			continue;
		}
		if (!rd_u32(&r, &vlen) || vlen > TPL_MAX_LEN ||
		    !rd_u8(&r, &has_data))
			return CKR_ATTRIBUTE_VALUE_INVALID;
		if (has_data) {
			if (vlen > r.len - r.pos)
				return CKR_ATTRIBUTE_VALUE_INVALID;
			arr[i].pValue = alloc(ctx, vlen);
			if (!arr[i].pValue)
				return CKR_DEVICE_MEMORY;
			memcpy(arr[i].pValue, r.p + r.pos, vlen);
			r.pos += vlen;
		} else if (vlen) {
			/* a value the sender claims but doesn't provide */
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		arr[i].ulValueLen = vlen;
	}
	if (r.pos != r.len)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	*out = arr;
	*count = n;
	return CKR_OK;
}

/* Fill the caller's nested attributes from a response blob. */
CK_RV gck_rpc_template_apply(const unsigned char *blob, size_t len,
			     CK_ATTRIBUTE_PTR arr, CK_ULONG count)
{
	struct tpl_rd r = { blob, len, 0 };
	uint32_t n, i, type, vlen;
	unsigned char flag, has_data;

	if (!rd_u32(&r, &n) || n != count)
		return CKR_DEVICE_ERROR;
	for (i = 0; i < n; ++i) {
		CK_ATTRIBUTE_PTR a = &arr[i];

		if (!rd_u32(&r, &type) || !rd_u8(&r, &flag) || a->type != type)
			return CKR_DEVICE_ERROR;
		if (!flag) {
			a->ulValueLen = (CK_ULONG)-1;
			continue;
		}
		if (!rd_u32(&r, &vlen) || !rd_u8(&r, &has_data))
			return CKR_DEVICE_ERROR;
		if (has_data) {
			if (vlen > r.len - r.pos)
				return CKR_DEVICE_ERROR;
			if (a->pValue && vlen <= a->ulValueLen)
				memcpy(a->pValue, r.p + r.pos, vlen);
			else if (a->pValue)
				return CKR_DEVICE_ERROR;
			r.pos += vlen;
		}
		a->ulValueLen = vlen;
	}
	return r.pos == r.len ? CKR_OK : CKR_DEVICE_ERROR;
}

/* Reject sizes the nested-template code can't represent. */
int gck_rpc_attribute_templates_ok(CK_ATTRIBUTE_PTR arr, CK_ULONG n)
{
	CK_ULONG i;

	for (i = 0; i < n; ++i) {
		if (!gck_rpc_attr_is_template(arr[i].type) || !arr[i].pValue)
			continue;
		if (arr[i].ulValueLen == (CK_ULONG)-1 ||
		    arr[i].ulValueLen % sizeof(CK_ATTRIBUTE) != 0 ||
		    arr[i].ulValueLen / sizeof(CK_ATTRIBUTE) > TPL_MAX_ATTRS)
			return 0;
	}
	return 1;
}

int
gck_rpc_has_ulong_parameter(CK_ATTRIBUTE_TYPE type)
{
	switch (type) {
	case CKA_CLASS:
	case CKA_KEY_TYPE:
	case CKA_CERTIFICATE_TYPE:
	case CKA_HW_FEATURE_TYPE:
        case CKA_MODULUS_BITS:
#ifdef CKA_PARAMETER_SET
	case CKA_PARAMETER_SET:
	case CKA_HSS_LEVELS:
	case CKA_HSS_LMS_TYPE:
	case CKA_HSS_LMOTS_TYPE:
	case CKA_HSS_KEYS_REMAINING:
#endif
		return 1;
	default:
		return 0;
	}
}

int
gck_rpc_has_bad_sized_ulong_parameter(CK_ATTRIBUTE_PTR attr)
{
	if (!attr->pValue)
		return 0;
	/* All this parameters are transmited on the network
	 * as 64bit integers */
	if (sizeof (uint64_t) != attr->ulValueLen)
		return 0;
	if (sizeof (CK_ULONG) == attr->ulValueLen)
		return 0;
	return gck_rpc_has_ulong_parameter(attr->type);
}

/*
 * Parses prefix into two strings (host and port). Port may be a NULL pointer
 * if none is specified. Since this code does not decode port in any way, a
 * service name works too (but requires other code (like
 * _get_listening_socket()) able to resolve service names).
 *
 * This should work for IPv4 and IPv6 inputs :
 *
 *   0.0.0.0:2345
 *   0.0.0.0
 *   [::]:2345
 *   [::]
 *   [::1]:2345
 *   localhost:2345
 *   localhost
 *   localhost:p11proxy   (if p11proxy is a known service name)
 *
 * Returns 0 on failure, and 1 on success.
 */
int gck_rpc_parse_host_port(const char *prefix, char **host, char **port)
{
	char *p = NULL;
	int is_ipv6;

	is_ipv6 = (prefix[0] == '[') ? 1 : 0;

	*host = strdup(prefix + is_ipv6);
	*port = NULL;

	if (*host == NULL) {
		gck_rpc_warn("out of memory");
		return 0;
	}

	if (is_ipv6 && prefix[0] == '[')
		p = strchr(*host, ']');
	else
		p = strchr(*host, ':');

	if (p) {
		is_ipv6 = (*p == ']'); /* remember if separator was ']' */

		*p = '\0'; /* replace separator will NULL to terminate *host */
		*port = p + 1;

		if (is_ipv6 && (**port == ':'))
			*port = p + 2;
	}

	return 1;
}
