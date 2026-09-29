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

#ifdef GCK_RPC_HAVE_V32

#define U_(s, m) { 0, offsetof(s, m), 0, 0, 0, 0, 0 }
#define B_(s, m, idx, bits, fixed, req, resp) \
	{ 1, offsetof(s, m), idx, bits, fixed, req, resp }
#define PH_MSG (GCK_RPC_PHASE_ENC | GCK_RPC_PHASE_DEC)

static const GckRpcParamField gcm_msg_fields[] = {
	B_(CK_GCM_MESSAGE_PARAMS, pIv, 1, 0, 0, PH_MSG, 1),
	U_(CK_GCM_MESSAGE_PARAMS, ulIvLen),
	U_(CK_GCM_MESSAGE_PARAMS, ulIvFixedBits),
	U_(CK_GCM_MESSAGE_PARAMS, ivGenerator),
	B_(CK_GCM_MESSAGE_PARAMS, pTag, 5, 1, 0, PH_MSG, 1),
	U_(CK_GCM_MESSAGE_PARAMS, ulTagBits),
};
static const GckRpcParamField ccm_msg_fields[] = {
	U_(CK_CCM_MESSAGE_PARAMS, ulDataLen),
	B_(CK_CCM_MESSAGE_PARAMS, pNonce, 2, 0, 0, PH_MSG, 1),
	U_(CK_CCM_MESSAGE_PARAMS, ulNonceLen),
	U_(CK_CCM_MESSAGE_PARAMS, ulNonceFixedBits),
	U_(CK_CCM_MESSAGE_PARAMS, nonceGenerator),
	B_(CK_CCM_MESSAGE_PARAMS, pMAC, 6, 0, 0, PH_MSG, 1),
	U_(CK_CCM_MESSAGE_PARAMS, ulMACLen),
};
static const GckRpcParamField chacha_msg_fields[] = {
	B_(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS, pNonce, 1, 0, 0, PH_MSG, 1),
	U_(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS, ulNonceLen),
	B_(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS, pTag, -1, 0, 16,
	   PH_MSG, 1),
};
static const GckRpcParamField gcm_fields[] = {
	B_(CK_GCM_PARAMS, pIv, 1, 0, 0, GCK_RPC_PHASE_MECH, 0),
	U_(CK_GCM_PARAMS, ulIvLen),
	U_(CK_GCM_PARAMS, ulIvBits),
	B_(CK_GCM_PARAMS, pAAD, 4, 0, 0, GCK_RPC_PHASE_MECH, 0),
	U_(CK_GCM_PARAMS, ulAADLen),
	U_(CK_GCM_PARAMS, ulTagBits),
};
static const GckRpcParamField ccm_fields[] = {
	U_(CK_CCM_PARAMS, ulDataLen),
	B_(CK_CCM_PARAMS, pNonce, 2, 0, 0, GCK_RPC_PHASE_MECH, 0),
	U_(CK_CCM_PARAMS, ulNonceLen),
	B_(CK_CCM_PARAMS, pAAD, 4, 0, 0, GCK_RPC_PHASE_MECH, 0),
	U_(CK_CCM_PARAMS, ulAADLen),
	U_(CK_CCM_PARAMS, ulMACLen),
};
static const GckRpcParamField chacha_fields[] = {
	B_(CK_SALSA20_CHACHA20_POLY1305_PARAMS, pNonce, 1, 0, 0, GCK_RPC_PHASE_MECH, 0),
	U_(CK_SALSA20_CHACHA20_POLY1305_PARAMS, ulNonceLen),
	B_(CK_SALSA20_CHACHA20_POLY1305_PARAMS, pAAD, 3, 0, 0, GCK_RPC_PHASE_MECH, 0),
	U_(CK_SALSA20_CHACHA20_POLY1305_PARAMS, ulAADLen),
};

#define NF_(a) ((int)(sizeof(a) / sizeof((a)[0])))
static const GckRpcParamDesc param_descs[] = {
	{ 1, PH_MSG, sizeof(CK_GCM_MESSAGE_PARAMS), NF_(gcm_msg_fields), gcm_msg_fields },
	{ 2, PH_MSG, sizeof(CK_CCM_MESSAGE_PARAMS), NF_(ccm_msg_fields), ccm_msg_fields },
	{ 3, PH_MSG, sizeof(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS), NF_(chacha_msg_fields), chacha_msg_fields },
	{ 4, GCK_RPC_PHASE_MECH, sizeof(CK_GCM_PARAMS), NF_(gcm_fields), gcm_fields },
	{ 5, GCK_RPC_PHASE_MECH, sizeof(CK_CCM_PARAMS), NF_(ccm_fields), ccm_fields },
	{ 6, GCK_RPC_PHASE_MECH, sizeof(CK_SALSA20_CHACHA20_POLY1305_PARAMS), NF_(chacha_fields), chacha_fields },
};

const GckRpcParamDesc *gck_rpc_param_desc_for_mechanism(CK_MECHANISM_TYPE mech)
{
	switch (mech) {
	case CKM_AES_GCM:
		return &param_descs[3];
	case CKM_AES_CCM:
		return &param_descs[4];
	case CKM_CHACHA20_POLY1305:
	case CKM_SALSA20_POLY1305:
		return &param_descs[5];
	default:
		return NULL;
	}
}

/* The message structures differ in size, which tells them apart. */
const GckRpcParamDesc *gck_rpc_param_desc_for_message(CK_ULONG param_len)
{
	int i;

	for (i = 0; i < 3; ++i)
		if (param_descs[i].size == param_len)
			return &param_descs[i];
	return NULL;
}

static CK_ULONG param_get_ulong(const void *base, const GckRpcParamField *f)
{
	CK_ULONG v;
	memcpy(&v, (const char *)base + f->off, sizeof(v));
	return v;
}

/* Length in bytes of buffer field i, read from the structure in `base`. */
static CK_RV param_buf_len(const GckRpcParamDesc *d, const void *base, int i,
			   size_t *len)
{
	const GckRpcParamField *f = &d->fields[i];
	CK_ULONG v;

	if (f->len_idx < 0) {
		*len = f->len_fixed;
		return CKR_OK;
	}
	v = param_get_ulong(base, &d->fields[f->len_idx]);
	if (f->len_bits) {
		if (v > (CK_ULONG)GCK_RPC_PARAM_MAX_BUF * 8)
			return CKR_MECHANISM_PARAM_INVALID;
		v = (v + 7) / 8;
	}
	if (v > GCK_RPC_PARAM_MAX_BUF)
		return CKR_MECHANISM_PARAM_INVALID;
	*len = (size_t)v;
	return CKR_OK;
}

static void put_be64(unsigned char *p, uint64_t v)
{
	int i;
	for (i = 7; i >= 0; --i)
		*p++ = (unsigned char)(v >> (8 * i));
}

static uint64_t get_be64(const unsigned char *p)
{
	uint64_t v = 0;
	int i;
	for (i = 0; i < 8; ++i)
		v = (v << 8) | p[i];
	return v;
}

CK_RV gck_rpc_param_encode(const GckRpcParamDesc *d, const void *param,
			   int phase, unsigned char *out, size_t cap,
			   size_t *out_len)
{
	size_t n = 1, len;
	CK_BYTE_PTR ptr;
	CK_RV rv;
	int i;

	if (!d || !param || !(d->phases & phase))
		return CKR_MECHANISM_PARAM_INVALID;
	if (cap < 1)
		return CKR_MECHANISM_PARAM_INVALID;
	out[0] = (unsigned char)d->kind;

	for (i = 0; i < d->nfields; ++i) {
		if (d->fields[i].is_buf)
			continue;
		if (n + 8 > cap)
			return CKR_MECHANISM_PARAM_INVALID;
		put_be64(out + n, param_get_ulong(param, &d->fields[i]));
		n += 8;
	}
	for (i = 0; i < d->nfields; ++i) {
		if (!d->fields[i].is_buf || !(d->fields[i].req & phase))
			continue;
		rv = param_buf_len(d, param, i, &len);
		if (rv != CKR_OK)
			return rv;
		memcpy(&ptr, (const char *)param + d->fields[i].off, sizeof(ptr));
		if (len && !ptr)
			return CKR_MECHANISM_PARAM_INVALID;
		if (len > cap - n)
			return CKR_MECHANISM_PARAM_INVALID;
		if (len)
			memcpy(out + n, ptr, len);
		n += len;
	}
	if (phase == GCK_RPC_PHASE_ENC) {
		/* The returned IV/nonce and tag must fit a blob of this size */
		size_t resp = 0;

		for (i = 0; i < d->nfields; ++i) {
			if (!d->fields[i].is_buf || !d->fields[i].resp)
				continue;
			rv = param_buf_len(d, param, i, &len);
			if (rv != CKR_OK)
				return rv;
			resp += len;
		}
		if (resp > cap)
			return CKR_MECHANISM_PARAM_INVALID;
	}
	*out_len = n;
	return CKR_OK;
}

CK_RV gck_rpc_param_decode(const unsigned char *blob, size_t n, int phase,
			   GckRpcParamState *st,
			   void *(*alloc)(void *, size_t), void *ctx)
{
	const GckRpcParamDesc *d = NULL;
	size_t pos = 1, total = 0, len, used = 0;
	unsigned char *work;
	CK_RV rv;
	int i;

	memset(st, 0, sizeof(*st));
	if (n < 1)
		return CKR_MECHANISM_PARAM_INVALID;
	for (i = 0; i < (int)(sizeof(param_descs) / sizeof(param_descs[0])); ++i)
		if (param_descs[i].kind == blob[0])
			d = &param_descs[i];
	if (!d || !(d->phases & phase) || d->nfields > GCK_RPC_PARAM_MAX_FIELDS)
		return CKR_MECHANISM_PARAM_INVALID;

	/* CK_ULONG fields */
	for (i = 0; i < d->nfields; ++i) {
		uint64_t v;
		CK_ULONG u;

		if (d->fields[i].is_buf)
			continue;
		if (n - pos < 8)
			return CKR_MECHANISM_PARAM_INVALID;
		v = get_be64(blob + pos);
		pos += 8;
		u = (CK_ULONG)v;
		if ((uint64_t)u != v)
			return CKR_MECHANISM_PARAM_INVALID;
		memcpy((char *)&st->s + d->fields[i].off, &u, sizeof(u));
	}

	/* Buffer lengths; every buffer gets private, writable backing */
	for (i = 0; i < d->nfields; ++i) {
		if (!d->fields[i].is_buf)
			continue;
		rv = param_buf_len(d, &st->s, i, &len);
		if (rv != CKR_OK)
			return rv;
		st->lens[i] = len;
		total += len;
		if (d->fields[i].req & phase) {
			if (len > n - pos)
				return CKR_MECHANISM_PARAM_INVALID;
			pos += len;	/* checked again below when copying */
		}
	}
	if (pos != n)
		return CKR_MECHANISM_PARAM_INVALID;

	work = alloc(ctx, total + 1);
	if (!work)
		return CKR_DEVICE_MEMORY;
	memset(work, 0, total + 1);

	pos = 1 + 8 * (size_t)0;
	for (i = 0; i < d->nfields; ++i)
		if (!d->fields[i].is_buf)
			pos += 8;
	for (i = 0; i < d->nfields; ++i) {
		CK_BYTE_PTR p;

		if (!d->fields[i].is_buf)
			continue;
		len = st->lens[i];
		p = len ? work + used : NULL;
		if (len && (d->fields[i].req & phase)) {
			memcpy(p, blob + pos, len);
			pos += len;
		}
		used += len;
		memcpy((char *)&st->s + d->fields[i].off, &p, sizeof(p));
	}
	st->desc = d;
	return CKR_OK;
}

CK_RV gck_rpc_param_resp_encode(const GckRpcParamState *st,
				unsigned char *out, size_t cap,
				size_t *out_len)
{
	const GckRpcParamDesc *d = st->desc;
	size_t n = 0;
	CK_BYTE_PTR p;
	int i;

	for (i = 0; d && i < d->nfields; ++i) {
		if (!d->fields[i].is_buf || !d->fields[i].resp)
			continue;
		if (st->lens[i] > cap - n)
			return CKR_DEVICE_MEMORY;
		memcpy(&p, (const char *)&st->s + d->fields[i].off, sizeof(p));
		if (st->lens[i])
			memcpy(out + n, p, st->lens[i]);
		n += st->lens[i];
	}
	*out_len = n;
	return CKR_OK;
}

CK_RV gck_rpc_param_resp_apply(const GckRpcParamDesc *d, void *param,
			       const unsigned char *blob, size_t n)
{
	size_t pos = 0, len;
	CK_BYTE_PTR p;
	CK_RV rv;
	int i;

	if (!d)
		return n == 0 ? CKR_OK : CKR_DEVICE_ERROR;

	/* Check the whole blob fits before touching the caller's buffers */
	for (i = 0; i < d->nfields; ++i) {
		if (!d->fields[i].is_buf || !d->fields[i].resp)
			continue;
		rv = param_buf_len(d, param, i, &len);
		if (rv != CKR_OK)
			return rv;
		if (len > n - pos)
			return CKR_DEVICE_ERROR;
		pos += len;
	}
	if (pos != n)
		return CKR_DEVICE_ERROR;

	pos = 0;
	for (i = 0; i < d->nfields; ++i) {
		if (!d->fields[i].is_buf || !d->fields[i].resp)
			continue;
		param_buf_len(d, param, i, &len);
		memcpy(&p, (char *)param + d->fields[i].off, sizeof(p));
		if (len && p)
			memcpy(p, blob + pos, len);
		pos += len;
	}
	return CKR_OK;
}

#endif /* GCK_RPC_HAVE_V32 */

int gck_rpc_mechanism_has_sane_parameters(CK_MECHANISM_TYPE type)
{
	/* This list is incomplete */
	switch (type) {
	case CKM_RSA_PKCS_OAEP:
	case CKM_RSA_PKCS_PSS:
	/* Parameters below are flat (IV bytes or CK_ULONG fields, no
	 * pointers), so a raw copy is safe.  Pointer-carrying params such
	 * as CK_GCM_PARAMS or CK_ECDH1_DERIVE_PARAMS must NOT be added
	 * here without real serialization. */
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA224_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
	case CKM_SHA384_RSA_PKCS_PSS:
	case CKM_SHA512_RSA_PKCS_PSS:
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	case CKM_AES_CTR:
	case CKM_AES_KEY_WRAP:
	case CKM_AES_KEY_WRAP_PAD:
	case CKM_DES_CBC:
	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC:
	case CKM_DES3_CBC_PAD:
		return 1;
	default:
		return 0;
	}
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
	case CKM_SSL3_PRE_MASTER_KEY_GEN:
	case CKM_TLS_PRE_MASTER_KEY_GEN:
	case CKM_SKIPJACK_KEY_GEN:
	case CKM_BATON_KEY_GEN:
	case CKM_JUNIPER_KEY_GEN:
	case CKM_RC2_ECB:
	case CKM_DES_ECB:
	case CKM_DES3_ECB:
	case CKM_CDMF_ECB:
	case CKM_CAST_ECB:
	case CKM_CAST3_ECB:
	case CKM_CAST128_ECB:
	case CKM_RC5_ECB:
	case CKM_IDEA_ECB:
	case CKM_RC2_MAC:
	case CKM_DES_MAC:
	case CKM_DES3_MAC:
	case CKM_CDMF_MAC:
	case CKM_CAST_MAC:
	case CKM_CAST3_MAC:
	case CKM_RC5_MAC:
	case CKM_IDEA_MAC:
	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:
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
#endif
		return 1;
	default:
		return 0;
	};
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
