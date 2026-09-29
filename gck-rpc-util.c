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

#ifdef GCK_RPC_HAVE_V32

#define U_(s, m)  { GCK_RPC_F_ULONG, offsetof(s, m), 0, 0, 0, 0, 0, NULL }
#define Z_(s, m)  { GCK_RPC_F_BBOOL, offsetof(s, m), 0, 0, 0, 0, 0, NULL }
#define B_(s, m, idx, bits, fixed, req, resp) \
	{ GCK_RPC_F_BUF, offsetof(s, m), idx, bits, fixed, req, resp, NULL }
#define I_(s, m, n) \
	{ GCK_RPC_F_INLINE, offsetof(s, m), 0, 0, n, GCK_RPC_PHASE_MECH, 0, NULL }
#define S_(s, m, d) \
	{ GCK_RPC_F_STRUCT, offsetof(s, m), 0, 0, 0, GCK_RPC_PHASE_MECH, 0, d }
#define PH_MSG (GCK_RPC_PHASE_ENC | GCK_RPC_PHASE_DEC)
#define PH_MECH GCK_RPC_PHASE_MECH
#define NF_(a) ((int)(sizeof(a) / sizeof((a)[0])))
#define DESC_(name, kind, phases, type, fields) \
	static const GckRpcParamDesc name = \
		{ kind, phases, sizeof(type), NF_(fields), fields }

/* ---- message-based AEAD: IV/nonce and tag travel both ways ---- */
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
	B_(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS, pTag, -1, 0, 16, PH_MSG, 1),
};

/* ---- single-part mechanism parameters (input only) ---- */
static const GckRpcParamField gcm_fields[] = {
	B_(CK_GCM_PARAMS, pIv, 1, 0, 0, PH_MECH, 0),
	U_(CK_GCM_PARAMS, ulIvLen),
	U_(CK_GCM_PARAMS, ulIvBits),
	B_(CK_GCM_PARAMS, pAAD, 4, 0, 0, PH_MECH, 0),
	U_(CK_GCM_PARAMS, ulAADLen),
	U_(CK_GCM_PARAMS, ulTagBits),
};
static const GckRpcParamField ccm_fields[] = {
	U_(CK_CCM_PARAMS, ulDataLen),
	B_(CK_CCM_PARAMS, pNonce, 2, 0, 0, PH_MECH, 0),
	U_(CK_CCM_PARAMS, ulNonceLen),
	B_(CK_CCM_PARAMS, pAAD, 4, 0, 0, PH_MECH, 0),
	U_(CK_CCM_PARAMS, ulAADLen),
	U_(CK_CCM_PARAMS, ulMACLen),
};
static const GckRpcParamField chacha_fields[] = {
	B_(CK_SALSA20_CHACHA20_POLY1305_PARAMS, pNonce, 1, 0, 0, PH_MECH, 0),
	U_(CK_SALSA20_CHACHA20_POLY1305_PARAMS, ulNonceLen),
	B_(CK_SALSA20_CHACHA20_POLY1305_PARAMS, pAAD, 3, 0, 0, PH_MECH, 0),
	U_(CK_SALSA20_CHACHA20_POLY1305_PARAMS, ulAADLen),
};
static const GckRpcParamField oaep_fields[] = {
	U_(CK_RSA_PKCS_OAEP_PARAMS, hashAlg),
	U_(CK_RSA_PKCS_OAEP_PARAMS, mgf),
	U_(CK_RSA_PKCS_OAEP_PARAMS, source),
	B_(CK_RSA_PKCS_OAEP_PARAMS, pSourceData, 4, 0, 0, PH_MECH, 0),
	U_(CK_RSA_PKCS_OAEP_PARAMS, ulSourceDataLen),
};
static const GckRpcParamField ecdh1_fields[] = {
	U_(CK_ECDH1_DERIVE_PARAMS, kdf),
	U_(CK_ECDH1_DERIVE_PARAMS, ulSharedDataLen),
	B_(CK_ECDH1_DERIVE_PARAMS, pSharedData, 1, 0, 0, PH_MECH, 0),
	U_(CK_ECDH1_DERIVE_PARAMS, ulPublicDataLen),
	B_(CK_ECDH1_DERIVE_PARAMS, pPublicData, 3, 0, 0, PH_MECH, 0),
};
static const GckRpcParamField ecdh_wrap_fields[] = {
	U_(CK_ECDH_AES_KEY_WRAP_PARAMS, ulAESKeyBits),
	U_(CK_ECDH_AES_KEY_WRAP_PARAMS, kdf),
	U_(CK_ECDH_AES_KEY_WRAP_PARAMS, ulSharedDataLen),
	B_(CK_ECDH_AES_KEY_WRAP_PARAMS, pSharedData, 2, 0, 0, PH_MECH, 0),
};
static const GckRpcParamField hkdf_fields[] = {
	Z_(CK_HKDF_PARAMS, bExtract),
	Z_(CK_HKDF_PARAMS, bExpand),
	U_(CK_HKDF_PARAMS, prfHashMechanism),
	U_(CK_HKDF_PARAMS, ulSaltType),
	B_(CK_HKDF_PARAMS, pSalt, 5, 0, 0, PH_MECH, 0),
	U_(CK_HKDF_PARAMS, ulSaltLen),
	U_(CK_HKDF_PARAMS, hSaltKey),
	B_(CK_HKDF_PARAMS, pInfo, 8, 0, 0, PH_MECH, 0),
	U_(CK_HKDF_PARAMS, ulInfoLen),
};
static const GckRpcParamField eddsa_fields[] = {
	Z_(CK_EDDSA_PARAMS, phFlag),
	U_(CK_EDDSA_PARAMS, ulContextDataLen),
	B_(CK_EDDSA_PARAMS, pContextData, 1, 0, 0, PH_MECH, 0),
};
static const GckRpcParamField chacha20_fields[] = {
	B_(CK_CHACHA20_PARAMS, pBlockCounter, 1, 1, 0, PH_MECH, 0),
	U_(CK_CHACHA20_PARAMS, blockCounterBits),
	B_(CK_CHACHA20_PARAMS, pNonce, 3, 1, 0, PH_MECH, 0),
	U_(CK_CHACHA20_PARAMS, ulNonceBits),
};
static const GckRpcParamField salsa20_fields[] = {
	B_(CK_SALSA20_PARAMS, pBlockCounter, -1, 0, 8, PH_MECH, 0),
	B_(CK_SALSA20_PARAMS, pNonce, 2, 1, 0, PH_MECH, 0),
	U_(CK_SALSA20_PARAMS, ulNonceBits),
};
static const GckRpcParamField strdata_fields[] = {
	B_(CK_KEY_DERIVATION_STRING_DATA, pData, 1, 0, 0, PH_MECH, 0),
	U_(CK_KEY_DERIVATION_STRING_DATA, ulLen),
};
static const GckRpcParamField aes_cbc_data_fields[] = {
	I_(CK_AES_CBC_ENCRYPT_DATA_PARAMS, iv, 16),
	B_(CK_AES_CBC_ENCRYPT_DATA_PARAMS, pData, 2, 0, 0, PH_MECH, 0),
	U_(CK_AES_CBC_ENCRYPT_DATA_PARAMS, length),
};
static const GckRpcParamField des_cbc_data_fields[] = {
	I_(CK_DES_CBC_ENCRYPT_DATA_PARAMS, iv, 8),
	B_(CK_DES_CBC_ENCRYPT_DATA_PARAMS, pData, 2, 0, 0, PH_MECH, 0),
	U_(CK_DES_CBC_ENCRYPT_DATA_PARAMS, length),
};

DESC_(d_gcm_msg, 1, PH_MSG, CK_GCM_MESSAGE_PARAMS, gcm_msg_fields);
DESC_(d_ccm_msg, 2, PH_MSG, CK_CCM_MESSAGE_PARAMS, ccm_msg_fields);
DESC_(d_chacha_msg, 3, PH_MSG, CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS, chacha_msg_fields);
DESC_(d_gcm, 4, PH_MECH, CK_GCM_PARAMS, gcm_fields);
DESC_(d_ccm, 5, PH_MECH, CK_CCM_PARAMS, ccm_fields);
DESC_(d_chacha, 6, PH_MECH, CK_SALSA20_CHACHA20_POLY1305_PARAMS, chacha_fields);
DESC_(d_oaep, 7, PH_MECH, CK_RSA_PKCS_OAEP_PARAMS, oaep_fields);
DESC_(d_ecdh1, 8, PH_MECH, CK_ECDH1_DERIVE_PARAMS, ecdh1_fields);
DESC_(d_ecdh_wrap, 9, PH_MECH, CK_ECDH_AES_KEY_WRAP_PARAMS, ecdh_wrap_fields);
DESC_(d_hkdf, 10, PH_MECH, CK_HKDF_PARAMS, hkdf_fields);
DESC_(d_eddsa, 11, PH_MECH, CK_EDDSA_PARAMS, eddsa_fields);
DESC_(d_chacha20, 12, PH_MECH, CK_CHACHA20_PARAMS, chacha20_fields);
DESC_(d_salsa20, 13, PH_MECH, CK_SALSA20_PARAMS, salsa20_fields);
DESC_(d_strdata, 14, PH_MECH, CK_KEY_DERIVATION_STRING_DATA, strdata_fields);
DESC_(d_aes_cbc_data, 15, PH_MECH, CK_AES_CBC_ENCRYPT_DATA_PARAMS, aes_cbc_data_fields);
DESC_(d_des_cbc_data, 16, PH_MECH, CK_DES_CBC_ENCRYPT_DATA_PARAMS, des_cbc_data_fields);

/* RSA-AES key wrap points at an OAEP parameter structure */
static const GckRpcParamField rsa_aes_wrap_fields[] = {
	U_(CK_RSA_AES_KEY_WRAP_PARAMS, ulAESKeyBits),
	S_(CK_RSA_AES_KEY_WRAP_PARAMS, pOAEPParams, &d_oaep),
};
DESC_(d_rsa_aes_wrap, 17, PH_MECH, CK_RSA_AES_KEY_WRAP_PARAMS, rsa_aes_wrap_fields);

static const GckRpcParamDesc *const all_descs[] = {
	&d_gcm_msg, &d_ccm_msg, &d_chacha_msg, &d_gcm, &d_ccm, &d_chacha,
	&d_oaep, &d_ecdh1, &d_ecdh_wrap, &d_hkdf, &d_eddsa, &d_chacha20,
	&d_salsa20, &d_strdata, &d_aes_cbc_data, &d_des_cbc_data, &d_rsa_aes_wrap,
};

const GckRpcParamDesc *gck_rpc_param_desc_for_mechanism(CK_MECHANISM_TYPE mech)
{
	switch (mech) {
	case CKM_AES_GCM:
		return &d_gcm;
	case CKM_AES_CCM:
		return &d_ccm;
	case CKM_CHACHA20_POLY1305:
	case CKM_SALSA20_POLY1305:
		return &d_chacha;
	case CKM_RSA_PKCS_OAEP:
		return &d_oaep;
	case CKM_ECDH1_DERIVE:
	case CKM_ECDH1_COFACTOR_DERIVE:
		return &d_ecdh1;
	case CKM_ECDH_AES_KEY_WRAP:
	case CKM_ECDH_COF_AES_KEY_WRAP:
	case CKM_ECDH_X_AES_KEY_WRAP:
		return &d_ecdh_wrap;
	case CKM_HKDF_DERIVE:
	case CKM_HKDF_DATA:
		return &d_hkdf;
	case CKM_EDDSA:
		return &d_eddsa;
	case CKM_CHACHA20:
		return &d_chacha20;
	case CKM_SALSA20:
		return &d_salsa20;
	case CKM_CONCATENATE_BASE_AND_DATA:
	case CKM_CONCATENATE_DATA_AND_BASE:
	case CKM_XOR_BASE_AND_DATA:
	case CKM_AES_ECB_ENCRYPT_DATA:
	case CKM_DES_ECB_ENCRYPT_DATA:
	case CKM_DES3_ECB_ENCRYPT_DATA:
	case CKM_ARIA_ECB_ENCRYPT_DATA:
	case CKM_CAMELLIA_ECB_ENCRYPT_DATA:
	case CKM_SEED_ECB_ENCRYPT_DATA:
		return &d_strdata;
	case CKM_AES_CBC_ENCRYPT_DATA:
	case CKM_ARIA_CBC_ENCRYPT_DATA:
	case CKM_CAMELLIA_CBC_ENCRYPT_DATA:
	case CKM_SEED_CBC_ENCRYPT_DATA:
		/* the ARIA/Camellia/SEED structures have the same layout */
		return &d_aes_cbc_data;
	case CKM_DES_CBC_ENCRYPT_DATA:
	case CKM_DES3_CBC_ENCRYPT_DATA:
		return &d_des_cbc_data;
	case CKM_RSA_AES_KEY_WRAP:
		return &d_rsa_aes_wrap;
	default:
		return NULL;
	}
}

/* The message structures differ in size, which tells them apart. */
const GckRpcParamDesc *gck_rpc_param_desc_for_message(CK_ULONG param_len)
{
	int i;

	for (i = 0; i < 3; ++i)
		if (all_descs[i]->size == param_len)
			return all_descs[i];
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

/* ---- encoding ---- */

struct pwr {
	unsigned char *out;
	size_t cap, n;
};

static CK_RV pw_put(struct pwr *w, const void *data, size_t len)
{
	if (len > w->cap - w->n)
		return CKR_MECHANISM_PARAM_INVALID;
	if (len)
		memcpy(w->out + w->n, data, len);
	w->n += len;
	return CKR_OK;
}

static CK_RV enc_body(const GckRpcParamDesc *d, const void *base, int phase,
		      struct pwr *w, int depth)
{
	unsigned char x[8];
	size_t len;
	CK_RV rv;
	int i;

	if (depth >= GCK_RPC_PARAM_MAX_DEPTH)
		return CKR_MECHANISM_PARAM_INVALID;

	for (i = 0; i < d->nfields; ++i) {
		const GckRpcParamField *f = &d->fields[i];

		if (f->type == GCK_RPC_F_ULONG)
			put_be64(x, param_get_ulong(base, f));
		else if (f->type == GCK_RPC_F_BBOOL)
			put_be64(x, *((const CK_BBOOL *)base + f->off) ? 1 : 0);
		else
			continue;
		if ((rv = pw_put(w, x, 8)) != CKR_OK)
			return rv;
	}
	for (i = 0; i < d->nfields; ++i) {
		const GckRpcParamField *f = &d->fields[i];
		CK_BYTE_PTR ptr;

		if (!(f->req & phase))
			continue;
		switch (f->type) {
		case GCK_RPC_F_BUF:
			if ((rv = param_buf_len(d, base, i, &len)) != CKR_OK)
				return rv;
			memcpy(&ptr, (const char *)base + f->off, sizeof(ptr));
			if (len && !ptr)
				return CKR_MECHANISM_PARAM_INVALID;
			if ((rv = pw_put(w, ptr, len)) != CKR_OK)
				return rv;
			break;
		case GCK_RPC_F_INLINE:
			if ((rv = pw_put(w, (const char *)base + f->off, f->len_fixed)) != CKR_OK)
				return rv;
			break;
		case GCK_RPC_F_STRUCT: {
			const void *sub;

			memcpy(&sub, (const char *)base + f->off, sizeof(sub));
			x[0] = sub != NULL;
			if ((rv = pw_put(w, x, 1)) != CKR_OK)
				return rv;
			if (sub && (rv = enc_body(f->sub, sub, phase, w, depth + 1)) != CKR_OK)
				return rv;
			break;
		}
		}
	}
	return CKR_OK;
}

CK_RV gck_rpc_param_encode(const GckRpcParamDesc *d, const void *param,
			   int phase, unsigned char *out, size_t cap,
			   size_t *out_len)
{
	struct pwr w = { out, cap, 0 };
	unsigned char kind;
	size_t len;
	CK_RV rv;
	int i;

	if (!d || !param || !(d->phases & phase))
		return CKR_MECHANISM_PARAM_INVALID;
	kind = (unsigned char)d->kind;
	if ((rv = pw_put(&w, &kind, 1)) != CKR_OK)
		return rv;
	if ((rv = enc_body(d, param, phase, &w, 0)) != CKR_OK)
		return rv;

	if (phase == GCK_RPC_PHASE_ENC) {
		/* The returned IV/nonce and tag must fit a blob of this size */
		size_t resp = 0;

		for (i = 0; i < d->nfields; ++i) {
			if (d->fields[i].type != GCK_RPC_F_BUF || !d->fields[i].resp)
				continue;
			if ((rv = param_buf_len(d, param, i, &len)) != CKR_OK)
				return rv;
			resp += len;
		}
		if (resp > cap)
			return CKR_MECHANISM_PARAM_INVALID;
	}
	*out_len = w.n;
	return CKR_OK;
}

/* ---- decoding ---- */

struct prd {
	const unsigned char *p;
	size_t n, pos;
	void *(*alloc)(void *, size_t);
	void *ctx;
};

static void *pr_alloc0(struct prd *r, size_t n)
{
	void *m = r->alloc(r->ctx, n ? n : 1);

	if (m)
		memset(m, 0, n ? n : 1);
	return m;
}

/* Fill the zeroed structure `base` from the blob. `lens` records buffer
 * lengths (top level only). Every pointer handed out is daemon-owned. */
static CK_RV dec_body(const GckRpcParamDesc *d, int phase, struct prd *r,
		      void *base, size_t *lens, int depth)
{
	size_t len;
	CK_RV rv;
	int i;

	if (depth >= GCK_RPC_PARAM_MAX_DEPTH || d->nfields > GCK_RPC_PARAM_MAX_FIELDS)
		return CKR_MECHANISM_PARAM_INVALID;

	for (i = 0; i < d->nfields; ++i) {
		const GckRpcParamField *f = &d->fields[i];
		uint64_t v;

		if (f->type != GCK_RPC_F_ULONG && f->type != GCK_RPC_F_BBOOL)
			continue;
		if (r->n - r->pos < 8)
			return CKR_MECHANISM_PARAM_INVALID;
		v = get_be64(r->p + r->pos);
		r->pos += 8;
		if (f->type == GCK_RPC_F_ULONG) {
			CK_ULONG u = (CK_ULONG)v;

			if ((uint64_t)u != v)
				return CKR_MECHANISM_PARAM_INVALID;
			memcpy((char *)base + f->off, &u, sizeof(u));
		} else {
			*((CK_BBOOL *)((char *)base + f->off)) = v ? 1 : 0;
		}
	}
	for (i = 0; i < d->nfields; ++i) {
		const GckRpcParamField *f = &d->fields[i];
		int sent = (f->req & phase) != 0;

		switch (f->type) {
		case GCK_RPC_F_BUF: {
			unsigned char *mem;

			if ((rv = param_buf_len(d, base, i, &len)) != CKR_OK)
				return rv;
			if (lens)
				lens[i] = len;
			if (sent && len > r->n - r->pos)
				return CKR_MECHANISM_PARAM_INVALID;
			/* every buffer gets private, writable backing */
			mem = len ? pr_alloc0(r, len) : NULL;
			if (len && !mem)
				return CKR_DEVICE_MEMORY;
			if (sent && len) {
				memcpy(mem, r->p + r->pos, len);
				r->pos += len;
			}
			memcpy((char *)base + f->off, &mem, sizeof(mem));
			break;
		}
		case GCK_RPC_F_INLINE:
			if (sent) {
				if (f->len_fixed > r->n - r->pos)
					return CKR_MECHANISM_PARAM_INVALID;
				memcpy((char *)base + f->off, r->p + r->pos, f->len_fixed);
				r->pos += f->len_fixed;
			}
			break;
		case GCK_RPC_F_STRUCT:
			if (sent) {
				void *sub;

				if (r->n - r->pos < 1)
					return CKR_MECHANISM_PARAM_INVALID;
				if (r->p[r->pos++]) {
					sub = pr_alloc0(r, f->sub->size);
					if (!sub)
						return CKR_DEVICE_MEMORY;
					rv = dec_body(f->sub, phase, r, sub, NULL, depth + 1);
					if (rv != CKR_OK)
						return rv;
					memcpy((char *)base + f->off, &sub, sizeof(sub));
				}
			}
			break;
		}
	}
	return CKR_OK;
}

CK_RV gck_rpc_param_decode(const unsigned char *blob, size_t n, int phase,
			   GckRpcParamState *st,
			   void *(*alloc)(void *, size_t), void *ctx)
{
	const GckRpcParamDesc *d = NULL;
	struct prd r = { blob, n, 1, alloc, ctx };
	CK_RV rv;
	size_t i;

	memset(st, 0, sizeof(*st));
	if (n < 1)
		return CKR_MECHANISM_PARAM_INVALID;
	for (i = 0; i < sizeof(all_descs) / sizeof(all_descs[0]); ++i)
		if (all_descs[i]->kind == blob[0])
			d = all_descs[i];
	if (!d || !(d->phases & phase) || d->size > sizeof(st->s))
		return CKR_MECHANISM_PARAM_INVALID;

	rv = dec_body(d, phase, &r, &st->s, st->lens, 0);
	if (rv != CKR_OK)
		return rv;
	if (r.pos != n)
		return CKR_MECHANISM_PARAM_INVALID;
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
		if (d->fields[i].type != GCK_RPC_F_BUF || !d->fields[i].resp)
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
		if (d->fields[i].type != GCK_RPC_F_BUF || !d->fields[i].resp)
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
		if (d->fields[i].type != GCK_RPC_F_BUF || !d->fields[i].resp)
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
	case CKM_DSA_FIPS_G_GEN:
	case CKM_DSA_PROBABILISTIC_PARAMETER_GEN:
	case CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN:
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
