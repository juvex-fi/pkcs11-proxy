/*
 * Minimal PKCS#11 3.2 mock module for testing the proxy's wire format:
 * message-based AEAD (GCM, CCM, ChaCha20-Poly1305), single-part parameter
 * structures, sign-message and the async functions. It validates what it
 * receives and writes deterministic outputs (IV byte i = 0xB0 + i, tag 0xA5).
 */
#include <stdio.h>
#include <string.h>
#include "pkcs11/v3.2/pkcs11-platform.h"
#include "pkcs11/v3.2/pkcs11.h"

#define EXPORT __attribute__((visibility("default")))

static CK_MECHANISM_TYPE enc_mech, dec_mech;

static CK_RV m_Initialize(CK_VOID_PTR a) { return CKR_OK; }
static CK_RV m_Finalize(CK_VOID_PTR a) { return CKR_OK; }
static CK_RV m_GetSlotList(CK_BBOOL p, CK_SLOT_ID_PTR l, CK_ULONG_PTR n)
{
	if (l && *n >= 1) l[0] = 0;
	*n = 1;
	return CKR_OK;
}
static CK_RV m_OpenSession(CK_SLOT_ID s, CK_FLAGS f, CK_VOID_PTR a, CK_NOTIFY n, CK_SESSION_HANDLE_PTR h)
{ static CK_SESSION_HANDLE next = 1; *h = next++; return CKR_OK; }
static CK_RV m_CloseSession(CK_SESSION_HANDLE h) { return CKR_OK; }

/* ---- single-part GCM / CCM: verify the rebuilt parameter structs ---- */
static CK_RV m_EncryptInit(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE k)
{
	if (m->mechanism == CKM_AES_GCM) {
		CK_GCM_PARAMS *p = m->pParameter;
		if (!p || m->ulParameterLen != sizeof *p) return CKR_MECHANISM_PARAM_INVALID;
		if (p->ulIvLen != 12 || !p->pIv || memcmp(p->pIv, "0123456789ab", 12)) return CKR_MECHANISM_PARAM_INVALID;
		if (p->ulAADLen != 5 || !p->pAAD || memcmp(p->pAAD, "hello", 5)) return CKR_MECHANISM_PARAM_INVALID;
		if (p->ulTagBits != 96 || p->ulIvBits != 96) return CKR_MECHANISM_PARAM_INVALID;
	} else if (m->mechanism == CKM_AES_CCM) {
		CK_CCM_PARAMS *p = m->pParameter;
		if (!p || m->ulParameterLen != sizeof *p) return CKR_MECHANISM_PARAM_INVALID;
		if (p->ulDataLen != 16 || p->ulNonceLen != 7 || !p->pNonce || memcmp(p->pNonce, "NONCE07", 7)) return CKR_MECHANISM_PARAM_INVALID;
		if (p->ulAADLen != 3 || !p->pAAD || memcmp(p->pAAD, "aad", 3) || p->ulMACLen != 8) return CKR_MECHANISM_PARAM_INVALID;
	} else if (m->mechanism == CKM_CHACHA20_POLY1305) {
		CK_SALSA20_CHACHA20_POLY1305_PARAMS *p = m->pParameter;
		if (!p || p->ulNonceLen != 12 || !p->pNonce || memcmp(p->pNonce, "chachanonce!", 12)) return CKR_MECHANISM_PARAM_INVALID;
		if (p->ulAADLen != 4 || !p->pAAD || memcmp(p->pAAD, "adad", 4)) return CKR_MECHANISM_PARAM_INVALID;
	} else
		return CKR_MECHANISM_INVALID;
	return CKR_OK;
}

/* ---- message-based encryption ---- */
static CK_RV m_MessageEncryptInit(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE k)
{
	if (m->pParameter != NULL || m->ulParameterLen != 0) return CKR_MECHANISM_PARAM_INVALID;
	enc_mech = m->mechanism;
	return CKR_OK;
}
static CK_RV m_MessageDecryptInit(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE k)
{
	if (m->pParameter != NULL || m->ulParameterLen != 0) return CKR_MECHANISM_PARAM_INVALID;
	dec_mech = m->mechanism;
	return CKR_OK;
}

/* generate the variable part of the IV/nonce, keeping the caller's fixed prefix */
static void gen_iv(CK_BYTE_PTR iv, CK_ULONG len, CK_ULONG fixed_bits)
{
	CK_ULONG i, fb = fixed_bits / 8;
	for (i = fb; i < len; i++) iv[i] = (CK_BYTE)(0xB0 + i);
}
static int iv_ok(CK_BYTE_PTR iv, CK_ULONG len, CK_ULONG fixed_bits)
{
	CK_ULONG i, fb = fixed_bits / 8;
	for (i = fb; i < len; i++) if (iv[i] != (CK_BYTE)(0xB0 + i)) return 0;
	return 1;
}

/* Fill the generated IV; produce/verify the tag. */
static CK_RV do_msg(int encrypt, CK_MECHANISM_TYPE mech, CK_VOID_PTR par, CK_ULONG plen, int gen_iv_now, int do_tag, int check_tag)
{
	CK_BYTE_PTR iv, tag; CK_ULONG ivlen, ivfixed, taglen, gen;
	if (mech == CKM_AES_GCM) {
		CK_GCM_MESSAGE_PARAMS *p = par;
		if (plen != sizeof *p || !p->pIv || !p->pTag) return CKR_MECHANISM_PARAM_INVALID;
		iv = p->pIv; ivlen = p->ulIvLen; ivfixed = p->ulIvFixedBits; gen = p->ivGenerator;
		tag = p->pTag; taglen = (p->ulTagBits + 7) / 8;
	} else if (mech == CKM_AES_CCM) {
		CK_CCM_MESSAGE_PARAMS *p = par;
		if (plen != sizeof *p || !p->pNonce || !p->pMAC) return CKR_MECHANISM_PARAM_INVALID;
		if (p->ulDataLen != 32) return CKR_MECHANISM_PARAM_INVALID;
		iv = p->pNonce; ivlen = p->ulNonceLen; ivfixed = p->ulNonceFixedBits; gen = p->nonceGenerator;
		tag = p->pMAC; taglen = p->ulMACLen;
	} else if (mech == CKM_CHACHA20_POLY1305) {
		CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS *p = par;
		if (plen != sizeof *p || !p->pNonce || !p->pTag) return CKR_MECHANISM_PARAM_INVALID;
		iv = p->pNonce; ivlen = p->ulNonceLen; ivfixed = 0; gen = CKG_GENERATE_RANDOM;
		tag = p->pTag; taglen = 16;
	} else
		return CKR_MECHANISM_INVALID;
	(void)gen;
	/* a client pointer smuggled through would not be usable here; these writes prove ours are */
	if (gen_iv_now) gen_iv(iv, ivlen, ivfixed);
	if (encrypt && do_tag) memset(tag, 0xA5, taglen);
	if (check_tag) {
		CK_ULONG i;
		if (!iv_ok(iv, ivlen, ivfixed)) return CKR_ENCRYPTED_DATA_INVALID;
		for (i = 0; i < taglen; i++) if (tag[i] != 0xA5) return CKR_ENCRYPTED_DATA_INVALID;
	}
	return CKR_OK;
}

static CK_RV m_EncryptMessage(CK_SESSION_HANDLE s, CK_VOID_PTR par, CK_ULONG plen,
	CK_BYTE_PTR ad, CK_ULONG adl, CK_BYTE_PTR pt, CK_ULONG ptl, CK_BYTE_PTR ct, CK_ULONG_PTR ctl)
{
	CK_RV rv; CK_ULONG i;
	if (adl != 3 || memcmp(ad, "hdr", 3)) return CKR_DATA_INVALID;
	if (!ct) { *ctl = ptl; return CKR_OK; }
	if (*ctl < ptl) { *ctl = ptl; return CKR_BUFFER_TOO_SMALL; }
	rv = do_msg(1, enc_mech, par, plen, 1, 1, 0);
	if (rv != CKR_OK) return rv;
	for (i = 0; i < ptl; i++) ct[i] = pt[i] ^ 0x5A;
	*ctl = ptl;
	return CKR_OK;
}
static CK_RV m_DecryptMessage(CK_SESSION_HANDLE s, CK_VOID_PTR par, CK_ULONG plen,
	CK_BYTE_PTR ad, CK_ULONG adl, CK_BYTE_PTR ct, CK_ULONG ctl, CK_BYTE_PTR pt, CK_ULONG_PTR ptl)
{
	CK_RV rv; CK_ULONG i;
	if (adl != 3 || memcmp(ad, "hdr", 3)) return CKR_DATA_INVALID;
	if (!pt) { *ptl = ctl; return CKR_OK; }
	if (*ptl < ctl) { *ptl = ctl; return CKR_BUFFER_TOO_SMALL; }
	rv = do_msg(0, dec_mech, par, plen, 0, 0, 1);
	if (rv != CKR_OK) return rv;
	for (i = 0; i < ctl; i++) pt[i] = ct[i] ^ 0x5A;
	*ptl = ctl;
	return CKR_OK;
}
static CK_RV m_EncryptMessageBegin(CK_SESSION_HANDLE s, CK_VOID_PTR par, CK_ULONG plen, CK_BYTE_PTR ad, CK_ULONG adl)
{
	return do_msg(1, enc_mech, par, plen, 1, 0, 0);
}
static CK_RV m_EncryptMessageNext(CK_SESSION_HANDLE s, CK_VOID_PTR par, CK_ULONG plen,
	CK_BYTE_PTR pt, CK_ULONG ptl, CK_BYTE_PTR ct, CK_ULONG_PTR ctl, CK_FLAGS flags)
{
	CK_RV rv; CK_ULONG i;
	if (*ctl < ptl) { *ctl = ptl; return CKR_BUFFER_TOO_SMALL; }
	rv = do_msg(1, enc_mech, par, plen, 0, (flags & CKF_END_OF_MESSAGE) != 0, 0);
	if (rv != CKR_OK) return rv;
	for (i = 0; i < ptl; i++) ct[i] = pt[i] ^ 0x5A;
	*ctl = ptl;
	return CKR_OK;
}
static CK_RV m_DecryptMessageBegin(CK_SESSION_HANDLE s, CK_VOID_PTR par, CK_ULONG plen, CK_BYTE_PTR ad, CK_ULONG adl)
{
	return do_msg(0, dec_mech, par, plen, 0, 0, 1);
}
static CK_RV m_MessageEncryptFinal(CK_SESSION_HANDLE s) { return CKR_OK; }
static CK_RV m_MessageDecryptFinal(CK_SESSION_HANDLE s) { return CKR_OK; }

/* ---- sign message: parameter must arrive as NULL ---- */
static CK_RV m_MessageSignInit(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE k) { return CKR_OK; }
static CK_RV m_SignMessage(CK_SESSION_HANDLE s, CK_VOID_PTR par, CK_ULONG plen,
	CK_BYTE_PTR d, CK_ULONG dl, CK_BYTE_PTR sig, CK_ULONG_PTR sl)
{
	if (par != NULL || plen != 0) return CKR_MECHANISM_PARAM_INVALID;
	if (!sig) { *sl = 4; return CKR_OK; }
	memcpy(sig, "SIG!", 4); *sl = 4;
	return CKR_OK;
}

/* ---- async ---- */
static CK_RV m_AsyncGetID(CK_SESSION_HANDLE s, CK_UTF8CHAR_PTR name, CK_ULONG_PTR id)
{
	if (strcmp((char *)name, "C_Sign")) return CKR_ARGUMENTS_BAD;
	*id = 42;
	return CKR_OK;
}
static CK_RV m_AsyncJoin(CK_SESSION_HANDLE s, CK_UTF8CHAR_PTR name, CK_ULONG id, CK_BYTE_PTR data, CK_ULONG dl)
{
	if (strcmp((char *)name, "C_Sign") || id != 42) return CKR_ARGUMENTS_BAD;
	if (data) memset(data, 0x77, dl);
	return CKR_OK;
}
static CK_RV m_AsyncComplete(CK_SESSION_HANDLE s, CK_UTF8CHAR_PTR name, CK_ASYNC_DATA_PTR r)
{
	if (strcmp((char *)name, "C_Sign")) return CKR_ARGUMENTS_BAD;
	if (r->ulVersion != 3) return CKR_ARGUMENTS_BAD;	/* input must arrive */
	if (r->pValue == NULL || r->ulValue < 4) { r->ulValue = 4; return CKR_BUFFER_TOO_SMALL; }
	memcpy(r->pValue, "done", 4);
	r->ulValue = 4;
	r->hObject = 7;
	r->hAdditionalObject = 8;
	return CKR_OK;
}

static CK_FUNCTION_LIST_3_2 list32 = {
	.version = {3, 2},
	.C_Initialize = m_Initialize, .C_Finalize = m_Finalize,
	.C_GetSlotList = m_GetSlotList,
	.C_OpenSession = m_OpenSession, .C_CloseSession = m_CloseSession,
	.C_EncryptInit = m_EncryptInit,
	.C_MessageEncryptInit = m_MessageEncryptInit, .C_EncryptMessage = m_EncryptMessage,
	.C_EncryptMessageBegin = m_EncryptMessageBegin, .C_EncryptMessageNext = m_EncryptMessageNext,
	.C_MessageEncryptFinal = m_MessageEncryptFinal,
	.C_MessageDecryptInit = m_MessageDecryptInit, .C_DecryptMessage = m_DecryptMessage,
	.C_DecryptMessageBegin = m_DecryptMessageBegin, .C_MessageDecryptFinal = m_MessageDecryptFinal,
	.C_MessageSignInit = m_MessageSignInit, .C_SignMessage = m_SignMessage,
	.C_AsyncGetID = m_AsyncGetID, .C_AsyncJoin = m_AsyncJoin, .C_AsyncComplete = m_AsyncComplete,
};
static CK_FUNCTION_LIST list2 = {
	.version = {2, 40},
	.C_Initialize = m_Initialize, .C_Finalize = m_Finalize,
	.C_GetSlotList = m_GetSlotList,
	.C_OpenSession = m_OpenSession, .C_CloseSession = m_CloseSession,
	.C_EncryptInit = m_EncryptInit,
};

EXPORT CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR l) { *l = &list2; return CKR_OK; }
EXPORT CK_RV C_GetInterface(CK_UTF8CHAR_PTR name, CK_VERSION_PTR v, CK_INTERFACE_PTR_PTR out, CK_FLAGS f)
{
	static CK_INTERFACE i = { (CK_UTF8CHAR_PTR)"PKCS 11", &list32, 0 };
	*out = &i;
	return CKR_OK;
}
EXPORT CK_RV C_GetInterfaceList(CK_INTERFACE_PTR l, CK_ULONG_PTR n)
{
	*n = 0;
	return CKR_OK;
}
