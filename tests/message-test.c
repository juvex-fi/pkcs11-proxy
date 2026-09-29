/*
 * Message-based AEAD, single-part AEAD parameters, sign-message and async
 * functions through the proxy, against tests/mock-module.c.
 * Usage: message-test <libpkcs11-proxy>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include "pkcs11/v3.2/pkcs11-platform.h"
#include "pkcs11/v3.2/pkcs11.h"

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { printf("FAIL: " __VA_ARGS__); printf("\n"); fails++; } else { printf("ok:   " __VA_ARGS__); printf("\n"); } } while (0)
#define RV(name, rv, want) do { CK_RV _r = (rv); CHECK(_r == (want), "%s -> 0x%lx (want 0x%lx)", name, (unsigned long)_r, (unsigned long)(want)); } while (0)

static int all(const CK_BYTE *p, size_t n, CK_BYTE v) { for (size_t i = 0; i < n; i++) if (p[i] != v) return 0; return 1; }
static int gen_ok(const CK_BYTE *iv, size_t from, size_t len) { for (size_t i = from; i < len; i++) if (iv[i] != (CK_BYTE)(0xB0 + i)) return 0; return 1; }

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	void *h = dlopen(argv[1], RTLD_NOW);
	if (!h) { printf("dlopen: %s\n", dlerror()); return 2; }
	CK_C_GetInterface gi = dlsym(h, "C_GetInterface");
	CK_C_GetFunctionList gfl = dlsym(h, "C_GetFunctionList");
	CK_INTERFACE_PTR iface = NULL; CK_VERSION ver = {3, 2};
	CK_RV rv = gi((CK_UTF8CHAR_PTR)"PKCS 11", &ver, &iface, 0);
	RV("C_GetInterface", rv, CKR_OK);
	CK_FUNCTION_LIST_3_2_PTR f = iface->pFunctionList;
	CK_INTERFACE_PTR tmp;
	rv = gi((CK_UTF8CHAR_PTR)"PKCS 11", &ver, &tmp, 1);
	RV("C_GetInterface(flags=FORK_SAFE)", rv, CKR_ARGUMENTS_BAD);
	CK_FUNCTION_LIST_PTR l2; gfl(&l2);
	CHECK(l2->version.major == 2 && l2->version.minor == 40, "2.x function list says %d.%d", l2->version.major, l2->version.minor);

	RV("C_Initialize", f->C_Initialize(NULL), CKR_OK);
	CK_SLOT_ID slots[4]; CK_ULONG ns = 4;
	RV("C_GetSlotList", f->C_GetSlotList(CK_TRUE, slots, &ns), CKR_OK);
	CK_SESSION_HANDLE s;
	RV("C_OpenSession", f->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &s), CKR_OK);

	CK_BYTE pt[32], ct[32], out[32];
	for (int i = 0; i < 32; i++) pt[i] = (CK_BYTE)i;
	CK_ULONG cl;

	/* ================= AES-GCM message ================= */
	CK_MECHANISM gcm = {CKM_AES_GCM, NULL, 0};
	RV("MessageEncryptInit(GCM)", f->C_MessageEncryptInit(s, &gcm, 1), CKR_OK);
	CK_BYTE iv[12], tag[16];
	memset(iv, 0xEE, sizeof iv); memcpy(iv, "FIXD", 4); memset(tag, 0xEE, sizeof tag);
	CK_GCM_MESSAGE_PARAMS gp = { iv, 12, 32, CKG_GENERATE_RANDOM, tag, 128 };

	cl = 4;
	rv = f->C_EncryptMessage(s, &gp, sizeof gp, (CK_BYTE_PTR)"hdr", 3, pt, 32, ct, &cl);
	RV("EncryptMessage too small", rv, CKR_BUFFER_TOO_SMALL);
	CHECK(iv[4] == 0xEE && tag[0] == 0xEE, "outputs untouched after CKR_BUFFER_TOO_SMALL");
	cl = 0;
	rv = f->C_EncryptMessage(s, &gp, sizeof gp, (CK_BYTE_PTR)"hdr", 3, pt, 32, NULL, &cl);
	CHECK(rv == CKR_OK && cl == 32, "EncryptMessage size query (0x%lx, %lu)", (unsigned long)rv, (unsigned long)cl);
	cl = sizeof ct;
	rv = f->C_EncryptMessage(s, &gp, sizeof gp, (CK_BYTE_PTR)"hdr", 3, pt, 32, ct, &cl);
	RV("EncryptMessage", rv, CKR_OK);
	CHECK(memcmp(iv, "FIXD", 4) == 0, "caller's fixed IV prefix preserved");
	CHECK(gen_ok(iv, 4, 12), "generated IV returned to caller");
	CHECK(all(tag, 16, 0xA5), "tag returned to caller");
	{ int ok = 1; for (int i = 0; i < 32; i++) if (ct[i] != (pt[i] ^ 0x5A)) ok = 0; CHECK(ok, "ciphertext correct"); }
	RV("MessageEncryptFinal", f->C_MessageEncryptFinal(s), CKR_OK);

	RV("MessageDecryptInit(GCM)", f->C_MessageDecryptInit(s, &gcm, 1), CKR_OK);
	cl = sizeof out;
	rv = f->C_DecryptMessage(s, &gp, sizeof gp, (CK_BYTE_PTR)"hdr", 3, ct, 32, out, &cl);
	RV("DecryptMessage", rv, CKR_OK);
	CHECK(cl == 32 && memcmp(out, pt, 32) == 0, "plaintext recovered");
	tag[0] ^= 1; cl = sizeof out;
	rv = f->C_DecryptMessage(s, &gp, sizeof gp, (CK_BYTE_PTR)"hdr", 3, ct, 32, out, &cl);
	RV("DecryptMessage bad tag", rv, CKR_ENCRYPTED_DATA_INVALID);
	tag[0] ^= 1;
	RV("MessageDecryptFinal", f->C_MessageDecryptFinal(s), CKR_OK);

	/* bad struct size is refused before anything is sent */
	cl = sizeof ct;
	rv = f->C_EncryptMessage(s, &gp, 5, (CK_BYTE_PTR)"hdr", 3, pt, 32, ct, &cl);
	RV("EncryptMessage bad param size", rv, CKR_MECHANISM_PARAM_INVALID);

	/* ================= streaming ================= */
	RV("MessageEncryptInit(GCM) #2", f->C_MessageEncryptInit(s, &gcm, 1), CKR_OK);
	memset(iv, 0xEE, sizeof iv); memcpy(iv, "FIXD", 4); memset(tag, 0xEE, sizeof tag);
	RV("EncryptMessageBegin", f->C_EncryptMessageBegin(s, &gp, sizeof gp, (CK_BYTE_PTR)"hdr", 3), CKR_OK);
	CHECK(gen_ok(iv, 4, 12) && tag[0] == 0xEE, "IV generated at Begin, tag not yet");
	cl = 16;
	RV("EncryptMessageNext(part)", f->C_EncryptMessageNext(s, &gp, sizeof gp, pt, 16, ct, &cl, 0), CKR_OK);
	CHECK(tag[0] == 0xEE, "no tag before end of message");
	cl = 16;
	RV("EncryptMessageNext(end)", f->C_EncryptMessageNext(s, &gp, sizeof gp, pt + 16, 16, ct + 16, &cl, CKF_END_OF_MESSAGE), CKR_OK);
	CHECK(all(tag, 16, 0xA5), "tag returned at end of message");
	RV("MessageEncryptFinal #2", f->C_MessageEncryptFinal(s), CKR_OK);

	/* ================= AES-CCM message ================= */
	CK_MECHANISM ccm = {CKM_AES_CCM, NULL, 0};
	RV("MessageEncryptInit(CCM)", f->C_MessageEncryptInit(s, &ccm, 1), CKR_OK);
	CK_BYTE nonce[7], mac[8];
	memset(nonce, 0xEE, sizeof nonce); nonce[0] = 'N'; memset(mac, 0xEE, sizeof mac);
	CK_CCM_MESSAGE_PARAMS cp = { 32, nonce, 7, 8, CKG_GENERATE_RANDOM, mac, 8 };
	cl = sizeof ct;
	rv = f->C_EncryptMessage(s, &cp, sizeof cp, (CK_BYTE_PTR)"hdr", 3, pt, 32, ct, &cl);
	RV("EncryptMessage(CCM)", rv, CKR_OK);
	CHECK(nonce[0] == 'N' && gen_ok(nonce, 1, 7) && all(mac, 8, 0xA5), "CCM nonce and MAC returned");

	/* ================= ChaCha20-Poly1305 message ================= */
	CK_MECHANISM cc = {CKM_CHACHA20_POLY1305, NULL, 0};
	RV("MessageEncryptInit(ChaCha)", f->C_MessageEncryptInit(s, &cc, 1), CKR_OK);
	CK_BYTE cn[12], ctag[16];
	memset(cn, 0xEE, sizeof cn); memset(ctag, 0xEE, sizeof ctag);
	CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS chp = { cn, 12, ctag };
	cl = sizeof ct;
	rv = f->C_EncryptMessage(s, &chp, sizeof chp, (CK_BYTE_PTR)"hdr", 3, pt, 32, ct, &cl);
	RV("EncryptMessage(ChaCha)", rv, CKR_OK);
	CHECK(gen_ok(cn, 0, 12) && all(ctag, 16, 0xA5), "ChaCha nonce and tag returned");

	/* ================= single-part mechanism parameters ================= */
	{
		CK_GCM_PARAMS p = { (CK_BYTE_PTR)"0123456789ab", 12, 96, (CK_BYTE_PTR)"hello", 5, 96 };
		CK_MECHANISM m = { CKM_AES_GCM, &p, sizeof p };
		RV("EncryptInit(CK_GCM_PARAMS)", f->C_EncryptInit(s, &m, 1), CKR_OK);
		m.ulParameterLen = 3;
		RV("EncryptInit(GCM, wrong size)", f->C_EncryptInit(s, &m, 1), CKR_MECHANISM_PARAM_INVALID);
		CK_GCM_PARAMS bad = { NULL, 12, 96, NULL, 0, 96 };
		CK_MECHANISM mb = { CKM_AES_GCM, &bad, sizeof bad };
		RV("EncryptInit(GCM, NULL IV with length)", f->C_EncryptInit(s, &mb, 1), CKR_MECHANISM_PARAM_INVALID);
	}
	{
		CK_CCM_PARAMS p = { 16, (CK_BYTE_PTR)"NONCE07", 7, (CK_BYTE_PTR)"aad", 3, 8 };
		CK_MECHANISM m = { CKM_AES_CCM, &p, sizeof p };
		RV("EncryptInit(CK_CCM_PARAMS)", f->C_EncryptInit(s, &m, 1), CKR_OK);
	}
	{
		CK_SALSA20_CHACHA20_POLY1305_PARAMS p = { (CK_BYTE_PTR)"chachanonce!", 12, (CK_BYTE_PTR)"adad", 4 };
		CK_MECHANISM m = { CKM_CHACHA20_POLY1305, &p, sizeof p };
		RV("EncryptInit(ChaCha params)", f->C_EncryptInit(s, &m, 1), CKR_OK);
	}

	/* ================= sign message ================= */
	CK_MECHANISM hm = {CKM_SHA256_HMAC, NULL, 0};
	RV("MessageSignInit", f->C_MessageSignInit(s, &hm, 1), CKR_OK);
	CK_BYTE sig[16]; CK_ULONG sl = sizeof sig;
	rv = f->C_SignMessage(s, NULL, 0, pt, 8, sig, &sl);
	CHECK(rv == CKR_OK && sl == 4 && memcmp(sig, "SIG!", 4) == 0, "SignMessage (0x%lx)", (unsigned long)rv);
	sl = sizeof sig;
	rv = f->C_SignMessage(s, &gp, sizeof gp, pt, 8, sig, &sl);
	RV("SignMessage with a parameter", rv, CKR_MECHANISM_PARAM_INVALID);

	/* ================= async ================= */
	CK_ULONG id = 0;
	rv = f->C_AsyncGetID(s, (CK_UTF8CHAR_PTR)"C_Sign", &id);
	CHECK(rv == CKR_OK && id == 42, "AsyncGetID -> %lu (0x%lx)", (unsigned long)id, (unsigned long)rv);
	CK_BYTE jd[8]; memset(jd, 0, sizeof jd);
	rv = f->C_AsyncJoin(s, (CK_UTF8CHAR_PTR)"C_Sign", 42, jd, sizeof jd);
	CHECK(rv == CKR_OK && all(jd, 8, 0x77), "AsyncJoin fills caller's buffer (0x%lx)", (unsigned long)rv);
	CK_BYTE vbuf[16]; memset(vbuf, 0, sizeof vbuf);
	CK_ASYNC_DATA ad = { 3, vbuf, sizeof vbuf, 0, 0 };
	rv = f->C_AsyncComplete(s, (CK_UTF8CHAR_PTR)"C_Sign", &ad);
	RV("AsyncComplete", rv, CKR_OK);
	CHECK(ad.ulValue == 4 && memcmp(vbuf, "done", 4) == 0, "AsyncComplete value (%lu)", (unsigned long)ad.ulValue);
	CHECK(ad.hObject == 7 && ad.hAdditionalObject == 8 && ad.ulVersion == 3, "AsyncComplete handles/version (%lu,%lu,%lu)",
	      (unsigned long)ad.hObject, (unsigned long)ad.hAdditionalObject, (unsigned long)ad.ulVersion);
	CK_ASYNC_DATA small = { 3, vbuf, 2, 0, 0 };
	rv = f->C_AsyncComplete(s, (CK_UTF8CHAR_PTR)"C_Sign", &small);
	CHECK(rv == CKR_BUFFER_TOO_SMALL && small.ulValue == 4, "AsyncComplete small buffer (0x%lx, %lu)", (unsigned long)rv, (unsigned long)small.ulValue);


	/* ================= type confusion is refused by the daemon ================= */
	RV("MessageEncryptInit(GCM) again", f->C_MessageEncryptInit(s, &gcm, 1), CKR_OK);
	cl = sizeof ct;
	rv = f->C_EncryptMessage(s, &cp, sizeof cp, (CK_BYTE_PTR)"hdr", 3, pt, 32, ct, &cl);
	RV("CCM params on a GCM session", rv, CKR_MECHANISM_PARAM_INVALID);
	rv = f->C_EncryptMessage(s, &chp, sizeof chp, (CK_BYTE_PTR)"hdr", 3, pt, 32, ct, &cl);
	RV("ChaCha params on a GCM session", rv, CKR_MECHANISM_PARAM_INVALID);
	{
		CK_SESSION_HANDLE s2;
		RV("C_OpenSession #2", f->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &s2), CKR_OK);
		cl = sizeof ct;
		rv = f->C_EncryptMessage(s2, &gp, sizeof gp, (CK_BYTE_PTR)"hdr", 3, pt, 32, ct, &cl);
		RV("message params on a fresh session", rv, CKR_OPERATION_NOT_INITIALIZED);
		cl = sizeof out;
		rv = f->C_DecryptMessage(s2, &gp, sizeof gp, (CK_BYTE_PTR)"hdr", 3, ct, 32, out, &cl);
		RV("decrypt params on a fresh session", rv, CKR_OPERATION_NOT_INITIALIZED);
		cl = sizeof ct;
		rv = f->C_EncryptMessage(s, &gp, sizeof gp, (CK_BYTE_PTR)"hdr", 3, pt, 32, ct, &cl);
		RV("GCM params on the GCM session still work", rv, CKR_OK);
	}

	f->C_Finalize(NULL);
	printf("\n%d failure(s)\n", fails);
	return fails != 0;
}
