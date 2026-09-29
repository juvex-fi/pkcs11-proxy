/*
 * Mechanism parameters through the proxy, against tests/mock-module.c which
 * checks every field it is handed: ECDH, HKDF, EdDSA, ChaCha20/Salsa20,
 * key derivation from data, RSA-AES and ECDH-AES key wrap, general MACs and
 * IV-carrying mechanisms, plus what the client must refuse.
 * Usage: mechanism-test <libpkcs11-proxy>
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

static CK_FUNCTION_LIST_PTR f;
static CK_SESSION_HANDLE s;

static CK_RV derive(CK_MECHANISM_TYPE type, void *param, CK_ULONG len)
{
	CK_MECHANISM m = { type, param, len };
	CK_OBJECT_HANDLE k = 0;
	CK_RV rv = f->C_DeriveKey(s, &m, 1, NULL, 0, &k);
	if (rv == CKR_OK && k != 99) return CKR_GENERAL_ERROR;
	return rv;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	void *h = dlopen(argv[1], RTLD_NOW);
	if (!h) { printf("dlopen: %s\n", dlerror()); return 2; }
	CK_C_GetFunctionList gfl = dlsym(h, "C_GetFunctionList");
	gfl(&f);
	RV("C_Initialize", f->C_Initialize(NULL), CKR_OK);
	CK_SLOT_ID slots[4]; CK_ULONG ns = 4;
	RV("C_GetSlotList", f->C_GetSlotList(CK_TRUE, slots, &ns), CKR_OK);
	RV("C_OpenSession", f->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &s), CKR_OK);

	/* ---- key derivation with pointer-carrying parameters ---- */
	{
		CK_ECDH1_DERIVE_PARAMS p = { CKD_NULL, 11, (CK_BYTE_PTR)"shared-data", 18, (CK_BYTE_PTR)"public-point-bytes" };
		RV("ECDH1_DERIVE", derive(CKM_ECDH1_DERIVE, &p, sizeof p), CKR_OK);
		CK_ECDH1_DERIVE_PARAMS c = { CKD_NULL, 0, NULL, 4, (CK_BYTE_PTR)"abcd" };
		RV("ECDH1_COFACTOR_DERIVE without shared data", derive(CKM_ECDH1_COFACTOR_DERIVE, &c, sizeof c), CKR_OK);
		CK_ECDH1_DERIVE_PARAMS bad = { CKD_NULL, 11, NULL, 0, NULL };
		RV("ECDH1 with a NULL pointer and a length", derive(CKM_ECDH1_DERIVE, &bad, sizeof bad), CKR_MECHANISM_PARAM_INVALID);
		RV("ECDH1 with a short parameter", derive(CKM_ECDH1_DERIVE, &p, 8), CKR_MECHANISM_PARAM_INVALID);
	}
	{
		CK_HKDF_PARAMS p = { CK_TRUE, CK_TRUE, CKM_SHA256, CKF_HKDF_SALT_DATA, (CK_BYTE_PTR)"salt!", 5, 0, (CK_BYTE_PTR)"info-info", 9 };
		RV("HKDF_DERIVE", derive(CKM_HKDF_DERIVE, &p, sizeof p), CKR_OK);
	}
	{
		CK_KEY_DERIVATION_STRING_DATA p = { (CK_BYTE_PTR)"suffix", 6 };
		RV("CONCATENATE_BASE_AND_DATA", derive(CKM_CONCATENATE_BASE_AND_DATA, &p, sizeof p), CKR_OK);
	}
	{
		CK_BYTE data[32];
		for (int i = 0; i < 32; i++) data[i] = (CK_BYTE)(i * 5);
		CK_AES_CBC_ENCRYPT_DATA_PARAMS p; memset(&p, 0x11, sizeof p.iv); memcpy(p.iv, "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11", 16);
		p.pData = data; p.length = 32;
		RV("AES_CBC_ENCRYPT_DATA (iv[16] inside the structure)", derive(CKM_AES_CBC_ENCRYPT_DATA, &p, sizeof p), CKR_OK);
		CK_DES_CBC_ENCRYPT_DATA_PARAMS d; memcpy(d.iv, "8bytesIV", 8); d.pData = (CK_BYTE_PTR)"0123456789abcdef"; d.length = 16;
		RV("DES_CBC_ENCRYPT_DATA", derive(CKM_DES_CBC_ENCRYPT_DATA, &d, sizeof d), CKR_OK);
	}
	{
		CK_BYTE pub[300];
		for (int i = 0; i < 300; i++) pub[i] = (CK_BYTE)(i * 3);
		RV("DH_PKCS_DERIVE (public value, 300 bytes)", derive(CKM_DH_PKCS_DERIVE, pub, 300), CKR_OK);
		RV("DH_PKCS_DERIVE (too long)", derive(CKM_DH_PKCS_DERIVE, pub, 5000), CKR_MECHANISM_PARAM_INVALID);
		CK_OBJECT_HANDLE hk = 1234;
		RV("CONCATENATE_BASE_AND_KEY", derive(CKM_CONCATENATE_BASE_AND_KEY, &hk, sizeof hk), CKR_OK);
		RV("SHA256_KEY_DERIVATION (no parameter)", derive(CKM_SHA256_KEY_DERIVATION, NULL, 0), CKR_OK);
	}

	/* ---- signing ---- */
	{
		CK_MECHANISM m = { CKM_ECDSA_SHA256, NULL, 0 };
		RV("ECDSA_SHA256", f->C_SignInit(s, &m, 1), CKR_OK);
		m.mechanism = CKM_ECDSA_SHA3_256; RV("ECDSA_SHA3_256", f->C_SignInit(s, &m, 1), CKR_OK);
		m.mechanism = CKM_DSA_SHA512; RV("DSA_SHA512", f->C_SignInit(s, &m, 1), CKR_OK);
		m.mechanism = CKM_EDDSA; RV("EDDSA (pure, no parameter)", f->C_SignInit(s, &m, 1), CKR_OK);
		CK_EDDSA_PARAMS ep = { CK_TRUE, 4, (CK_BYTE_PTR)"ctx!" };
		CK_MECHANISM em = { CKM_EDDSA, &ep, sizeof ep };
		RV("EDDSA (Ed25519ph with a context)", f->C_SignInit(s, &em, 1), CKR_OK);
		CK_ULONG macbits = 16;
		CK_MECHANISM gm = { CKM_SHA256_HMAC_GENERAL, &macbits, sizeof macbits };
		RV("SHA256_HMAC_GENERAL (MAC length)", f->C_SignInit(s, &gm, 1), CKR_OK);
		gm.ulParameterLen = 4;
		RV("SHA256_HMAC_GENERAL (short parameter)", f->C_SignInit(s, &gm, 1), CKR_MECHANISM_PARAM_INVALID);
	}

	/* ---- stream ciphers and IVs ---- */
	{
		CK_CHACHA20_PARAMS p = { (CK_BYTE_PTR)"\1\2\3\4", 32, (CK_BYTE_PTR)"chachanonce!", 96 };
		CK_MECHANISM m = { CKM_CHACHA20, &p, sizeof p };
		RV("CHACHA20 (counter and nonce given in bits)", f->C_EncryptInit(s, &m, 1), CKR_OK);
		CK_SALSA20_PARAMS q = { (CK_BYTE_PTR)"counter8", (CK_BYTE_PTR)"nonce-08", 64 };
		CK_MECHANISM sm = { CKM_SALSA20, &q, sizeof q };
		RV("SALSA20", f->C_EncryptInit(s, &sm, 1), CKR_OK);
		CK_MECHANISM cts = { CKM_AES_CTS, "0123456789abcdef", 16 };
		RV("AES_CTS (16-byte IV)", f->C_EncryptInit(s, &cts, 1), CKR_OK);
		cts.ulParameterLen = 15;
		RV("AES_CTS (15-byte IV)", f->C_EncryptInit(s, &cts, 1), CKR_MECHANISM_PARAM_INVALID);
		CK_MECHANISM dc = { CKM_DES_CFB8, "01234567", 8 };
		RV("DES_CFB8 (8-byte IV)", f->C_EncryptInit(s, &dc, 1), CKR_OK);
	}

	/* ---- key wrap with a parameter that points at another structure ---- */
	{
		CK_RSA_PKCS_OAEP_PARAMS o = { CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, (void *)"lbl", 3 };
		CK_RSA_AES_KEY_WRAP_PARAMS p = { 256, &o };
		CK_MECHANISM m = { CKM_RSA_AES_KEY_WRAP, &p, sizeof p };
		CK_BYTE out[16]; CK_ULONG ol = sizeof out;
		RV("RSA_AES_KEY_WRAP (nested OAEP parameters)", f->C_WrapKey(s, &m, 1, 2, out, &ol), CKR_OK);
		CHECK(ol == 4 && memcmp(out, "WRAP", 4) == 0, "wrapped key returned");
		CK_RSA_AES_KEY_WRAP_PARAMS np = { 256, NULL };
		m.pParameter = &np;
		ol = sizeof out;
		RV("RSA_AES_KEY_WRAP without OAEP parameters", f->C_WrapKey(s, &m, 1, 2, out, &ol), CKR_MECHANISM_PARAM_INVALID);
		CK_ECDH_AES_KEY_WRAP_PARAMS ep = { 256, CKD_NULL, 4, (CK_BYTE_PTR)"shar" };
		CK_MECHANISM em = { CKM_ECDH_AES_KEY_WRAP, &ep, sizeof ep };
		ol = sizeof out;
		RV("ECDH_AES_KEY_WRAP", f->C_WrapKey(s, &em, 1, 2, out, &ol), CKR_OK);
	}

	/* mechanisms the proxy doesn't handle are refused, not forwarded */
	{
		CK_MECHANISM m = { CKM_X3DH_INITIALIZE, "x", 1 };
		RV("unsupported mechanism", f->C_SignInit(s, &m, 1), CKR_MECHANISM_INVALID);
	}

	f->C_Finalize(NULL);
	printf("\n%d failure(s)\n", fails);
	return fails != 0;
}
