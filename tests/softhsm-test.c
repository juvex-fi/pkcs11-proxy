/*
 * Attribute templates and mechanism parameters through the proxy against a
 * real module (SoftHSM): wrap/derive templates (nested CK_ATTRIBUTE arrays),
 * RSA-OAEP and PSS, AES-GCM, AES-CBC and AES-CTR.
 * Usage: softhsm-test <libpkcs11-proxy> ; the token must have user PIN 1234.
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

static CK_FUNCTION_LIST_3_2_PTR f;
static CK_SESSION_HANDLE s;

static CK_OBJECT_HANDLE gen_aes(CK_ATTRIBUTE *extra, CK_ULONG n_extra, CK_RV *rv_out)
{
	CK_OBJECT_CLASS sk = CKO_SECRET_KEY; CK_KEY_TYPE kt = CKK_AES;
	CK_ULONG len = 32; CK_BBOOL T = CK_TRUE, F = CK_FALSE;
	CK_ATTRIBUTE t[16] = {
		{CKA_CLASS, &sk, sizeof sk}, {CKA_KEY_TYPE, &kt, sizeof kt}, {CKA_VALUE_LEN, &len, sizeof len},
		{CKA_TOKEN, &F, 1}, {CKA_ENCRYPT, &T, 1}, {CKA_DECRYPT, &T, 1},
	};
	CK_MECHANISM m = {CKM_AES_KEY_GEN, NULL, 0};
	CK_OBJECT_HANDLE k = 0;
	for (CK_ULONG i = 0; i < n_extra; i++) t[6 + i] = extra[i];
	*rv_out = f->C_GenerateKey(s, &m, t, 6 + n_extra, &k);
	return k;
}

static void test_templates(void)
{
	CK_KEY_TYPE inner_kt = CKK_AES; CK_ULONG inner_len = 16;
	CK_ATTRIBUTE wrap[2] = { {CKA_KEY_TYPE, &inner_kt, sizeof inner_kt}, {CKA_VALUE_LEN, &inner_len, sizeof inner_len} };
	CK_ATTRIBUTE extra[1] = { {CKA_WRAP_TEMPLATE, wrap, sizeof wrap} };
	CK_RV rv;
	CK_OBJECT_HANDLE k = gen_aes(extra, 1, &rv);
	RV("GenerateKey with a wrap template", rv, CKR_OK);
	if (rv != CKR_OK) return;

	/* read the template back into caller-provided nested buffers */
	{
		CK_KEY_TYPE kt = 0; CK_ULONG vl = 0;
		CK_ATTRIBUTE out[2] = { {CKA_KEY_TYPE, &kt, sizeof kt}, {CKA_VALUE_LEN, &vl, sizeof vl} };
		CK_ATTRIBUTE g = {CKA_WRAP_TEMPLATE, out, sizeof out};
		rv = f->C_GetAttributeValue(s, k, &g, 1);
		RV("GetAttributeValue(WRAP_TEMPLATE)", rv, CKR_OK);
		CHECK(g.ulValueLen == sizeof out, "template length %lu", (unsigned long)g.ulValueLen);
		CHECK(kt == CKK_AES && vl == 16 && out[0].ulValueLen == sizeof kt && out[1].ulValueLen == sizeof vl,
		      "nested values returned into the caller's buffers (%lx, %lu)", (unsigned long)kt, (unsigned long)vl);
	}
	/* only the size */
	{
		CK_ATTRIBUTE g = {CKA_WRAP_TEMPLATE, NULL, 0};
		rv = f->C_GetAttributeValue(s, k, &g, 1);
		CHECK(rv == CKR_OK && g.ulValueLen == 2 * sizeof(CK_ATTRIBUTE), "template size query -> %lu (0x%lx)", (unsigned long)g.ulValueLen, (unsigned long)rv);
	}
	/* a nested buffer that is too small must not overflow anything */
	{
		CK_KEY_TYPE kt_small[1]; char tiny[2];
		CK_ATTRIBUTE out[2] = { {CKA_KEY_TYPE, tiny, sizeof tiny}, {CKA_VALUE_LEN, kt_small, sizeof kt_small} };
		CK_ATTRIBUTE g = {CKA_WRAP_TEMPLATE, out, sizeof out};
		rv = f->C_GetAttributeValue(s, k, &g, 1);
		CHECK(rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL, "too-small nested buffer handled (0x%lx)", (unsigned long)rv);
	}
	/* a derive template, if the module allows one on this kind of key */
	{
		CK_ATTRIBUTE derive[1] = { {CKA_LABEL, "derived", 7} };
		CK_ATTRIBUTE dx[1] = { {CKA_DERIVE_TEMPLATE, derive, sizeof derive} };
		CK_OBJECT_HANDLE d = gen_aes(dx, 1, &rv);
		CHECK(rv == CKR_OK || rv == CKR_ATTRIBUTE_TYPE_INVALID, "derive template: 0x%lx", (unsigned long)rv);
		if (rv == CKR_OK) {
			char label[16] = {0};
			CK_ATTRIBUTE out[1] = { {CKA_LABEL, label, sizeof label} };
			CK_ATTRIBUTE g = {CKA_DERIVE_TEMPLATE, out, sizeof out};
			rv = f->C_GetAttributeValue(s, d, &g, 1);
			CHECK(rv == CKR_OK && out[0].ulValueLen == 7 && memcmp(label, "derived", 7) == 0,
			      "DERIVE_TEMPLATE label read back (0x%lx)", (unsigned long)rv);
		}
	}
	/* malformed templates are refused by the client before anything is sent */
	{
		CK_ATTRIBUTE bad[1] = { {CKA_WRAP_TEMPLATE, wrap, sizeof(CK_ATTRIBUTE) - 1} };
		gen_aes(bad, 1, &rv);
		RV("template of a non-multiple size", rv, CKR_ATTRIBUTE_VALUE_INVALID);
		CK_ATTRIBUTE nest[1] = { {CKA_WRAP_TEMPLATE, wrap, sizeof(CK_ATTRIBUTE)} };
		CK_ATTRIBUTE outer[1] = { {CKA_UNWRAP_TEMPLATE, nest, sizeof nest} };
		gen_aes(outer, 1, &rv);
		CHECK(rv != CKR_OK, "template nested in a template refused (0x%lx)", (unsigned long)rv);
	}
	/* the daemon is still up and the session is fine */
	gen_aes(NULL, 0, &rv);
	RV("daemon still serving", rv, CKR_OK);
}

static void test_aes(void)
{
	CK_RV rv; CK_OBJECT_HANDLE k = gen_aes(NULL, 0, &rv);
	CK_BYTE pt[48], ct[128], out[128];
	CK_ULONG cl, ol;
	for (int i = 0; i < 48; i++) pt[i] = (CK_BYTE)(i * 7);
	RV("AES key", rv, CKR_OK);

	/* GCM: pointer-carrying parameter (IV and AAD) */
	{
		CK_GCM_PARAMS p = { (CK_BYTE_PTR)"0123456789ab", 12, 96, (CK_BYTE_PTR)"hdr", 3, 128 };
		CK_MECHANISM m = { CKM_AES_GCM, &p, sizeof p };
		RV("GCM EncryptInit", f->C_EncryptInit(s, &m, k), CKR_OK);
		cl = sizeof ct;
		RV("GCM Encrypt", f->C_Encrypt(s, pt, 48, ct, &cl), CKR_OK);
		CHECK(cl == 48 + 16, "GCM ciphertext length %lu", (unsigned long)cl);
		RV("GCM DecryptInit", f->C_DecryptInit(s, &m, k), CKR_OK);
		ol = sizeof out;
		RV("GCM Decrypt", f->C_Decrypt(s, ct, cl, out, &ol), CKR_OK);
		CHECK(ol == 48 && memcmp(out, pt, 48) == 0, "GCM round trip");
		/* the AAD reached the module: a different one must fail authentication */
		CK_GCM_PARAMS p2 = { (CK_BYTE_PTR)"0123456789ab", 12, 96, (CK_BYTE_PTR)"HDR", 3, 128 };
		CK_MECHANISM m2 = { CKM_AES_GCM, &p2, sizeof p2 };
		RV("GCM DecryptInit (other AAD)", f->C_DecryptInit(s, &m2, k), CKR_OK);
		ol = sizeof out;
		rv = f->C_Decrypt(s, ct, cl, out, &ol);
		CHECK(rv != CKR_OK, "GCM with different AAD rejected (0x%lx)", (unsigned long)rv);
	}
	/* CBC: flat parameter (the IV) */
	{
		CK_BYTE iv[16]; memset(iv, 0x33, 16);
		CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, 16 };
		RV("CBC EncryptInit", f->C_EncryptInit(s, &m, k), CKR_OK);
		cl = sizeof ct;
		RV("CBC Encrypt", f->C_Encrypt(s, pt, 48, ct, &cl), CKR_OK);
		RV("CBC DecryptInit", f->C_DecryptInit(s, &m, k), CKR_OK);
		ol = sizeof out;
		RV("CBC Decrypt", f->C_Decrypt(s, ct, cl, out, &ol), CKR_OK);
		CHECK(ol == 48 && memcmp(out, pt, 48) == 0, "CBC round trip");
		CK_MECHANISM bad = { CKM_AES_CBC_PAD, iv, 15 };
		RV("CBC with a 15-byte IV", f->C_EncryptInit(s, &bad, k), CKR_MECHANISM_PARAM_INVALID);
	}
	/* CTR: flat structure */
	{
		CK_AES_CTR_PARAMS p; memset(&p, 0, sizeof p); p.ulCounterBits = 64; memset(p.cb, 0x44, 16);
		CK_MECHANISM m = { CKM_AES_CTR, &p, sizeof p };
		RV("CTR EncryptInit", f->C_EncryptInit(s, &m, k), CKR_OK);
		cl = sizeof ct;
		RV("CTR Encrypt", f->C_Encrypt(s, pt, 48, ct, &cl), CKR_OK);
		RV("CTR DecryptInit", f->C_DecryptInit(s, &m, k), CKR_OK);
		ol = sizeof out;
		RV("CTR Decrypt", f->C_Decrypt(s, ct, cl, out, &ol), CKR_OK);
		CHECK(ol == 48 && memcmp(out, pt, 48) == 0, "CTR round trip");
	}
}

static void test_rsa(void)
{
	CK_ULONG bits = 2048; CK_BYTE e[] = {1, 0, 1}; CK_BBOOL T = CK_TRUE, F = CK_FALSE;
	CK_ATTRIBUTE pt_[] = { {CKA_MODULUS_BITS, &bits, sizeof bits}, {CKA_PUBLIC_EXPONENT, e, 3},
			       {CKA_ENCRYPT, &T, 1}, {CKA_VERIFY, &T, 1}, {CKA_TOKEN, &F, 1} };
	CK_ATTRIBUTE vt_[] = { {CKA_DECRYPT, &T, 1}, {CKA_SIGN, &T, 1}, {CKA_TOKEN, &F, 1} };
	CK_MECHANISM kg = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
	CK_OBJECT_HANDLE pub, prv;
	CK_RV rv = f->C_GenerateKeyPair(s, &kg, pt_, 5, vt_, 3, &pub, &prv);
	RV("RSA keygen", rv, CKR_OK);
	if (rv != CKR_OK) return;

	CK_BYTE msg[32], ct[512], out[512];
	CK_ULONG cl, ol;
	for (int i = 0; i < 32; i++) msg[i] = (CK_BYTE)(i + 1);

	/* OAEP: its parameter contains pSourceData */
	CK_RSA_PKCS_OAEP_PARAMS op = { CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL, 0 };
	CK_MECHANISM om = { CKM_RSA_PKCS_OAEP, &op, sizeof op };
	RV("OAEP EncryptInit", f->C_EncryptInit(s, &om, pub), CKR_OK);
	cl = sizeof ct;
	RV("OAEP Encrypt", f->C_Encrypt(s, msg, 32, ct, &cl), CKR_OK);
	RV("OAEP DecryptInit", f->C_DecryptInit(s, &om, prv), CKR_OK);
	ol = sizeof out;
	RV("OAEP Decrypt", f->C_Decrypt(s, ct, cl, out, &ol), CKR_OK);
	CHECK(ol == 32 && memcmp(out, msg, 32) == 0, "OAEP round trip");

	/* a label: the pointer must be serialized, never forwarded. SoftHSM may
	 * refuse labels; either way the daemon must stay up and answer sanely. */
	CK_RSA_PKCS_OAEP_PARAMS lp = { CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, (void *)"a label", 7 };
	CK_MECHANISM lm = { CKM_RSA_PKCS_OAEP, &lp, sizeof lp };
	rv = f->C_EncryptInit(s, &lm, pub);
	CHECK(rv == CKR_OK || rv == CKR_MECHANISM_PARAM_INVALID || rv == CKR_ARGUMENTS_BAD || rv == CKR_DATA_INVALID,
	      "OAEP with a label: 0x%lx", (unsigned long)rv);
	if (rv == CKR_OK) {
		cl = sizeof ct;
		rv = f->C_Encrypt(s, msg, 32, ct, &cl);
		CHECK(rv == CKR_OK, "OAEP label Encrypt (0x%lx)", (unsigned long)rv);
		RV("OAEP label DecryptInit", f->C_DecryptInit(s, &lm, prv), CKR_OK);
		ol = sizeof out;
		RV("OAEP label Decrypt", f->C_Decrypt(s, ct, cl, out, &ol), CKR_OK);
		CHECK(ol == 32 && memcmp(out, msg, 32) == 0, "OAEP label round trip");
		/* the label was really used: without it decryption fails */
		RV("OAEP DecryptInit (no label)", f->C_DecryptInit(s, &om, prv), CKR_OK);
		ol = sizeof out;
		rv = f->C_Decrypt(s, ct, cl, out, &ol);
		CHECK(rv != CKR_OK, "wrong label rejected (0x%lx)", (unsigned long)rv);
	}

	/* PSS: flat parameter */
	CK_RSA_PKCS_PSS_PARAMS pp = { CKM_SHA256, CKG_MGF1_SHA256, 32 };
	CK_MECHANISM pm = { CKM_SHA256_RSA_PKCS_PSS, &pp, sizeof pp };
	CK_BYTE sig[512]; CK_ULONG sl = sizeof sig;
	RV("PSS SignInit", f->C_SignInit(s, &pm, prv), CKR_OK);
	RV("PSS Sign", f->C_Sign(s, msg, 32, sig, &sl), CKR_OK);
	RV("PSS VerifyInit", f->C_VerifyInit(s, &pm, pub), CKR_OK);
	RV("PSS Verify", f->C_Verify(s, msg, 32, sig, sl), CKR_OK);
	CK_MECHANISM bad = { CKM_SHA256_RSA_PKCS_PSS, &pp, 7 };
	RV("PSS with a short parameter", f->C_SignInit(s, &bad, prv), CKR_MECHANISM_PARAM_INVALID);
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	void *h = dlopen(argv[1], RTLD_NOW);
	if (!h) { printf("dlopen: %s\n", dlerror()); return 2; }
	CK_C_GetInterface gi = dlsym(h, "C_GetInterface");
	CK_INTERFACE_PTR iface = NULL; CK_VERSION ver = {3, 2};
	if (gi((CK_UTF8CHAR_PTR)"PKCS 11", &ver, &iface, 0) != CKR_OK) return 2;
	f = iface->pFunctionList;
	RV("C_Initialize", f->C_Initialize(NULL), CKR_OK);
	CK_SLOT_ID slots[4]; CK_ULONG ns = 4;
	RV("C_GetSlotList", f->C_GetSlotList(CK_TRUE, slots, &ns), CKR_OK);
	RV("C_OpenSession", f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &s), CKR_OK);
	RV("C_Login", f->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4), CKR_OK);

	test_templates();
	test_aes();
	test_rsa();

	f->C_Finalize(NULL);
	printf("\n%d failure(s)\n", fails);
	return fails != 0;
}
