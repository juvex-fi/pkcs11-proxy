/*
 * ML-KEM / ML-DSA through the proxy against a real module (SoftHSM built with
 * ML-DSA and ML-KEM). Usage: pqc-test <libpkcs11-proxy> ; the token must have
 * user PIN 1234. C_VerifySignatureInit is skipped when the module lacks it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include "pkcs11/v3.2/pkcs11-platform.h"
#include "pkcs11/v3.2/pkcs11.h"

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { printf("FAIL: " __VA_ARGS__); printf("\n"); fails++; } else { printf("ok:   " __VA_ARGS__); printf("\n"); } } while (0)
#define RV(name, rv, want) CHECK((rv) == (want), "%s -> 0x%lx (want 0x%lx)", name, (unsigned long)(rv), (unsigned long)(want))

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	void *h = dlopen(argv[1], RTLD_NOW);
	if (!h) { printf("dlopen: %s\n", dlerror()); return 2; }
	CK_C_GetInterface gi = dlsym(h, "C_GetInterface");
	CK_INTERFACE_PTR iface = NULL;
	CK_VERSION ver = {3, 2};
	CK_RV rv = gi((CK_UTF8CHAR_PTR)"PKCS 11", &ver, &iface, 0);
	RV("C_GetInterface", rv, CKR_OK);
	CK_FUNCTION_LIST_3_2_PTR f = iface->pFunctionList;

	rv = f->C_Initialize(NULL);
	RV("C_Initialize", rv, CKR_OK);

	CK_SLOT_ID slots[16]; CK_ULONG ns = 16;
	rv = f->C_GetSlotList(CK_TRUE, slots, &ns);
	RV("C_GetSlotList", rv, CKR_OK);
	if (rv != CKR_OK || ns == 0) return 2;
	CK_SLOT_ID slot = slots[0];

	CK_MECHANISM_TYPE mechs[512]; CK_ULONG nm = 512;
	rv = f->C_GetMechanismList(slot, mechs, &nm);
	RV("C_GetMechanismList", rv, CKR_OK);
	int has_kem = 0, has_dsa = 0;
	for (CK_ULONG i = 0; i < nm; i++) {
		if (mechs[i] == CKM_ML_KEM) has_kem = 1;
		if (mechs[i] == CKM_ML_DSA) has_dsa = 1;
	}
	CHECK(has_kem, "CKM_ML_KEM listed");
	CHECK(has_dsa, "CKM_ML_DSA listed");
	CK_MECHANISM_INFO mi;
	rv = f->C_GetMechanismInfo(slot, CKM_ML_DSA, &mi);
	RV("C_GetMechanismInfo(ML_DSA)", rv, CKR_OK);

	CK_SESSION_HANDLE s;
	rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &s);
	RV("C_OpenSession", rv, CKR_OK);
	rv = f->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
	RV("C_Login", rv, CKR_OK);

	CK_BBOOL T = CK_TRUE, F = CK_FALSE;
	CK_BYTE msg[] = "hello post-quantum world";

	/* ---- ML-DSA ---- */
	CK_ULONG ps = CKP_ML_DSA_65;
	CK_ATTRIBUTE pub_t[] = {
		{CKA_PARAMETER_SET, &ps, sizeof ps},
		{CKA_VERIFY, &T, 1}, {CKA_TOKEN, &F, 1},
	};
	CK_ATTRIBUTE prv_t[] = {
		{CKA_SIGN, &T, 1}, {CKA_TOKEN, &F, 1}, {CKA_PRIVATE, &T, 1},
	};
	CK_OBJECT_HANDLE dpub, dprv;
	CK_MECHANISM kg = {CKM_ML_DSA_KEY_PAIR_GEN, NULL, 0};
	rv = f->C_GenerateKeyPair(s, &kg, pub_t, 3, prv_t, 3, &dpub, &dprv);
	RV("ML-DSA keygen", rv, CKR_OK);

	CK_BYTE sig[8192]; CK_ULONG sl;
	CK_MECHANISM m0 = {CKM_ML_DSA, NULL, 0};
	rv = f->C_SignInit(s, &m0, dprv); RV("ML-DSA SignInit (no ctx)", rv, CKR_OK);
	sl = sizeof sig;
	rv = f->C_Sign(s, msg, sizeof msg, sig, &sl); RV("ML-DSA Sign (no ctx)", rv, CKR_OK);
	printf("      signature length %lu\n", (unsigned long)sl);
	rv = f->C_VerifyInit(s, &m0, dpub); RV("ML-DSA VerifyInit", rv, CKR_OK);
	rv = f->C_Verify(s, msg, sizeof msg, sig, sl); RV("ML-DSA Verify", rv, CKR_OK);

	/* with context string */
	CK_BYTE ctxs[] = "my-context";
	CK_SIGN_ADDITIONAL_CONTEXT sc = {CKH_DETERMINISTIC_REQUIRED, ctxs, sizeof ctxs - 1};
	CK_MECHANISM m1 = {CKM_ML_DSA, &sc, sizeof sc};
	rv = f->C_SignInit(s, &m1, dprv); RV("ML-DSA SignInit (ctx)", rv, CKR_OK);
	sl = sizeof sig;
	rv = f->C_Sign(s, msg, sizeof msg, sig, &sl); RV("ML-DSA Sign (ctx)", rv, CKR_OK);
	rv = f->C_VerifyInit(s, &m1, dpub); RV("ML-DSA VerifyInit (ctx)", rv, CKR_OK);
	rv = f->C_Verify(s, msg, sizeof msg, sig, sl); RV("ML-DSA Verify (ctx)", rv, CKR_OK);

	/* verifying with no / different context must fail: proves ctx crossed the wire */
	rv = f->C_VerifyInit(s, &m0, dpub); RV("VerifyInit (no ctx)", rv, CKR_OK);
	rv = f->C_Verify(s, msg, sizeof msg, sig, sl);
	CHECK(rv == CKR_SIGNATURE_INVALID, "Verify with wrong context rejected (0x%lx)", (unsigned long)rv);

	/* v3.2 C_VerifySignature* with the signature supplied at init */
	rv = f->C_VerifySignatureInit(s, &m1, dpub, sig, sl);
	CHECK(rv == CKR_OK || rv == CKR_FUNCTION_NOT_SUPPORTED, "C_VerifySignatureInit -> 0x%lx (OK or not supported)", (unsigned long)rv);
	if (rv == CKR_OK) {
		rv = f->C_VerifySignature(s, msg, sizeof msg);
		RV("C_VerifySignature", rv, CKR_OK);
	}

	/* bad parameter sizes are rejected client-side */
	CK_MECHANISM mbad = {CKM_ML_DSA, ctxs, 3};
	rv = f->C_SignInit(s, &mbad, dprv);
	RV("bad param size", rv, CKR_MECHANISM_PARAM_INVALID);

	/* ---- ML-KEM ---- */
	CK_ULONG kps = CKP_ML_KEM_768;
	CK_ATTRIBUTE kpub_t[] = {
		{CKA_PARAMETER_SET, &kps, sizeof kps},
		{CKA_ENCAPSULATE, &T, 1}, {CKA_TOKEN, &F, 1},
	};
	CK_ATTRIBUTE kprv_t[] = {
		{CKA_DECAPSULATE, &T, 1}, {CKA_TOKEN, &F, 1}, {CKA_PRIVATE, &T, 1},
	};
	CK_OBJECT_HANDLE kpub, kprv;
	CK_MECHANISM kkg = {CKM_ML_KEM_KEY_PAIR_GEN, NULL, 0};
	rv = f->C_GenerateKeyPair(s, &kkg, kpub_t, 3, kprv_t, 3, &kpub, &kprv);
	RV("ML-KEM keygen", rv, CKR_OK);

	CK_OBJECT_CLASS sk = CKO_SECRET_KEY; CK_KEY_TYPE gt = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE st[] = {
		{CKA_CLASS, &sk, sizeof sk}, {CKA_KEY_TYPE, &gt, sizeof gt},
		{CKA_TOKEN, &F, 1}, {CKA_SENSITIVE, &F, 1}, {CKA_EXTRACTABLE, &T, 1},
	};
	CK_MECHANISM km = {CKM_ML_KEM, NULL, 0};
	CK_BYTE ct[4096]; CK_ULONG ctl = 0;
	CK_OBJECT_HANDLE k1 = 0, k2 = 0;
	rv = f->C_EncapsulateKey(s, &km, kpub, st, 5, NULL, &ctl, &k1);
	RV("EncapsulateKey (size query)", rv, CKR_OK);
	printf("      ciphertext length %lu\n", (unsigned long)ctl);
	ctl = sizeof ct;
	rv = f->C_EncapsulateKey(s, &km, kpub, st, 5, ct, &ctl, &k1);
	RV("EncapsulateKey", rv, CKR_OK);
	rv = f->C_DecapsulateKey(s, &km, kprv, st, 5, ct, ctl, &k2);
	RV("DecapsulateKey", rv, CKR_OK);

	CK_BYTE v1[64], v2[64];
	CK_ATTRIBUTE g1 = {CKA_VALUE, v1, sizeof v1}, g2 = {CKA_VALUE, v2, sizeof v2};
	CK_RV r1 = f->C_GetAttributeValue(s, k1, &g1, 1); RV("GetAttributeValue k1", r1, CKR_OK);
	CK_RV r2 = f->C_GetAttributeValue(s, k2, &g2, 1); RV("GetAttributeValue k2", r2, CKR_OK);
	CHECK(r1 == CKR_OK && r2 == CKR_OK && g1.ulValueLen == g2.ulValueLen && g1.ulValueLen > 0 &&
	      memcmp(v1, v2, g1.ulValueLen) == 0,
	      "encapsulated and decapsulated shared secrets match (%lu bytes)", (unsigned long)g1.ulValueLen);

	f->C_Finalize(NULL);
	printf("\n%d failure(s)\n", fails);
	return fails != 0;
}
