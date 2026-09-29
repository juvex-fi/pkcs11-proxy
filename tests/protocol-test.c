/*
 * Protocol-specific and legacy mechanisms through the proxy, against
 * tests/mock-module.c, which checks every field it is handed and writes its
 * outputs: SSL/TLS/WTLS key derivation (values returned through the
 * parameter), PRFs, PBE and PBKDF2, SP 800-108 KDFs (arrays of structures,
 * extra keys coming back), IKE, X9.42/KEA/GOST key agreement, OTP, and
 * parameters that hold another mechanism (KIP, CMS).
 * Usage: protocol-test <libpkcs11-proxy>
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

static CK_RV derive(CK_MECHANISM_TYPE type, void *param, CK_ULONG len, CK_OBJECT_HANDLE *key)
{
	CK_MECHANISM m = { type, param, len };
	CK_OBJECT_HANDLE k = 0;
	CK_RV rv = f->C_DeriveKey(s, &m, 1, NULL, 0, &k);
	if (key) *key = k;
	return rv;
}
static CK_RV gen(CK_MECHANISM_TYPE type, void *param, CK_ULONG len)
{
	CK_MECHANISM m = { type, param, len };
	CK_OBJECT_HANDLE k = 0;
	return f->C_GenerateKey(s, &m, NULL, 0, &k);
}
static CK_RV sign_init(CK_MECHANISM_TYPE type, void *param, CK_ULONG len)
{
	CK_MECHANISM m = { type, param, len };
	return f->C_SignInit(s, &m, 1);
}
static int all(const CK_BYTE *p, size_t n, CK_BYTE v) { for (size_t i = 0; i < n; i++) if (p[i] != v) return 0; return 1; }

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	void *h = dlopen(argv[1], RTLD_NOW);
	if (!h) { printf("dlopen: %s\n", dlerror()); return 2; }
	CK_C_GetFunctionList gfl = dlsym(h, "C_GetFunctionList");
	gfl(&f);
	RV("C_Initialize", f->C_Initialize(NULL), CKR_OK);
	CK_SLOT_ID slots[4]; CK_ULONG ns = 4;
	f->C_GetSlotList(CK_TRUE, slots, &ns);
	RV("C_OpenSession", f->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &s), CKR_OK);

	CK_OBJECT_HANDLE k;
	CK_SSL3_RANDOM_DATA rnd = { (CK_BYTE_PTR)"clientRn", 8, (CK_BYTE_PTR)"serverRn", 8 };

	/* ================= SSL / TLS master secrets ================= */
	{
		CK_VERSION ver = { 3, 1 };
		CK_SSL3_MASTER_KEY_DERIVE_PARAMS p = { rnd, &ver };
		RV("TLS_MASTER_KEY_DERIVE", derive(CKM_TLS_MASTER_KEY_DERIVE, &p, sizeof p, &k), CKR_OK);
		CHECK(k == 0x100, "master secret handle 0x%lx", (unsigned long)k);
		CHECK(ver.major == 3 && ver.minor == 3, "the version the module wrote came back (%d.%d)", ver.major, ver.minor);
	}
	{
		CK_TLS12_MASTER_KEY_DERIVE_PARAMS p = { rnd, NULL, CKM_SHA256 };
		RV("TLS12_MASTER_KEY_DERIVE (no version pointer)", derive(CKM_TLS12_MASTER_KEY_DERIVE, &p, sizeof p, &k), CKR_OK);
		CHECK(k == 0x101 && p.pVersion == NULL, "handle 0x%lx, pointer still NULL", (unsigned long)k);
	}
	{
		CK_BYTE hash[32]; CK_VERSION ver = { 0, 0 };
		for (int i = 0; i < 32; i++) hash[i] = (CK_BYTE)(i ^ 0x5a);
		CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS p = { CKM_SHA384, hash, 32, &ver };
		RV("TLS12_EXTENDED_MASTER_KEY_DERIVE", derive(CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE, &p, sizeof p, &k), CKR_OK);
		CHECK(ver.major == 3 && ver.minor == 4, "version returned (%d.%d)", ver.major, ver.minor);
	}

	/* ================= key material: handles and IVs come back ================= */
	{
		CK_BYTE ivc[16], ivs[16];
		memset(ivc, 0xEE, 16); memset(ivs, 0xEE, 16);
		CK_SSL3_KEY_MAT_OUT out; memset(&out, 0, sizeof out);
		out.pIVClient = ivc; out.pIVServer = ivs;
		CK_TLS12_KEY_MAT_PARAMS p = { 256, 128, 128, CK_FALSE, rnd, &out, CKM_SHA384 };
		RV("TLS12_KEY_AND_MAC_DERIVE", derive(CKM_TLS12_KEY_AND_MAC_DERIVE, &p, sizeof p, &k), CKR_OK);
		CHECK(out.hClientMacSecret == 11 && out.hServerMacSecret == 12 && out.hClientKey == 13 && out.hServerKey == 14,
		      "four key handles returned (%lu %lu %lu %lu)", (unsigned long)out.hClientMacSecret, (unsigned long)out.hServerMacSecret,
		      (unsigned long)out.hClientKey, (unsigned long)out.hServerKey);
		int ok = 1;
		for (int i = 0; i < 16; i++) if (ivc[i] != (CK_BYTE)(0xC0 + i) || ivs[i] != (CK_BYTE)(0xD0 + i)) ok = 0;
		CHECK(ok, "client and server IVs returned into the caller's buffers");
		CHECK(out.pIVClient == ivc && out.pIVServer == ivs, "the caller's own pointers are untouched");
	}

	/* ================= PRFs: an output buffer and its length ================= */
	{
		CK_BYTE out[48]; CK_ULONG olen = 48;
		memset(out, 0xEE, sizeof out);
		CK_TLS_PRF_PARAMS p = { (CK_BYTE_PTR)"seed", 4, (CK_BYTE_PTR)"label", 5, out, &olen };
		RV("TLS_PRF", derive(CKM_TLS_PRF, &p, sizeof p, &k), CKR_OK);
		int ok = olen == 40;
		for (int i = 0; i < 40; i++) if (out[i] != (CK_BYTE)(i * 7)) ok = 0;
		CHECK(ok && all(out + 40, 8, 0xEE), "PRF output (40 of 48 bytes) and its length came back; the rest is untouched");
		CK_ULONG huge = (CK_ULONG)1 << 30;
		CK_TLS_PRF_PARAMS hp = { (CK_BYTE_PTR)"seed", 4, (CK_BYTE_PTR)"label", 5, out, &huge };
		RV("TLS_PRF with an absurd output length", derive(CKM_TLS_PRF, &hp, sizeof hp, &k), CKR_MECHANISM_PARAM_INVALID);
	}
	{
		CK_BYTE out[48]; CK_ULONG olen = 48;
		memset(out, 0xEE, sizeof out);
		CK_WTLS_PRF_PARAMS p = { CKM_SHA_1, (CK_BYTE_PTR)"seed", 4, (CK_BYTE_PTR)"label", 5, out, &olen };
		RV("WTLS_PRF", derive(CKM_WTLS_PRF, &p, sizeof p, &k), CKR_OK);
		CHECK(olen == 40 && out[39] == (CK_BYTE)(39 * 7), "WTLS PRF output returned");
	}
	{
		CK_BYTE ver = 1;
		CK_SSL3_RANDOM_DATA r2 = rnd;
		CK_WTLS_MASTER_KEY_DERIVE_PARAMS p; memset(&p, 0, sizeof p);
		p.DigestMechanism = CKM_SHA_1; memcpy(&p.RandomInfo, &r2, sizeof p.RandomInfo); p.pVersion = &ver;
		RV("WTLS_MASTER_KEY_DERIVE", derive(CKM_WTLS_MASTER_KEY_DERIVE, &p, sizeof p, &k), CKR_OK);
		CHECK(ver == 2 && k == 0x103, "one-byte WTLS version returned (%d)", ver);
	}
	{
		CK_BYTE iv[8]; memset(iv, 0xEE, 8);
		CK_WTLS_KEY_MAT_OUT out = { 0, 0, iv };
		CK_WTLS_KEY_MAT_PARAMS p; memset(&p, 0, sizeof p);
		p.DigestMechanism = CKM_SHA_1; p.ulMacSizeInBits = 160; p.ulKeySizeInBits = 128; p.ulIVSizeInBits = 64;
		p.ulSequenceNumber = 9; p.bIsExport = CK_TRUE; memcpy(&p.RandomInfo, &rnd, sizeof p.RandomInfo); p.pReturnedKeyMaterial = &out;
		RV("WTLS_SERVER_KEY_AND_MAC_DERIVE", derive(CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE, &p, sizeof p, &k), CKR_OK);
		CHECK(out.hMacSecret == 21 && out.hKey == 22 && iv[0] == 0xE0 && iv[7] == 0xE7, "WTLS handles and IV returned");
	}
	{
		CK_TLS_KDF_PARAMS p = { CKM_SHA256, (CK_BYTE_PTR)"master secret", 13, rnd, (CK_BYTE_PTR)"ctx", 3 };
		RV("TLS12_KDF", derive(CKM_TLS12_KDF, &p, sizeof p, &k), CKR_OK);
	}

	/* ================= password based ================= */
	{
		CK_BYTE iv[8]; memset(iv, 0xEE, 8);
		CK_PBE_PARAMS p = { iv, (CK_UTF8CHAR_PTR)"secret", 6, (CK_BYTE_PTR)"salt", 4, 2048 };
		RV("PBE_SHA1_DES3_EDE_CBC (C_GenerateKey)", gen(CKM_PBE_SHA1_DES3_EDE_CBC, &p, sizeof p), CKR_OK);
		CHECK(iv[0] == 0x90 && iv[7] == 0x97, "the IV the token derived came back");
		CK_PBE_PARAMS rc4 = { NULL, (CK_UTF8CHAR_PTR)"secret", 6, (CK_BYTE_PTR)"salt", 4, 2048 };
		RV("PBE_SHA1_RC4_128 (no IV)", gen(CKM_PBE_SHA1_RC4_128, &rc4, sizeof rc4), CKR_OK);
	}
	{
		CK_PKCS5_PBKD2_PARAMS2 p; memset(&p, 0, sizeof p);
		p.saltSource = CKZ_SALT_SPECIFIED; p.pSaltSourceData = "saltsalt"; p.ulSaltSourceDataLen = 8;
		p.iterations = 1000; p.prf = CKP_PKCS5_PBKD2_HMAC_SHA256; p.pPassword = (CK_UTF8CHAR_PTR)"hunter2"; p.ulPasswordLen = 7;
		RV("PKCS5_PBKD2 (CK_PKCS5_PBKD2_PARAMS2)", derive(CKM_PKCS5_PBKD2, &p, sizeof p, &k), CKR_OK);
		CHECK(k == 0x202, "the module saw the length as a value (0x%lx)", (unsigned long)k);
		CK_ULONG plen = 7;
		CK_PKCS5_PBKD2_PARAMS old; memset(&old, 0, sizeof old);
		old.saltSource = CKZ_SALT_SPECIFIED; old.pSaltSourceData = "saltsalt"; old.ulSaltSourceDataLen = 8;
		old.iterations = 1000; old.prf = CKP_PKCS5_PBKD2_HMAC_SHA256; old.pPassword = (CK_UTF8CHAR_PTR)"hunter2"; old.ulPasswordLen = &plen;
		RV("PKCS5_PBKD2 (the older CK_PKCS5_PBKD2_PARAMS)", derive(CKM_PKCS5_PBKD2, &old, sizeof old, &k), CKR_OK);
		CHECK(k == 0x201, "the module saw a pointer to the length (0x%lx)", (unsigned long)k);
	}

	/* ================= SP 800-108: arrays of structures ================= */
	{
		CK_SP800_108_COUNTER_FORMAT cf = { CK_FALSE, 16 };
		CK_SP800_108_DKM_LENGTH_FORMAT lf = { CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, CK_FALSE, 32 };
		CK_PRF_DATA_PARAM dp[3] = {
			{ CK_SP800_108_ITERATION_VARIABLE, &cf, sizeof cf },
			{ CK_SP800_108_BYTE_ARRAY, (void *)"label", 5 },
			{ CK_SP800_108_DKM_LENGTH, &lf, sizeof lf },
		};
		CK_ATTRIBUTE t1[1] = { { CKA_LABEL, "k1", 2 } }, t2[1] = { { CKA_LABEL, "k2", 2 } };
		CK_OBJECT_HANDLE h1 = 0, h2 = 0;
		CK_DERIVED_KEY dk[2] = { { t1, 1, &h1 }, { t2, 1, &h2 } };
		CK_SP800_108_KDF_PARAMS p = { CKM_SHA256_HMAC, 3, dp, 2, dk };
		RV("SP800_108_COUNTER_KDF", derive(CKM_SP800_108_COUNTER_KDF, &p, sizeof p, &k), CKR_OK);
		CHECK(k == 0x300 && h1 == 0x301 && h2 == 0x302, "the key and the two additional keys (0x%lx 0x%lx 0x%lx)",
		      (unsigned long)k, (unsigned long)h1, (unsigned long)h2);
		CK_SP800_108_KDF_PARAMS bad = { CKM_SHA256_HMAC, 3, NULL, 0, NULL };
		RV("SP800_108 with an array count but no array", derive(CKM_SP800_108_COUNTER_KDF, &bad, sizeof bad, &k), CKR_MECHANISM_PARAM_INVALID);
		CK_SP800_108_KDF_PARAMS many = { CKM_SHA256_HMAC, 3, dp, 100000, dk };
		RV("SP800_108 with an absurd key count", derive(CKM_SP800_108_COUNTER_KDF, &many, sizeof many, &k), CKR_MECHANISM_PARAM_INVALID);
	}
	{
		CK_PRF_DATA_PARAM dp[1] = { { CK_SP800_108_BYTE_ARRAY, (void *)"data", 4 } };
		CK_OBJECT_HANDLE h1 = 0;
		CK_DERIVED_KEY dk[1] = { { NULL, 0, &h1 } };
		CK_SP800_108_FEEDBACK_KDF_PARAMS p = { CKM_SHA256_HMAC, 1, dp, 8, (CK_BYTE_PTR)"feedback", 1, dk };
		RV("SP800_108_FEEDBACK_KDF", derive(CKM_SP800_108_FEEDBACK_KDF, &p, sizeof p, &k), CKR_OK);
		CHECK(k == 0x310 && h1 == 0x311, "feedback KDF key and additional key");
	}

	/* ================= IKE ================= */
	{
		CK_IKE2_PRF_PLUS_DERIVE_PARAMS a = { CKM_SHA256_HMAC, CK_TRUE, 77, (CK_BYTE_PTR)"seed", 4 };
		RV("IKE2_PRF_PLUS_DERIVE", derive(CKM_IKE2_PRF_PLUS_DERIVE, &a, sizeof a, &k), CKR_OK);
		CK_IKE_PRF_DERIVE_PARAMS b = { CKM_SHA256_HMAC, CK_TRUE, CK_FALSE, (CK_BYTE_PTR)"Ni-nonce", 8, (CK_BYTE_PTR)"Nr-nonce!", 9, 88 };
		RV("IKE_PRF_DERIVE", derive(CKM_IKE_PRF_DERIVE, &b, sizeof b, &k), CKR_OK);
		CK_IKE1_PRF_DERIVE_PARAMS c = { CKM_SHA256_HMAC, CK_TRUE, 5, 6, (CK_BYTE_PTR)"CKYi-cky", 8, (CK_BYTE_PTR)"CKYr-cky", 8, 3 };
		RV("IKE1_PRF_DERIVE (incl. a CK_BYTE member)", derive(CKM_IKE1_PRF_DERIVE, &c, sizeof c, &k), CKR_OK);
		CK_IKE1_EXTENDED_DERIVE_PARAMS d = { CKM_SHA256_HMAC, CK_TRUE, 9, (CK_BYTE_PTR)"extra", 5 };
		RV("IKE1_EXTENDED_DERIVE", derive(CKM_IKE1_EXTENDED_DERIVE, &d, sizeof d, &k), CKR_OK);
	}

	/* ================= other key agreement ================= */
	{
		CK_X9_42_DH1_DERIVE_PARAMS a = { 2, 5, (CK_BYTE_PTR)"other", 8, (CK_BYTE_PTR)"pubvalue" };
		RV("X9_42_DH_DERIVE", derive(CKM_X9_42_DH_DERIVE, &a, sizeof a, &k), CKR_OK);
		CK_X9_42_MQV_DERIVE_PARAMS b = { 2, 5, (CK_BYTE_PTR)"other", 8, (CK_BYTE_PTR)"pubvalue", 3, 55, 6, (CK_BYTE_PTR)"public", 66 };
		RV("X9_42_MQV_DERIVE", derive(CKM_X9_42_MQV_DERIVE, &b, sizeof b, &k), CKR_OK);
		CK_KEA_DERIVE_PARAMS c = { CK_TRUE, 4, (CK_BYTE_PTR)"AAAA", (CK_BYTE_PTR)"BBBB", 6, (CK_BYTE_PTR)"public" };
		RV("KEA_DERIVE", derive(CKM_KEA_DERIVE, &c, sizeof c, &k), CKR_OK);
		CK_GOSTR3410_DERIVE_PARAMS d = { 3, (CK_BYTE_PTR)"public", 6, (CK_BYTE_PTR)"ukm-ukm!", 8 };
		RV("GOSTR3410_DERIVE", derive(CKM_GOSTR3410_DERIVE, &d, sizeof d, &k), CKR_OK);
	}

	/* ================= generation with a parameter that is optional ================= */
	{
		CK_BYTE seed[16]; for (int i = 0; i < 16; i++) seed[i] = (CK_BYTE)(i + 1);
		CK_DSA_PARAMETER_GEN_PARAM p = { CKM_SHA256, seed, 16, 5 };
		RV("DSA_PROBABILISTIC_PARAMETER_GEN with a seed", gen(CKM_DSA_PROBABILISTIC_PARAMETER_GEN, &p, sizeof p), CKR_OK);
		RV("DSA_PROBABILISTIC_PARAMETER_GEN without", gen(CKM_DSA_PROBABILISTIC_PARAMETER_GEN, NULL, 0), CKR_OK);
	}

	/* ================= signing and MAC parameters ================= */
	{
		CK_TLS_MAC_PARAMS a = { CKM_SHA256, 12, 1 };
		RV("TLS12_MAC", sign_init(CKM_TLS12_MAC, &a, sizeof a), CKR_OK);
		CK_ULONG bits = 224;
		RV("TLS10_MAC_SERVER (a CK_ULONG)", sign_init(CKM_TLS10_MAC_SERVER, &bits, sizeof bits), CKR_OK);
		RV("SHA512_T (a CK_ULONG)", sign_init(CKM_SHA512_T, &bits, sizeof bits), CKR_OK);
		CK_XEDDSA_PARAMS x = { 4 };
		RV("XEDDSA", sign_init(CKM_XEDDSA, &x, sizeof x), CKR_OK);
		RV("AES_XTS (16-byte tweak)", sign_init(CKM_AES_XTS, "0123456789abcdef", 16), CKR_OK);
		CK_RC5_MAC_GENERAL_PARAMS r5 = { 32, 12, 8 };
		RV("RC5_MAC_GENERAL", sign_init(CKM_RC5_MAC_GENERAL, &r5, sizeof r5), CKR_OK);
		CK_RC5_CBC_PARAMS rc = { 32, 12, (CK_BYTE_PTR)"rc5-iv!!", 8 };
		RV("RC5_CBC (a pointer to the IV)", sign_init(CKM_RC5_CBC, &rc, sizeof rc), CKR_OK);
		CK_KEY_WRAP_SET_OAEP_PARAMS so = { 1, (CK_BYTE_PTR)"xdata", 5 };
		RV("KEY_WRAP_SET_OAEP (a CK_BYTE and a pointer)", sign_init(CKM_KEY_WRAP_SET_OAEP, &so, sizeof so), CKR_OK);
	}
	{
		CK_OTP_PARAM op[2] = { { CK_OTP_PIN, "1234", 4 }, { CK_OTP_TIME, "123456", 6 } };
		CK_OTP_PARAMS p = { op, 2 };
		RV("SECURID (an array of typed values)", sign_init(CKM_SECURID, &p, sizeof p), CKR_OK);
	}

	/* ================= parameters that contain another mechanism ================= */
	{
		CK_RSA_PKCS_PSS_PARAMS pss = { CKM_SHA256, CKG_MGF1_SHA256, 32 };
		CK_MECHANISM sm = { CKM_SHA256_RSA_PKCS_PSS, &pss, sizeof pss }, dm = { CKM_SHA256, NULL, 0 };
		CK_CMS_SIG_PARAMS p = { 44, &sm, &dm, (CK_UTF8CHAR_PTR)"1.2.840.113549.1.7.1", (CK_BYTE_PTR)"req", 3, (CK_BYTE_PTR)"rq", 2 };
		RV("CMS_SIG (two nested mechanisms and a string)", sign_init(CKM_CMS_SIG, &p, sizeof p), CKR_OK);
		CK_MECHANISM bad = { CKM_X3DH_INITIALIZE, NULL, 0 };
		CK_CMS_SIG_PARAMS q = { 44, &bad, &dm, (CK_UTF8CHAR_PTR)"x", NULL, 0, NULL, 0 };
		RV("CMS_SIG with an unsupported nested mechanism", sign_init(CKM_CMS_SIG, &q, sizeof q), CKR_MECHANISM_INVALID);
	}
	{
		CK_ECDH1_DERIVE_PARAMS e = { CKD_NULL, 0, NULL, 4, (CK_BYTE_PTR)"abcd" };
		CK_MECHANISM inner = { CKM_ECDH1_DERIVE, &e, sizeof e };
		CK_KIP_PARAMS p = { &inner, 33, (CK_BYTE_PTR)"seed", 4 };
		CK_MECHANISM m = { CKM_KIP_WRAP, &p, sizeof p };
		CK_BYTE out[16]; CK_ULONG ol = sizeof out;
		RV("KIP_WRAP (a mechanism whose parameter points at data)", f->C_WrapKey(s, &m, 1, 2, out, &ol), CKR_OK);
		/* nesting without end is cut off */
		CK_KIP_PARAMS l3 = { NULL, 1, NULL, 0 };
		CK_MECHANISM m3 = { CKM_KIP_WRAP, &l3, sizeof l3 };
		CK_KIP_PARAMS l2 = { &m3, 1, NULL, 0 };
		CK_MECHANISM m2 = { CKM_KIP_WRAP, &l2, sizeof l2 };
		CK_KIP_PARAMS l1 = { &m2, 1, NULL, 0 };
		CK_MECHANISM m1 = { CKM_KIP_WRAP, &l1, sizeof l1 };
		ol = sizeof out;
		RV("KIP_WRAP nested too deeply", f->C_WrapKey(s, &m1, 1, 2, out, &ol), CKR_MECHANISM_PARAM_INVALID);
	}

	/* what stays unsupported: structures without lengths for their buffers */
	RV("X3DH_INITIALIZE", sign_init(CKM_X3DH_INITIALIZE, "x", 1), CKR_MECHANISM_INVALID);

	f->C_Finalize(NULL);
	printf("\n%d failure(s)\n", fails);
	return fails != 0;
}
