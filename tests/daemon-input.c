/*
 * The daemon is the trust boundary: it must survive, and never pass on, what a
 * hostile client sends. This test embeds gck-rpc-dispatch.c so it can feed the
 * daemon's own (static) parsers crafted messages and check what the module
 * would be handed. Build with -fsanitize=address,undefined for full value.
 */
#undef SECCOMP
#undef DEBUG_SECCOMP
#include "gck-rpc-dispatch.c"

static int fails, checks;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { printf("FAIL: " __VA_ARGS__); printf("\n"); fails++; } } while (0)

static CallState cs;

static void fresh(void)
{
	call_reset(&cs);
}

static EggBuffer *req(void) { return &cs.req->buffer; }

/* ---- message builders: what a client would put on the wire ---- */
static void add_mechanism(CK_MECHANISM_TYPE m, const void *param, size_t n)
{
	egg_buffer_add_uint32(req(), (uint32_t)m);
	egg_buffer_add_byte_array(req(), param, n);
}

/* a one-attribute array: count, then type, validity, length, value */
static void add_attr(CK_ATTRIBUTE_TYPE type, const void *data, size_t len, size_t claimed_len)
{
	egg_buffer_add_uint32(req(), 1);
	egg_buffer_add_uint32(req(), (uint32_t)type);
	egg_buffer_add_byte(req(), 1);
	egg_buffer_add_uint32(req(), (uint32_t)claimed_len);
	egg_buffer_add_byte_array(req(), data, len);
}

static CK_RV read_mech(CK_MECHANISM *m)
{
	cs.req->parsed = 0;
	memset(m, 0, sizeof(*m));
	return proto_read_mechanism(&cs, m);
}

static CK_RV read_attrs(CK_ATTRIBUTE_PTR *a, CK_ULONG *n)
{
	cs.req->parsed = 0;
	return proto_read_attribute_array(&cs, a, n);
}

static CK_RV read_attr_buffer(CK_ATTRIBUTE_PTR *a, CK_ULONG *n)
{
	cs.req->parsed = 0;
	return proto_read_attribute_buffer(&cs, a, n);
}

static void test_mechanisms(void)
{
	CK_MECHANISM m;
	unsigned char raw[256];
	CK_RV rv;

	memset(raw, 0x41, sizeof raw);

	/* a mechanism the proxy doesn't handle: refused whatever it carries */
	fresh(); add_mechanism(CKM_X3DH_INITIALIZE, raw, 40);
	CHECK(read_mech(&m) == CKR_MECHANISM_INVALID, "unsupported mechanism must be refused");
	fresh(); add_mechanism(0x7fffff01UL, raw, 8);
	CHECK(read_mech(&m) == CKR_MECHANISM_INVALID, "unknown mechanism must be refused");

	/* flat parameters must have exactly the expected size */
	fresh(); add_mechanism(CKM_RSA_PKCS_PSS, raw, 5);
	CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "short PSS parameter");
	fresh(); add_mechanism(CKM_RSA_PKCS_PSS, raw, 200);
	CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "long PSS parameter");
	fresh(); add_mechanism(CKM_RSA_PKCS_PSS, raw, sizeof(CK_RSA_PKCS_PSS_PARAMS));
	rv = read_mech(&m);
	CHECK(rv == CKR_OK && m.ulParameterLen == sizeof(CK_RSA_PKCS_PSS_PARAMS), "exact PSS parameter accepted");
	CHECK(rv == CKR_OK && ((uintptr_t)m.pParameter % sizeof(CK_ULONG)) == 0, "PSS parameter is aligned");
	fresh(); add_mechanism(CKM_AES_CBC, raw, 15);
	CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "15-byte AES-CBC IV");
	fresh(); add_mechanism(CKM_AES_CBC, raw, 16);
	CHECK(read_mech(&m) == CKR_OK, "16-byte AES-CBC IV accepted");
	fresh(); add_mechanism(CKM_AES_CBC, raw, 17);
	CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "17-byte AES-CBC IV");
	fresh(); add_mechanism(CKM_DES3_CBC, raw, 16);
	CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "16-byte 3DES-CBC IV");

	/* a mechanism without parameters never gets the client's bytes */
	fresh(); add_mechanism(CKM_RSA_PKCS, raw, 64);
	rv = read_mech(&m);
	CHECK(rv == CKR_OK && m.pParameter == NULL && m.ulParameterLen == 0, "parameter dropped for RSA-PKCS");

	/* OAEP: the old raw copy carried the client's pSourceData pointer */
	{
		CK_RSA_PKCS_OAEP_PARAMS forged;
		memset(&forged, 0, sizeof forged);
		forged.hashAlg = CKM_SHA_1; forged.mgf = CKG_MGF1_SHA1;
		forged.source = CKZ_DATA_SPECIFIED;
		forged.pSourceData = (void *)0x4141414141414141UL; forged.ulSourceDataLen = 8;
		fresh(); add_mechanism(CKM_RSA_PKCS_OAEP, &forged, sizeof forged);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "raw OAEP parameter (with a pointer) refused");
	}
	{
		unsigned char label[] = "label!", blob[600];
		CK_RSA_PKCS_OAEP_PARAMS p = { CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, label, sizeof label - 1 };
		size_t n;
		CK_RSA_PKCS_OAEP_PARAMS *got;

		CHECK(gck_rpc_param_encode(gck_rpc_param_desc_for_mechanism(CKM_RSA_PKCS_OAEP), &p,
					   GCK_RPC_PHASE_MECH, blob, sizeof blob, &n) == CKR_OK, "encode OAEP");
		fresh(); add_mechanism(CKM_RSA_PKCS_OAEP, blob, n);
		rv = read_mech(&m);
		got = m.pParameter;
		CHECK(rv == CKR_OK && got && m.ulParameterLen == sizeof *got, "serialized OAEP parameter accepted");
		CHECK(rv == CKR_OK && got->ulSourceDataLen == 6 && got->pSourceData != (void *)label &&
		      memcmp(got->pSourceData, "label!", 6) == 0,
		      "OAEP label rebuilt in daemon memory");
		/* truncated / extended blobs */
		fresh(); add_mechanism(CKM_RSA_PKCS_OAEP, blob, n - 1);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "truncated OAEP blob");
		blob[n] = 0;
		fresh(); add_mechanism(CKM_RSA_PKCS_OAEP, blob, n + 1);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "OAEP blob with trailing bytes");
	}

	/* AEAD parameters must be serialized, never raw */
	fresh(); add_mechanism(CKM_AES_GCM, raw, sizeof(CK_GCM_PARAMS));
	CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "raw GCM parameter refused");
	fresh(); add_mechanism(CKM_AES_CCM, raw, sizeof(CK_CCM_PARAMS));
	CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "raw CCM parameter refused");

	/* pointer-carrying derive/sign/wrap parameters: never the client's raw struct */
	{
		CK_ECDH1_DERIVE_PARAMS forged;
		memset(&forged, 0, sizeof forged);
		forged.kdf = CKD_NULL; forged.ulPublicDataLen = 16;
		forged.pPublicData = (void *)0x4141414141414141UL;
		fresh(); add_mechanism(CKM_ECDH1_DERIVE, &forged, sizeof forged);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "raw ECDH1 parameter (forged pointer) refused");
		CK_HKDF_PARAMS hp; memset(&hp, 0, sizeof hp);
		fresh(); add_mechanism(CKM_HKDF_DERIVE, &hp, sizeof hp);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "raw HKDF parameter refused");
		CK_EDDSA_PARAMS ep; memset(&ep, 0, sizeof ep); ep.pContextData = (void *)0x4242424242424242UL; ep.ulContextDataLen = 4;
		fresh(); add_mechanism(CKM_EDDSA, &ep, sizeof ep);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "raw EDDSA parameter refused");
		CK_RSA_AES_KEY_WRAP_PARAMS wp = { 256, (void *)0x4343434343434343UL };
		fresh(); add_mechanism(CKM_RSA_AES_KEY_WRAP, &wp, sizeof wp);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "raw RSA-AES wrap parameter (nested pointer) refused");
		CK_AES_CBC_ENCRYPT_DATA_PARAMS cd; memset(&cd, 0, sizeof cd); cd.pData = (void *)0x4444444444444444UL; cd.length = 16;
		fresh(); add_mechanism(CKM_AES_CBC_ENCRYPT_DATA, &cd, sizeof cd);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "raw AES-CBC-ENCRYPT-DATA parameter refused");
	}
	/* a well-formed blob of the wrong kind for the mechanism */
	{
		unsigned char blob[600]; size_t n;
		static unsigned char salt[] = "salt!";
		CK_HKDF_PARAMS hp = { CK_TRUE, CK_TRUE, CKM_SHA256, CKF_HKDF_SALT_DATA, salt, 5, 0, (CK_BYTE_PTR)"i", 1 };
		CK_HKDF_PARAMS *got;
		CHECK(gck_rpc_param_encode(gck_rpc_param_desc_for_mechanism(CKM_HKDF_DERIVE), &hp,
					   GCK_RPC_PHASE_MECH, blob, sizeof blob, &n) == CKR_OK, "encode HKDF");
		fresh(); add_mechanism(CKM_ECDH1_DERIVE, blob, n);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "HKDF blob for an ECDH mechanism refused");
		fresh(); add_mechanism(CKM_HKDF_DERIVE, blob, n);
		rv = read_mech(&m);
		got = m.pParameter;
		CHECK(rv == CKR_OK && got && got->bExtract == CK_TRUE && got->ulSaltLen == 5 &&
		      got->pSalt != salt && memcmp(got->pSalt, "salt!", 5) == 0 &&
		      got->ulInfoLen == 1 && got->pInfo[0] == 'i', "HKDF blob rebuilt in daemon memory");
		fresh(); add_mechanism(CKM_HKDF_DERIVE, blob, n - 2);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "truncated HKDF blob refused");
	}
	/* nested structure: RSA-AES key wrap points at OAEP parameters */
	{
		unsigned char label[] = "lbl", blob[600]; size_t n;
		CK_RSA_PKCS_OAEP_PARAMS o = { CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, label, 3 };
		CK_RSA_AES_KEY_WRAP_PARAMS w = { 256, &o }, *got;
		CHECK(gck_rpc_param_encode(gck_rpc_param_desc_for_mechanism(CKM_RSA_AES_KEY_WRAP), &w,
					   GCK_RPC_PHASE_MECH, blob, sizeof blob, &n) == CKR_OK, "encode RSA-AES wrap");
		fresh(); add_mechanism(CKM_RSA_AES_KEY_WRAP, blob, n);
		rv = read_mech(&m);
		got = m.pParameter;
		CHECK(rv == CKR_OK && got && got->pOAEPParams && got->pOAEPParams != &o &&
		      got->pOAEPParams->pSourceData != (void *)label && got->pOAEPParams->ulSourceDataLen == 3 &&
		      memcmp(got->pOAEPParams->pSourceData, "lbl", 3) == 0, "nested OAEP structure rebuilt in daemon memory");
		fresh(); add_mechanism(CKM_RSA_AES_KEY_WRAP, blob, n - 1);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "truncated nested structure refused");
		/* the "present" byte says there is a nested structure but there is none */
		fresh(); add_mechanism(CKM_RSA_AES_KEY_WRAP, blob, 1 + 8 + 1);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "nested structure announced but missing");
	}
	/* structures that return values or hold pointers to lengths and arrays:
	 * the client's raw bytes are never accepted, whatever they contain */
	{
		static const CK_MECHANISM_TYPE mechs[] = {
			CKM_TLS_PRF, CKM_WTLS_PRF, CKM_TLS_MASTER_KEY_DERIVE, CKM_TLS12_MASTER_KEY_DERIVE,
			CKM_TLS12_KEY_AND_MAC_DERIVE, CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE, CKM_PKCS5_PBKD2,
			CKM_PBE_SHA1_DES3_EDE_CBC, CKM_SP800_108_COUNTER_KDF, CKM_SP800_108_FEEDBACK_KDF,
			CKM_CMS_SIG, CKM_KIP_WRAP, CKM_SECURID, CKM_IKE_PRF_DERIVE, CKM_X9_42_MQV_DERIVE,
			CKM_TLS12_KDF, CKM_GOSTR3410_DERIVE, CKM_KEA_DERIVE, CKM_RC5_CBC,
		};
		for (size_t i = 0; i < sizeof mechs / sizeof mechs[0]; i++) {
			unsigned char forged[192];
			memset(forged, 0x41, sizeof forged);	/* pointers 0x4141414141414141 */
			fresh(); add_mechanism(mechs[i], forged, 72);
			rv = read_mech(&m);
			CHECK(rv == CKR_MECHANISM_PARAM_INVALID, "raw parameter refused for mechanism 0x%lx (got 0x%lx)",
			      (unsigned long)mechs[i], (unsigned long)rv);
			memset(forged, 0, sizeof forged);
			fresh(); add_mechanism(mechs[i], forged, 72);
			CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "all-zero raw parameter refused for mechanism 0x%lx", (unsigned long)mechs[i]);
		}
	}
	/* output buffers: the capacity the client claims is bounded */
	{
		unsigned char out[64], blob[600]; size_t n;
		CK_BYTE b[8] = { 0 };
		CK_ULONG cap = 100;
		CK_TLS_PRF_PARAMS p = { b, 4, b, 4, out, &cap };
		CK_TLS_PRF_PARAMS *got;

		CHECK(gck_rpc_param_encode(gck_rpc_param_desc_for_mechanism(CKM_TLS_PRF), &p, GCK_RPC_PHASE_MECH, blob, sizeof blob, &n) == CKR_OK,
		      "encode TLS_PRF");
		fresh(); add_mechanism(CKM_TLS_PRF, blob, n);
		rv = read_mech(&m);
		got = m.pParameter;
		CHECK(rv == CKR_OK && got && got->pOutput && got->pulOutputLen && *got->pulOutputLen == 100 &&
		      got->pOutput != out && got->pulOutputLen != &cap, "PRF output buffer and length rebuilt in daemon memory");
		if (rv == CKR_OK && got && got->pOutput) memset(got->pOutput, 0x55, *got->pulOutputLen);	/* writable to its capacity */
		/* a capacity the client can't have room for */
		cap = (CK_ULONG)1 << 30;
		CHECK(gck_rpc_param_encode_alloc(gck_rpc_param_desc_for_mechanism(CKM_TLS_PRF), &p, GCK_RPC_PHASE_MECH, (unsigned char **)&got, &n) != CKR_OK,
		      "the client won't encode a 1 GiB output buffer");
		/* ... and one forged straight into a blob */
		cap = 100;
		gck_rpc_param_encode(gck_rpc_param_desc_for_mechanism(CKM_TLS_PRF), &p, GCK_RPC_PHASE_MECH, blob, sizeof blob, &n);
		{
			/* the CK_ULONGs come first: seed len, label len (2 x 8 bytes); the length pointer's value follows */
			size_t off = 1 + 8 + 8 + 1;	/* kind, ulSeedLen, ulLabelLen, presence of pulOutputLen */
			for (int i = 0; i < 8; i++) blob[off + i] = (i == 4) ? 0x40 : 0;	/* 0x40 << 24 = 1 GiB */
			fresh(); add_mechanism(CKM_TLS_PRF, blob, n);
			CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "a forged 1 GiB output capacity is refused");
		}
	}
	/* presence bytes, array counts and nesting depth */
	{
		unsigned char blob[64];
		size_t n = 0;
		const GckRpcParamDesc *kip = gck_rpc_param_desc_for_mechanism(CKM_KIP_WRAP);
		unsigned char lvl[4][200]; size_t ln[4];

		/* a KIP structure whose pMechanism is absent; wrap it in itself */
		memset(lvl, 0, sizeof lvl);
		lvl[0][0] = (unsigned char)kip->kind;	/* hKey, ulSeedLen: 16 zero bytes; presence 0 */
		ln[0] = 1 + 16 + 1;
		for (int i = 1; i < 4; i++) {
			size_t o = 0;
			lvl[i][o++] = (unsigned char)kip->kind;
			o += 16;
			lvl[i][o++] = 1;				/* a mechanism follows */
			for (int k = 0; k < 8; k++) lvl[i][o++] = (k == 7) ? (CKM_KIP_WRAP & 0xff) : (unsigned char)((CKM_KIP_WRAP >> (8 * (7 - k))) & 0xff);
			lvl[i][o++] = 0; lvl[i][o++] = 0; lvl[i][o++] = (unsigned char)(ln[i - 1] >> 8); lvl[i][o++] = (unsigned char)ln[i - 1];
			memcpy(lvl[i] + o, lvl[i - 1], ln[i - 1]);
			ln[i] = o + ln[i - 1];
		}
		fresh(); add_mechanism(CKM_KIP_WRAP, lvl[0], ln[0]);
		CHECK(read_mech(&m) == CKR_OK, "a KIP parameter without a nested mechanism");
		fresh(); add_mechanism(CKM_KIP_WRAP, lvl[2], ln[2]);
		CHECK(read_mech(&m) == CKR_OK, "two levels of nested mechanisms");
		fresh(); add_mechanism(CKM_KIP_WRAP, lvl[3], ln[3]);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "mechanisms nested too deeply are refused");

		/* a presence byte that is neither 0 nor 1 */
		memcpy(blob, lvl[0], ln[0]);
		blob[ln[0] - 1] = 2;
		n = ln[0];
		fresh(); add_mechanism(CKM_KIP_WRAP, blob, n);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "presence byte 2 refused");
	}
	{
		/* SP 800-108: an array count no client has a reason to send */
		unsigned char blob[64];
		const GckRpcParamDesc *sp = gck_rpc_param_desc_for_mechanism(CKM_SP800_108_COUNTER_KDF);
		memset(blob, 0, sizeof blob);
		blob[0] = (unsigned char)sp->kind;
		blob[1 + 8 + 7] = 0xff; blob[1 + 8 + 6] = 0xff;	/* ulNumberOfDataParams = 65535 */
		fresh(); add_mechanism(CKM_SP800_108_COUNTER_KDF, blob, 1 + 8 * 4);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "65535 data parameters refused");
	}
	fresh(); add_mechanism(CKM_TLS12_MAC, raw, sizeof(CK_TLS_MAC_PARAMS));
	CHECK(read_mech(&m) == CKR_OK, "TLS MAC parameter accepted");
	fresh(); add_mechanism(CKM_TLS12_MAC, raw, 5);
	CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "short TLS MAC parameter");

	/* the extended flat families */
	fresh(); add_mechanism(CKM_SHA256_HMAC_GENERAL, raw, 4);
	CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "short general-MAC length");
	fresh(); add_mechanism(CKM_SHA256_HMAC_GENERAL, raw, sizeof(CK_ULONG));
	CHECK(read_mech(&m) == CKR_OK, "general-MAC length accepted");
	fresh(); add_mechanism(CKM_AES_CTS, raw, 16);
	CHECK(read_mech(&m) == CKR_OK, "AES-CTS IV accepted");
	fresh(); add_mechanism(CKM_AES_CTS, raw, 8);
	CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "8-byte AES-CTS IV");
	fresh(); add_mechanism(CKM_DH_PKCS_DERIVE, raw, 200);
	rv = read_mech(&m);
	CHECK(rv == CKR_OK && m.ulParameterLen == 200 && memcmp(m.pParameter, raw, 200) == 0, "DH public value copied");
	{
		unsigned char *huge = calloc(1, 5000);
		fresh(); add_mechanism(CKM_DH_PKCS_DERIVE, huge, 5000);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "DH public value over the limit");
		free(huge);
	}
	/* legacy mechanisms that used to lose their parameter */
	fresh(); add_mechanism(CKM_RC2_ECB, raw, sizeof(CK_ULONG));
	rv = read_mech(&m);
	CHECK(rv == CKR_OK && m.ulParameterLen == sizeof(CK_ULONG), "RC2-ECB effective-bits parameter kept");
	fresh(); add_mechanism(CKM_RC2_ECB, raw, 3);
	CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "short RC2-ECB parameter");
	fresh(); add_mechanism(CKM_RC5_MAC, raw, sizeof(CK_RC5_PARAMS));
	CHECK(read_mech(&m) == CKR_OK, "RC5 parameters kept");
	fresh(); add_mechanism(CKM_TLS_PRE_MASTER_KEY_GEN, raw, sizeof(CK_VERSION));
	rv = read_mech(&m);
	CHECK(rv == CKR_OK && m.ulParameterLen == sizeof(CK_VERSION), "pre-master version kept");
	fresh(); add_mechanism(CKM_SHA1_KEY_DERIVATION, raw, 8);
	rv = read_mech(&m);
	CHECK(rv == CKR_OK && m.pParameter == NULL, "SHA-1 key derivation takes no parameter");

	fresh(); add_mechanism(CKM_ECDSA_SHA256, raw, 64);
	rv = read_mech(&m);
	CHECK(rv == CKR_OK && m.pParameter == NULL, "no parameter for ECDSA-SHA256");

	/* signing context: bad sizes */
	{
		unsigned char big[16 + 300];
		memset(big, 0, sizeof big);
		fresh(); add_mechanism(CKM_ML_DSA, big, 8 + 256);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "256-byte signing context");
		fresh(); add_mechanism(CKM_ML_DSA, big, 3);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "truncated signing context");
		fresh(); add_mechanism(CKM_ML_DSA, big, 8 + 255);
		CHECK(read_mech(&m) == CKR_OK, "255-byte signing context accepted");
		fresh(); add_mechanism(CKM_HASH_ML_DSA, big, 8);
		CHECK(read_mech(&m) == CKR_MECHANISM_PARAM_INVALID, "hash signing context without hash field");
	}
}

/* Build a template blob by hand */
static void blob_u32(GckRpcTplBuf *b, uint32_t v) { unsigned char x[4] = { v >> 24, v >> 16, v >> 8, v }; b->p = realloc(b->p, b->len + 4); memcpy(b->p + b->len, x, 4); b->len += 4; }
static void blob_u8(GckRpcTplBuf *b, unsigned char v) { b->p = realloc(b->p, b->len + 1); b->p[b->len++] = v; }
static void blob_raw(GckRpcTplBuf *b, const void *d, size_t n) { b->p = realloc(b->p, b->len + n + 1); memcpy(b->p + b->len, d, n); b->len += n; }

static void test_templates(void)
{
	CK_ATTRIBUTE_PTR a;
	CK_ULONG n;
	CK_RV rv;
	unsigned char raw[24 * 4];
	GckRpcTplBuf b;

	memset(raw, 0x41, sizeof raw);

	/* the raw client array (with its pointers) that used to reach the module */
	fresh(); add_attr(CKA_WRAP_TEMPLATE, raw, 24, 24);
	CHECK(read_attrs(&a, &n) == CKR_ATTRIBUTE_VALUE_INVALID, "raw CK_ATTRIBUTE array refused");

	/* a valid template is rebuilt in daemon memory */
	{
		CK_KEY_TYPE kt = CKK_AES;
		CK_ATTRIBUTE nested[2] = { { CKA_KEY_TYPE, &kt, sizeof kt }, { CKA_LABEL, "abc", 3 } };
		fresh();
		CHECK(gck_rpc_template_encode(&b, nested, 2, 0), "encode template");
		add_attr(CKA_WRAP_TEMPLATE, b.p, b.len, 2 * sizeof(CK_ATTRIBUTE));
		free(b.p);
		rv = read_attrs(&a, &n);
		CHECK(rv == CKR_OK && n == 1, "valid template accepted (0x%lx)", (unsigned long)rv);
		if (rv == CKR_OK) {
			CK_ATTRIBUTE_PTR in = a[0].pValue;
			CHECK(a[0].ulValueLen == 2 * sizeof(CK_ATTRIBUTE) && in && in[0].type == CKA_KEY_TYPE &&
			      in[0].pValue != (void *)&kt && *(CK_KEY_TYPE *)in[0].pValue == CKK_AES &&
			      in[1].ulValueLen == 3 && memcmp(in[1].pValue, "abc", 3) == 0,
			      "nested attributes rebuilt with daemon-owned values");
		}
	}

	/* template inside a template */
	{
		memset(&b, 0, sizeof b);
		blob_u32(&b, 1); blob_u32(&b, CKA_WRAP_TEMPLATE); blob_u8(&b, 1); blob_u32(&b, 0); blob_u8(&b, 0);
		fresh(); add_attr(CKA_DERIVE_TEMPLATE, b.p, b.len, sizeof(CK_ATTRIBUTE));
		CHECK(read_attrs(&a, &n) == CKR_ATTRIBUTE_VALUE_INVALID, "nested template refused");
		free(b.p);
	}
	/* absurd counts */
	memset(&b, 0, sizeof b);
	blob_u32(&b, 0xffffffffu);
	fresh(); add_attr(CKA_WRAP_TEMPLATE, b.p, b.len, 24);
	CHECK(read_attrs(&a, &n) == CKR_ATTRIBUTE_VALUE_INVALID, "4G nested attributes refused");
	free(b.p);
	memset(&b, 0, sizeof b);
	blob_u32(&b, 257);
	fresh(); add_attr(CKA_WRAP_TEMPLATE, b.p, b.len, 257 * 24);
	CHECK(read_attrs(&a, &n) == CKR_ATTRIBUTE_VALUE_INVALID, "257 nested attributes refused");
	free(b.p);
	/* declared length disagrees with the count */
	memset(&b, 0, sizeof b);
	blob_u32(&b, 1); blob_u32(&b, CKA_CLASS); blob_u8(&b, 1); blob_u32(&b, 0); blob_u8(&b, 0);
	fresh(); add_attr(CKA_WRAP_TEMPLATE, b.p, b.len, 5 * 24);
	CHECK(read_attrs(&a, &n) == CKR_ATTRIBUTE_VALUE_INVALID, "length not matching the nested count refused");
	free(b.p);
	/* value claimed but not provided */
	memset(&b, 0, sizeof b);
	blob_u32(&b, 1); blob_u32(&b, CKA_LABEL); blob_u8(&b, 1); blob_u32(&b, 1000); blob_u8(&b, 0);
	fresh(); add_attr(CKA_WRAP_TEMPLATE, b.p, b.len, 24);
	CHECK(read_attrs(&a, &n) == CKR_ATTRIBUTE_VALUE_INVALID, "claimed but missing nested value refused");
	free(b.p);
	/* data longer than the rest of the blob */
	memset(&b, 0, sizeof b);
	blob_u32(&b, 1); blob_u32(&b, CKA_LABEL); blob_u8(&b, 1); blob_u32(&b, 1000); blob_u8(&b, 1); blob_raw(&b, "xx", 2);
	fresh(); add_attr(CKA_WRAP_TEMPLATE, b.p, b.len, 24);
	CHECK(read_attrs(&a, &n) == CKR_ATTRIBUTE_VALUE_INVALID, "nested value longer than the blob refused");
	free(b.p);
	/* template with no attributes given at all */
	fresh(); add_attr(CKA_UNWRAP_TEMPLATE, NULL, 0, 24);
	CHECK(read_attrs(&a, &n) == CKR_ATTRIBUTE_VALUE_INVALID, "template without its attributes refused");
	/* trailing garbage */
	memset(&b, 0, sizeof b);
	blob_u32(&b, 0); blob_raw(&b, "junk", 4);
	fresh(); add_attr(CKA_WRAP_TEMPLATE, b.p, b.len, 0);
	CHECK(read_attrs(&a, &n) == CKR_ATTRIBUTE_VALUE_INVALID, "trailing bytes after the template refused");
	free(b.p);

	/* C_GetAttributeValue request: nested buffers */
	{
		CK_ATTRIBUTE want_kt[2] = { { CKA_KEY_TYPE, raw, 8 }, { CKA_LABEL, raw, 20 } };
		fresh();
		egg_buffer_add_uint32(req(), 1);
		egg_buffer_add_uint32(req(), CKA_WRAP_TEMPLATE);
		egg_buffer_add_uint32(req(), 2 * sizeof(CK_ATTRIBUTE));
		CHECK(gck_rpc_template_encode(&b, want_kt, 2, 1), "encode buffer request");
		egg_buffer_add_byte_array(req(), b.p, b.len);
		free(b.p);
		rv = read_attr_buffer(&a, &n);
		CHECK(rv == CKR_OK && n == 1, "template buffer request accepted (0x%lx)", (unsigned long)rv);
		if (rv == CKR_OK) {
			CK_ATTRIBUTE_PTR in = a[0].pValue;
			/* buffers are daemon-owned and writable up to their capacity */
			memset(in[0].pValue, 0x55, in[0].ulValueLen);
			memset(in[1].pValue, 0x55, in[1].ulValueLen);
			CHECK(in[0].ulValueLen == 8 && in[1].ulValueLen == 20 && in[0].pValue != raw,
			      "nested buffers allocated locally");
		}
		/* a claimed buffer length that disagrees with the nested count */
		fresh();
		egg_buffer_add_uint32(req(), 1);
		egg_buffer_add_uint32(req(), CKA_WRAP_TEMPLATE);
		egg_buffer_add_uint32(req(), 7 * sizeof(CK_ATTRIBUTE));
		gck_rpc_template_encode(&b, want_kt, 2, 1);
		egg_buffer_add_byte_array(req(), b.p, b.len);
		free(b.p);
		CHECK(read_attr_buffer(&a, &n) == CKR_ATTRIBUTE_VALUE_INVALID, "buffer length not matching nested count refused");
		/* huge nested capacity */
		memset(&b, 0, sizeof b);
		blob_u32(&b, 1); blob_u32(&b, CKA_LABEL); blob_u8(&b, 1); blob_u32(&b, 0x7fffffffu);
		fresh();
		egg_buffer_add_uint32(req(), 1);
		egg_buffer_add_uint32(req(), CKA_WRAP_TEMPLATE);
		egg_buffer_add_uint32(req(), sizeof(CK_ATTRIBUTE));
		egg_buffer_add_byte_array(req(), b.p, b.len);
		free(b.p);
		CHECK(read_attr_buffer(&a, &n) == CKR_ATTRIBUTE_VALUE_INVALID, "2GB nested buffer refused");
	}
}

int main(void)
{
	CHECK(call_init(&cs), "call_init");
	test_mechanisms();
	test_templates();
	call_reset(&cs);
	printf("%d checks, %d failure(s)\n", checks, fails);
	return fails != 0;
}
