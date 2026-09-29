/*
 * Fuzz gck_rpc_param_decode(), the daemon-side parser of attacker-controlled
 * AEAD parameter blobs: random blobs, mutations of blobs from the real
 * encoder, and a round trip. Every pointer handed out must lie inside the
 * private work buffer. Build with -fsanitize=address,undefined for full value.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "gck-rpc-layer.h"
#include "gck-rpc-private.h"

void gck_rpc_log(const char *m, ...) { (void)m; }

static unsigned char *last_work; static size_t last_len;
static void *al(void *ctx, size_t n) { last_work = malloc(n); last_len = n; return last_work; }

static void *tptrs[512]; static long ntpl;
static void *tal(void *ctx, size_t n) { (void)ctx; if (ntpl >= 512) return NULL; return tptrs[ntpl++] = malloc(n ? n : 1); }

static uint64_t rng = 88172645463325252ULL;
static uint64_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

int main(int argc, char **argv)
{
	/* usage: param-fuzz [iterations] */
	long n_it = argc > 1 ? atol(argv[1]) : 300000;
	long ok = 0, rej = 0;
	unsigned char blob[512];
	for (long it = 0; it < n_it; it++) {
		size_t n = rnd() % sizeof blob;
		for (size_t i = 0; i < n; i++) blob[i] = (unsigned char)rnd();
		if (n && (rnd() & 3)) blob[0] = (unsigned char)(1 + rnd() % 7);      /* plausible kind */
		/* bias the length fields so many blobs parse */
		for (size_t i = 1; i + 8 <= n; i += 8)
			if (rnd() & 1) { memset(blob + i, 0, 7); blob[i + 7] = (unsigned char)(rnd() % 40); }
		int phase = 1 << (rnd() % 3);
		GckRpcParamState st;
		last_work = NULL;
		CK_RV rv = gck_rpc_param_decode(blob, n, phase, &st, al, NULL);
		if (rv == CKR_OK) {
			ok++;
			/* every pointer must lie inside the private work buffer */
			const GckRpcParamDesc *d = st.desc;
			for (int i = 0; i < d->nfields; i++) {
				if (!d->fields[i].is_buf) continue;
				unsigned char *p; memcpy(&p, (char *)&st.s + d->fields[i].off, sizeof p);
				if (st.lens[i] == 0) { if (p) { printf("non-NULL empty ptr\n"); return 1; } continue; }
				if (p < last_work || p + st.lens[i] > last_work + last_len) { printf("pointer escapes work buffer!\n"); return 1; }
				volatile unsigned char x = p[0]; x = p[st.lens[i] - 1]; (void)x;   /* touch under ASAN */
			}
			unsigned char rb[GCK_RPC_MSGPARAM_BLOB]; size_t rn;
			gck_rpc_param_resp_encode(&st, rb, sizeof rb, &rn);
		} else rej++;
		free(last_work);
	}

	/* mutate blobs produced by the real encoder */
	long mok = 0, mrej = 0;
	for (long it = 0; it < n_it; it++) {
		CK_BYTE a[40], b[40];
		int k = rnd() % 6;
		unsigned char enc[600]; size_t en = 0;
		memset(a, 1, sizeof a); memset(b, 2, sizeof b);
		CK_GCM_MESSAGE_PARAMS g = { a, 12, 32, 3, b, 128 };
		CK_CCM_MESSAGE_PARAMS c = { 32, a, 7, 8, 3, b, 8 };
		CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS h = { a, 12, b };
		CK_GCM_PARAMS gp = { a, 12, 96, b, 5, 96 };
		CK_CCM_PARAMS cp = { 16, a, 7, b, 3, 8 };
		CK_SALSA20_CHACHA20_POLY1305_PARAMS hp = { a, 12, b, 4 };
		int phase = 2;
		CK_RV rv;
		switch (k) {
		case 0: rv = gck_rpc_param_encode(gck_rpc_param_desc_for_message(sizeof g), &g, phase, enc, sizeof enc, &en); break;
		case 1: rv = gck_rpc_param_encode(gck_rpc_param_desc_for_message(sizeof c), &c, phase, enc, sizeof enc, &en); break;
		case 2: rv = gck_rpc_param_encode(gck_rpc_param_desc_for_message(sizeof h), &h, phase, enc, sizeof enc, &en); break;
		case 3: phase = 1; rv = gck_rpc_param_encode(gck_rpc_param_desc_for_mechanism(CKM_AES_GCM), &gp, phase, enc, sizeof enc, &en); break;
		case 4: phase = 1; rv = gck_rpc_param_encode(gck_rpc_param_desc_for_mechanism(CKM_AES_CCM), &cp, phase, enc, sizeof enc, &en); break;
		default: phase = 1; rv = gck_rpc_param_encode(gck_rpc_param_desc_for_mechanism(CKM_CHACHA20_POLY1305), &hp, phase, enc, sizeof enc, &en); break;
		}
		if (rv != CKR_OK) { printf("encode failed %d 0x%lx\n", k, (unsigned long)rv); return 1; }
		int nmut = rnd() % 4;
		for (int m = 0; m < nmut; m++) enc[rnd() % en] = (unsigned char)rnd();
		size_t n = en; if (rnd() % 4 == 0) n = rnd() % (en + 1);
		GckRpcParamState st; last_work = NULL;
		rv = gck_rpc_param_decode(enc, n, phase, &st, al, NULL);
		if (rv == CKR_OK) {
			mok++;
			const GckRpcParamDesc *dd = st.desc;
			for (int i = 0; i < dd->nfields; i++) {
				if (!dd->fields[i].is_buf) continue;
				unsigned char *p; memcpy(&p, (char *)&st.s + dd->fields[i].off, sizeof p);
				if (st.lens[i] == 0) continue;
				if (p < last_work || p + st.lens[i] > last_work + last_len) { printf("pointer escapes work buffer!\n"); return 1; }
				volatile unsigned char x = p[0]; x = p[st.lens[i] - 1]; (void)x;
			}
		} else mrej++;
		free(last_work);
	}
	/* round trip: what the client encodes, the daemon decodes to the same fields */
	{
		CK_BYTE a[12], b[16];
		memcpy(a, "0123456789ab", 12); memset(b, 9, 16);
		CK_GCM_MESSAGE_PARAMS g = { a, 12, 32, 3, b, 128 };
		unsigned char enc[600]; size_t en; GckRpcParamState st;
		gck_rpc_param_encode(gck_rpc_param_desc_for_message(sizeof g), &g, GCK_RPC_PHASE_DEC, enc, sizeof enc, &en);
		CK_RV rv = gck_rpc_param_decode(enc, en, GCK_RPC_PHASE_DEC, &st, al, NULL);
		int good = rv == CKR_OK && st.s.gcm_msg.ulIvLen == 12 && st.s.gcm_msg.ulIvFixedBits == 32 &&
			   st.s.gcm_msg.ivGenerator == 3 && st.s.gcm_msg.ulTagBits == 128 &&
			   memcmp(st.s.gcm_msg.pIv, a, 12) == 0 && memcmp(st.s.gcm_msg.pTag, b, 16) == 0 &&
			   st.s.gcm_msg.pIv != a && st.s.gcm_msg.pTag != b;
		printf("round trip %s\n", good ? "ok" : "FAILED");
		if (!good) return 1;
		rv = gck_rpc_param_decode(enc, en, GCK_RPC_PHASE_MECH, &st, al, NULL);
		printf("message blob as mechanism param: 0x%lx (want 0x%lx)\n", (unsigned long)rv,
		       (unsigned long)CKR_MECHANISM_PARAM_INVALID);
		if (rv != CKR_MECHANISM_PARAM_INVALID)
			return 1;
	}

	/* ---- nested attribute templates ---- */
	{
		long tok = 0, trej = 0, tapply = 0;

		for (long it = 0; it < n_it; it++) {
			CK_ATTRIBUTE in[4];
			CK_ULONG cnt = rnd() % 5, i;
			unsigned char vals[4][40];
			GckRpcTplBuf b;
			int bufmode = rnd() & 1;

			for (i = 0; i < cnt; i++) {
				memset(vals[i], (int)i + 1, sizeof vals[i]);
				in[i].type = CKA_LABEL + (rnd() % 8);
				in[i].pValue = (rnd() % 5) ? vals[i] : NULL;
				in[i].ulValueLen = (rnd() % 7 || bufmode) ? rnd() % 40 : (CK_ULONG)-1;
			}
			if (!gck_rpc_template_encode(&b, in, cnt, bufmode)) { printf("template encode failed\n"); return 1; }
			int nmut = rnd() % 4;
			for (int m = 0; m < nmut && b.len; m++) b.p[rnd() % b.len] = (unsigned char)rnd();
			size_t n = b.len; if (rnd() % 4 == 0) n = rnd() % (b.len + 1);

			CK_ATTRIBUTE_PTR out; CK_ULONG oc;
			ntpl = 0;
			CK_RV rv = gck_rpc_template_decode(b.p, n, bufmode, tal, NULL, &out, &oc);
			if (rv == CKR_OK) {
				tok++;
				for (i = 0; i < oc; i++)   /* touch every value under ASan */
					if (out[i].pValue && (CK_LONG)out[i].ulValueLen != -1) {
						volatile unsigned char x = ((unsigned char *)out[i].pValue)[0];
						if (out[i].ulValueLen) x = ((unsigned char *)out[i].pValue)[out[i].ulValueLen - 1];
						(void)x;
					}
			} else trej++;
			for (long k = 0; k < ntpl; k++) free(tptrs[k]);

			/* the client applying a (possibly corrupt) reply to its own buffers */
			if (!bufmode) {
				CK_ATTRIBUTE mine[4]; unsigned char store[4][40];
				for (i = 0; i < cnt; i++) { mine[i].type = in[i].type; mine[i].pValue = store[i]; mine[i].ulValueLen = sizeof store[i]; }
				if (gck_rpc_template_apply(b.p, n, mine, cnt) == CKR_OK) tapply++;
			}
			free(b.p);
		}
		printf("templates: decoded %ld rejected %ld, replies applied %ld; no faults\n", tok, trej, tapply);
	}
	printf("random: decoded %ld rejected %ld; mutated: decoded %ld rejected %ld; no faults\n", ok, rej, mok, mrej);

	return 0;
}
