/*
 * Property tests and fuzzing of the mechanism-parameter codec
 * (gck-rpc-params.c), driven by its own descriptor tables, for every kind:
 *
 *  - build a random valid structure, encode it, decode it in the "daemon" and
 *    check that what was rebuilt equals the original, that every pointer of
 *    it lies inside memory the daemon allocated, and that encoding the result
 *    gives the same blob
 *  - let the "module" write random outputs into the rebuilt structure, return
 *    them, apply them to the original and check they arrived; corrupt replies
 *    must be refused without touching the caller's structure
 *  - mutated, truncated and random blobs must never crash the decoder or make
 *    it hand out a pointer outside its own memory
 *
 * The length rules are re-implemented here rather than shared, so the codec is
 * checked against a second reading of the tables. Build with
 * -fsanitize=address,undefined for full value.
 * Usage: param-fuzz [iterations per kind]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "gck-rpc-layer.h"
#include "gck-rpc-private.h"

void gck_rpc_log(const char *m, ...) { (void)m; }

static int fails;
#define FAIL(...) do { printf("FAIL: " __VA_ARGS__); printf("\n"); fails++; } while (0)

static uint64_t rng = 88172645463325252ULL;
static uint64_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

/* ---- blocks the decoder allocates (the daemon's memory) ---- */
static struct { unsigned char *p; size_t n; } blocks[4096]; static int nblocks;
static void *dal(void *ctx, size_t n)
{
	(void)ctx;
	if (nblocks >= 4096) return NULL;
	blocks[nblocks].n = n ? n : 1;
	return blocks[nblocks++].p = malloc(n ? n : 1);
}
static void free_blocks(void) { while (nblocks) free(blocks[--nblocks].p); }
static int inside(const void *p, size_t n)
{
	for (int i = 0; i < nblocks; i++)
		if ((const unsigned char *)p >= blocks[i].p &&
		    (const unsigned char *)p + n <= blocks[i].p + blocks[i].n) return 1;
	return 0;
}

/* ---- memory for the "client's" structures ---- */
static void *arena[16384]; static int narena;
static void *aalloc(size_t n)
{
	void *m = calloc(1, n ? n : 1);
	if (narena < 16384) arena[narena++] = m;
	return m;
}
static void arena_free(void) { while (narena) free(arena[--narena]); }

static void *ptr_at(const void *base, const GckRpcParamField *f)
{
	void *p; memcpy(&p, (const char *)base + f->off, sizeof p); return p;
}
static void put_ptr(void *base, const GckRpcParamField *f, void *p)
{
	memcpy((char *)base + f->off, &p, sizeof p);
}
static int scalar_type(int t) { return t == GCK_RPC_F_ULONG || t == GCK_RPC_F_BBOOL || t == GCK_RPC_F_BYTE; }
static uint64_t get_sc(const void *base, const GckRpcParamField *f)
{
	if (f->type == GCK_RPC_F_ULONG) { CK_ULONG v; memcpy(&v, (const char *)base + f->off, sizeof v); return v; }
	return *((const unsigned char *)base + f->off);
}
static void put_sc(void *base, const GckRpcParamField *f, uint64_t v)
{
	if (f->type == GCK_RPC_F_ULONG) { CK_ULONG u = (CK_ULONG)v; memcpy((char *)base + f->off, &u, sizeof u); }
	else *((unsigned char *)base + f->off) = f->type == GCK_RPC_F_BBOOL ? (v != 0) : (unsigned char)v;
}

/* ---- a second implementation of the length rules ---- */
static uint64_t src_value(const GckRpcParamDesc *d, const void *base, const GckRpcParamDesc *pd,
			  const void *pbase, const GckRpcParamField *f)
{
	const GckRpcParamDesc *sd = (f->flags & GCK_RPC_LEN_PARENT) ? pd : d;
	const void *sb = (f->flags & GCK_RPC_LEN_PARENT) ? pbase : base;
	const GckRpcParamField *sf = &sd->fields[f->len_idx];
	if (scalar_type(sf->type)) return get_sc(sb, sf);
	CK_ULONG *p = ptr_at(sb, sf);
	return p ? *p : 0;
}
static size_t tlen(const GckRpcParamDesc *d, const void *base, const GckRpcParamDesc *pd,
		   const void *pbase, int i)
{
	const GckRpcParamField *f = &d->fields[i];
	if (f->len_idx < 0) return f->len_fixed;
	uint64_t v = src_value(d, base, pd, pbase, f);
	return (f->flags & GCK_RPC_LEN_BITS) ? (size_t)((v + 7) / 8) : (size_t)v;
}
static size_t tcount(const GckRpcParamDesc *d, const void *base, const GckRpcParamDesc *pd,
		     const void *pbase, int i)
{
	return (size_t)src_value(d, base, pd, pbase, &d->fields[i]);
}

/* ---- random valid structures ---- */
static void rbytes(void *p, size_t n) { for (size_t i = 0; i < n; i++) ((unsigned char *)p)[i] = (unsigned char)rnd(); }

static void fill(const GckRpcParamDesc *d, unsigned char *base, const GckRpcParamDesc *pd,
		 const unsigned char *pbase)
{
	int i;
	for (i = 0; i < d->nfields; i++) {
		const GckRpcParamField *f = &d->fields[i];
		if (scalar_type(f->type)) put_sc(base, f, f->type == GCK_RPC_F_BYTE ? rnd() % 256 : rnd() % 4);
		else if (f->type == GCK_RPC_F_ULONGPTR) {
			if (rnd() % 5) { CK_ULONG *p = aalloc(sizeof *p); *p = rnd() % 40; put_ptr(base, f, p); }
		}
	}
	for (i = 0; i < d->nfields; i++) {
		const GckRpcParamField *f = &d->fields[i];
		switch (f->type) {
		case GCK_RPC_F_BUF: case GCK_RPC_F_OBUF: {
			size_t len = tlen(d, base, pd, pbase, i);
			if ((f->type == GCK_RPC_F_OBUF && rnd() % 4 == 0) || (f->type == GCK_RPC_F_BUF && len == 0)) break;
			unsigned char *p = aalloc(len); rbytes(p, len); put_ptr(base, f, p);
			break;
		}
		case GCK_RPC_F_INLINE: rbytes(base + f->off, f->len_fixed); break;
		case GCK_RPC_F_STRUCT:
			if (rnd() % 4) { unsigned char *sub = aalloc(f->sub->size); fill(f->sub, sub, d, base); put_ptr(base, f, sub); }
			break;
		case GCK_RPC_F_ISTRUCT: fill(f->sub, base + f->off, d, base); break;
		case GCK_RPC_F_ARRAY: {
			size_t n = tcount(d, base, pd, pbase, i);
			if (!n) break;
			unsigned char *a = aalloc(n * f->sub->size);
			for (size_t k = 0; k < n; k++) fill(f->sub, a + k * f->sub->size, d, base);
			put_ptr(base, f, a);
			break;
		}
		case GCK_RPC_F_ATTRS: {
			size_t n = tcount(d, base, pd, pbase, i);
			if (!n) break;
			CK_ATTRIBUTE *a = aalloc(n * sizeof *a);
			for (size_t k = 0; k < n; k++) {
				a[k].type = 3 + rnd() % 8; a[k].ulValueLen = rnd() % 6;
				a[k].pValue = aalloc(a[k].ulValueLen); rbytes(a[k].pValue, a[k].ulValueLen);
			}
			put_ptr(base, f, a);
			break;
		}
		case GCK_RPC_F_CSTR:
			if (rnd() % 4) { char *s = aalloc(8); for (int k = 0; k < 5; k++) s[k] = 'a' + (char)(rnd() % 26); put_ptr(base, f, s); }
			break;
		case GCK_RPC_F_MECHPTR:
			if (rnd() % 4) {
				CK_MECHANISM *m = aalloc(sizeof *m);
				switch (rnd() % 3) {
				case 0: m->mechanism = CKM_SHA256; break;
				case 1: m->mechanism = CKM_AES_CBC; m->pParameter = aalloc(16); rbytes(m->pParameter, 16); m->ulParameterLen = 16; break;
				default: {
					CK_ECDH1_DERIVE_PARAMS *e = aalloc(sizeof *e);
					e->kdf = 1; e->ulPublicDataLen = 5; e->pPublicData = aalloc(5); rbytes(e->pPublicData, 5);
					m->mechanism = CKM_ECDH1_DERIVE; m->pParameter = e; m->ulParameterLen = sizeof *e;
				}
				}
				put_ptr(base, f, m);
			}
			break;
		}
	}
}

/* ---- do two structures carry the same request? ---- */
static int same_mech(const CK_MECHANISM *a, const CK_MECHANISM *b)
{
	unsigned char *x, *y; size_t nx, ny; int ok;
	if (a->mechanism != b->mechanism) return 0;
	if (gck_rpc_mech_param_encode(a, &x, &nx) != CKR_OK) return 0;
	if (gck_rpc_mech_param_encode(b, &y, &ny) != CKR_OK) { free(x); return 0; }
	ok = nx == ny && (nx == 0 || memcmp(x, y, nx) == 0);
	free(x); free(y);
	return ok;
}
static int same(const GckRpcParamDesc *d, const unsigned char *a, const GckRpcParamDesc *pda, const unsigned char *pa,
		const unsigned char *b, const GckRpcParamDesc *pdb, const unsigned char *pb, int phase)
{
	for (int i = 0; i < d->nfields; i++) {
		const GckRpcParamField *f = &d->fields[i];
		int sent = (f->req & phase) != 0;
		if (scalar_type(f->type)) {
			if (!f->resp && get_sc(a, f) != get_sc(b, f)) return 0;
		} else if (f->type == GCK_RPC_F_ULONGPTR) {
			CK_ULONG *x = ptr_at(a, f), *y = ptr_at(b, f);
			if ((x == NULL) != (y == NULL)) return 0;
			if (x && sent && *x != *y) return 0;
		} else if (f->type == GCK_RPC_F_BUF || f->type == GCK_RPC_F_OBUF) {
			void *x = ptr_at(a, f), *y = ptr_at(b, f);
			size_t la = tlen(d, a, pda, pa, i), lb = tlen(d, b, pdb, pb, i);
			if (la != lb) return 0;
			if (f->type == GCK_RPC_F_OBUF && (x == NULL) != (y == NULL)) return 0;
			if (sent && la && x && y && memcmp(x, y, la) != 0) return 0;
		} else if (f->type == GCK_RPC_F_INLINE) {
			if (sent && memcmp(a + f->off, b + f->off, f->len_fixed) != 0) return 0;
		} else if (f->type == GCK_RPC_F_STRUCT) {
			const unsigned char *x = ptr_at(a, f), *y = ptr_at(b, f);
			if ((x == NULL) != (y == NULL)) return 0;
			if (x && !same(f->sub, x, d, a, y, d, b, phase)) return 0;
		} else if (f->type == GCK_RPC_F_ISTRUCT) {
			if (!same(f->sub, a + f->off, d, a, b + f->off, d, b, phase)) return 0;
		} else if (f->type == GCK_RPC_F_ARRAY) {
			size_t n = tcount(d, a, pda, pa, i);
			const unsigned char *x = ptr_at(a, f), *y = ptr_at(b, f);
			for (size_t k = 0; x && k < n; k++)
				if (!same(f->sub, x + k * f->sub->size, d, a, y + k * f->sub->size, d, b, phase)) return 0;
		} else if (f->type == GCK_RPC_F_ATTRS) {
			size_t n = tcount(d, a, pda, pa, i);
			const CK_ATTRIBUTE *x = ptr_at(a, f), *y = ptr_at(b, f);
			for (size_t k = 0; x && k < n; k++)
				if (x[k].type != y[k].type || x[k].ulValueLen != y[k].ulValueLen ||
				    (x[k].ulValueLen && memcmp(x[k].pValue, y[k].pValue, x[k].ulValueLen))) return 0;
		} else if (f->type == GCK_RPC_F_CSTR) {
			const char *x = ptr_at(a, f), *y = ptr_at(b, f);
			if ((x == NULL) != (y == NULL) || (x && strcmp(x, y))) return 0;
		} else if (f->type == GCK_RPC_F_MECHPTR) {
			const CK_MECHANISM *x = ptr_at(a, f), *y = ptr_at(b, f);
			if ((x == NULL) != (y == NULL) || (x && !same_mech(x, y))) return 0;
		}
	}
	return 1;
}

/* ---- every pointer of a decoded structure is the daemon's own ---- */
static int owned(const GckRpcParamDesc *d, const unsigned char *base, const GckRpcParamDesc *pd,
		 const unsigned char *pbase, int depth)
{
	if (depth > 4) return 0;
	for (int i = 0; i < d->nfields; i++) {
		const GckRpcParamField *f = &d->fields[i];
		void *p;
		if (f->type == GCK_RPC_F_ULONGPTR) {
			p = ptr_at(base, f);
			if (p && !inside(p, sizeof(CK_ULONG))) return 0;
		} else if (f->type == GCK_RPC_F_BUF || f->type == GCK_RPC_F_OBUF) {
			p = ptr_at(base, f);
			size_t len = tlen(d, base, pd, pbase, i);
			if (!p) continue;
			if (!inside(p, len)) return 0;
			if (len) { volatile unsigned char x = ((unsigned char *)p)[0]; x = ((unsigned char *)p)[len - 1]; (void)x; }
		} else if (f->type == GCK_RPC_F_STRUCT) {
			p = ptr_at(base, f);
			if (p && (!inside(p, f->sub->size) || !owned(f->sub, p, d, base, depth + 1))) return 0;
		} else if (f->type == GCK_RPC_F_ISTRUCT) {
			if (!owned(f->sub, base + f->off, d, base, depth + 1)) return 0;
		} else if (f->type == GCK_RPC_F_ARRAY) {
			p = ptr_at(base, f);
			size_t n = tcount(d, base, pd, pbase, i);
			if (p && !inside(p, n * f->sub->size)) return 0;
			for (size_t k = 0; p && k < n; k++)
				if (!owned(f->sub, (unsigned char *)p + k * f->sub->size, d, base, depth + 1)) return 0;
		} else if (f->type == GCK_RPC_F_ATTRS) {
			CK_ATTRIBUTE *a = ptr_at(base, f);
			size_t n = tcount(d, base, pd, pbase, i);
			if (a && !inside(a, n * sizeof *a)) return 0;
			for (size_t k = 0; a && k < n; k++)
				if (a[k].ulValueLen != (CK_ULONG)-1 && a[k].pValue && !inside(a[k].pValue, a[k].ulValueLen)) return 0;
		} else if (f->type == GCK_RPC_F_CSTR) {
			const char *s = ptr_at(base, f);
			if (s && !inside(s, strlen(s) + 1)) return 0;
		} else if (f->type == GCK_RPC_F_MECHPTR) {
			const CK_MECHANISM *m = ptr_at(base, f);
			if (m && (!inside(m, sizeof *m) || (m->pParameter && !inside(m->pParameter, m->ulParameterLen)))) return 0;
		}
	}
	return 1;
}

/* ---- the module fills in its outputs ---- */
static void module_writes(const GckRpcParamDesc *d, unsigned char *base, const GckRpcParamDesc *pd, const unsigned char *pbase)
{
	int i, j;
	for (i = 0; i < d->nfields; i++) {
		const GckRpcParamField *f = &d->fields[i];
		if (!f->resp) continue;
		if (scalar_type(f->type)) put_sc(base, f, rnd() % 1000);
		else if (f->type == GCK_RPC_F_ULONGPTR) {
			CK_ULONG *p = ptr_at(base, f);
			int is_len = 0;
			for (j = 0; j < d->nfields; j++) if (d->fields[j].len_idx == i && !(d->fields[j].flags & GCK_RPC_LEN_PARENT)) is_len = 1;
			/* a length the module updates never exceeds the room it was given */
			if (p) *p = is_len ? rnd() % (*p + 1) : rnd() % 1000;
		}
	}
	for (i = 0; i < d->nfields; i++) {
		const GckRpcParamField *f = &d->fields[i];
		if (!f->resp) continue;
		if (f->type == GCK_RPC_F_BUF || f->type == GCK_RPC_F_OBUF) {
			void *p = ptr_at(base, f);
			if (p) rbytes(p, tlen(d, base, pd, pbase, i));
		} else if (f->type == GCK_RPC_F_STRUCT) {
			void *p = ptr_at(base, f);
			if (p) module_writes(f->sub, p, d, base);
		} else if (f->type == GCK_RPC_F_ISTRUCT) module_writes(f->sub, base + f->off, d, base);
		else if (f->type == GCK_RPC_F_ARRAY) {
			unsigned char *a = ptr_at(base, f); size_t n = tcount(d, base, pd, pbase, i);
			for (size_t k = 0; a && k < n; k++) module_writes(f->sub, a + k * f->sub->size, d, base);
		}
	}
}

static int same_out(const GckRpcParamDesc *d, const unsigned char *a, const GckRpcParamDesc *pda, const unsigned char *pa,
		    const unsigned char *b, const GckRpcParamDesc *pdb, const unsigned char *pb)
{
	for (int i = 0; i < d->nfields; i++) {
		const GckRpcParamField *f = &d->fields[i];
		if (!f->resp) continue;
		if (scalar_type(f->type)) { if (get_sc(a, f) != get_sc(b, f)) return 0; }
		else if (f->type == GCK_RPC_F_ULONGPTR) {
			CK_ULONG *x = ptr_at(a, f), *y = ptr_at(b, f);
			if (x && *x != *y) return 0;
		} else if (f->type == GCK_RPC_F_BUF || f->type == GCK_RPC_F_OBUF) {
			void *x = ptr_at(a, f), *y = ptr_at(b, f);
			size_t la = tlen(d, a, pda, pa, i);
			if (x && y && la && memcmp(x, y, la)) return 0;
		} else if (f->type == GCK_RPC_F_STRUCT) {
			const unsigned char *x = ptr_at(a, f), *y = ptr_at(b, f);
			if (x && !same_out(f->sub, x, d, a, y, d, b)) return 0;
		} else if (f->type == GCK_RPC_F_ISTRUCT) {
			if (!same_out(f->sub, a + f->off, d, a, b + f->off, d, b)) return 0;
		} else if (f->type == GCK_RPC_F_ARRAY) {
			const unsigned char *x = ptr_at(a, f), *y = ptr_at(b, f);
			size_t n = tcount(d, a, pda, pa, i);
			for (size_t k = 0; x && k < n; k++)
				if (!same_out(f->sub, x + k * f->sub->size, d, a, y + k * f->sub->size, d, b)) return 0;
		}
	}
	return 1;
}

static void mutate(unsigned char *b, size_t *n)
{
	int k = 1 + (int)(rnd() % 3);
	while (k-- && *n) b[rnd() % *n] = (unsigned char)rnd();
	if (rnd() % 4 == 0) *n = rnd() % (*n + 1);
}

static void test_kind(const GckRpcParamDesc *d, long iters)
{
	int phase = (d->phases & GCK_RPC_PHASE_MECH) ? GCK_RPC_PHASE_MECH :
		    ((rnd() & 1) ? GCK_RPC_PHASE_ENC : GCK_RPC_PHASE_DEC);
	long ok_mut = 0;

	for (long it = 0; it < iters; it++) {
		unsigned char *client = aalloc(d->size), *blob = NULL, *blob2 = NULL, *rb = NULL, *snap;
		size_t n = 0, n2 = 0, rn = 0;
		GckRpcParamState st;
		CK_RV rv;

		phase = (d->phases & GCK_RPC_PHASE_MECH) ? GCK_RPC_PHASE_MECH :
			((rnd() & 1) ? GCK_RPC_PHASE_ENC : GCK_RPC_PHASE_DEC);
		fill(d, client, NULL, NULL);
		rv = gck_rpc_param_encode_alloc(d, client, phase, &blob, &n);
		if (rv != CKR_OK) { FAIL("kind %d: encode failed 0x%lx", d->kind, (unsigned long)rv); arena_free(); return; }

		nblocks = 0;
		rv = gck_rpc_param_decode(blob, n, phase, &st, dal, NULL);
		if (rv != CKR_OK || st.desc != d) { FAIL("kind %d: decode failed 0x%lx", d->kind, (unsigned long)rv); free(blob); free_blocks(); arena_free(); return; }
		if (!owned(d, (unsigned char *)&st.s, NULL, NULL, 0)) { FAIL("kind %d: a pointer escapes the daemon's memory", d->kind); return; }
		if (!same(d, client, NULL, NULL, (unsigned char *)&st.s, NULL, NULL, phase)) { FAIL("kind %d: the rebuilt structure differs", d->kind); return; }
		if (gck_rpc_param_encode_alloc(d, &st.s, phase, &blob2, &n2) != CKR_OK || n2 != n || memcmp(blob, blob2, n) != 0) {
			FAIL("kind %d: re-encoding the rebuilt structure gives another blob", d->kind); return; }

		/* the module writes outputs; they must reach the caller's structure */
		module_writes(d, (unsigned char *)&st.s, NULL, NULL);
		rv = gck_rpc_param_resp_encode_alloc(&st, &rb, &rn);
		if (rv != CKR_OK) { FAIL("kind %d: reply encode failed 0x%lx", d->kind, (unsigned long)rv); return; }
		snap = malloc(d->size);
		memcpy(snap, client, d->size);
		rv = gck_rpc_param_resp_apply(d, client, rb, rn);
		if (rv != CKR_OK) { FAIL("kind %d: applying the reply failed 0x%lx", d->kind, (unsigned long)rv); return; }
		if (!same_out(d, (unsigned char *)&st.s, NULL, NULL, client, NULL, NULL)) { FAIL("kind %d: outputs did not arrive", d->kind); return; }
		free(snap);

		/* corrupt replies are refused and change nothing */
		if (rn) {
			unsigned char *bad = malloc(rn + 4); size_t bn = rn, before_n;
			unsigned char *copy = malloc(d->size);
			memcpy(bad, rb, rn); memcpy(copy, client, d->size);
			(void)before_n;
			mutate(bad, &bn);
			if (rnd() & 1 && bn == rn) bn = rn + (rnd() % 3 ? 1 : 0);   /* trailing garbage */
			if (gck_rpc_param_resp_apply(d, client, bad, bn) != CKR_OK && memcmp(copy, client, d->size) != 0)
				FAIL("kind %d: a refused reply changed the structure", d->kind);
			free(bad); free(copy);
		}

		free_blocks();

		/* corrupt requests never crash the decoder or leak a foreign pointer */
		for (int m = 0; m < 4; m++) {
			unsigned char *mb = malloc(n + 8); size_t mn = n;
			memcpy(mb, blob, n);
			mutate(mb, &mn);
			GckRpcParamState st2;
			if (gck_rpc_param_decode(mb, mn, phase, &st2, dal, NULL) == CKR_OK) {
				ok_mut++;
				if (!owned(st2.desc, (unsigned char *)&st2.s, NULL, NULL, 0)) { FAIL("kind %d: mutated blob yields a foreign pointer", d->kind); return; }
			}
			free_blocks();
			free(mb);
		}
		free(blob); free(blob2); free(rb);
		free_blocks();
		arena_free();
	}
	(void)ok_mut;
}

int main(int argc, char **argv)
{
	long n_it = argc > 1 ? atol(argv[1]) : 2000;
	size_t nd, i;
	const GckRpcParamDesc *const *ds = gck_rpc_param_descs(&nd);

	for (i = 0; i < nd; i++)
		test_kind(ds[i], n_it);
	printf("%zu structure kinds x %ld random structures: round trip, outputs, mutations\n", nd, n_it);

	/* random garbage against every kind */
	{
		unsigned char blob[512];
		long ok = 0;
		for (long it = 0; it < n_it * 20; it++) {
			size_t n = rnd() % sizeof blob;
			for (size_t k = 0; k < n; k++) blob[k] = (unsigned char)rnd();
			if (n) blob[0] = (unsigned char)(1 + rnd() % (nd + 2));
			for (size_t k = 1; k + 8 <= n; k += 8) if (rnd() & 1) { memset(blob + k, 0, 7); blob[k + 7] = (unsigned char)(rnd() % 6); }
			GckRpcParamState st;
			nblocks = 0;
			if (gck_rpc_param_decode(blob, n, 1 << (rnd() % 3), &st, dal, NULL) == CKR_OK) {
				ok++;
				if (!owned(st.desc, (unsigned char *)&st.s, NULL, NULL, 0)) { FAIL("random blob yields a foreign pointer"); break; }
			}
			free_blocks();
		}
		printf("random blobs: %ld decoded, no foreign pointers\n", ok);
	}

	/* nested attribute templates */
	{
		long tok = 0, trej = 0, tapply = 0;
		void *tptrs[512]; int ntp;
		for (long it = 0; it < n_it * 10; it++) {
			CK_ATTRIBUTE in[4];
			CK_ULONG cnt = rnd() % 5, k;
			unsigned char vals[4][40];
			GckRpcTplBuf b;
			int bufmode = rnd() & 1;

			for (k = 0; k < cnt; k++) {
				memset(vals[k], (int)k + 1, sizeof vals[k]);
				in[k].type = CKA_LABEL + (rnd() % 8);
				in[k].pValue = (rnd() % 5) ? vals[k] : NULL;
				in[k].ulValueLen = (rnd() % 7 || bufmode) ? rnd() % 40 : (CK_ULONG)-1;
			}
			if (!gck_rpc_template_encode(&b, in, cnt, bufmode)) { FAIL("template encode failed"); break; }
			int nmut = rnd() % 4;
			for (int m = 0; m < nmut && b.len; m++) b.p[rnd() % b.len] = (unsigned char)rnd();
			size_t n = b.len; if (rnd() % 4 == 0) n = rnd() % (b.len + 1);
			CK_ATTRIBUTE_PTR out; CK_ULONG oc;
			ntp = 0;
			nblocks = 0;
			/* collect this decoder's allocations to free them */
			CK_RV rv = gck_rpc_template_decode(b.p, n, bufmode, dal, NULL, &out, &oc);
			(void)tptrs; (void)ntp;
			if (rv == CKR_OK) {
				tok++;
				for (k = 0; k < oc; k++)
					if (out[k].pValue && (CK_LONG)out[k].ulValueLen != -1) {
						volatile unsigned char x = ((unsigned char *)out[k].pValue)[0];
						if (out[k].ulValueLen) x = ((unsigned char *)out[k].pValue)[out[k].ulValueLen - 1];
						(void)x;
					}
			} else trej++;
			free_blocks();
			if (!bufmode) {
				CK_ATTRIBUTE mine[4]; unsigned char store[4][40];
				for (k = 0; k < cnt; k++) { mine[k].type = in[k].type; mine[k].pValue = store[k]; mine[k].ulValueLen = sizeof store[k]; }
				if (gck_rpc_template_apply(b.p, n, mine, cnt) == CKR_OK) tapply++;
			}
			free(b.p);
		}
		printf("templates: decoded %ld rejected %ld, replies applied %ld\n", tok, trej, tapply);
	}

	printf("%d failure(s)\n", fails);
	return fails != 0;
}
