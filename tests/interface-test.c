/*
 * C_GetInterface / C_GetInterfaceList and the C_Initialize locking rules,
 * through the proxy (against tests/mock-module.c).
 * Usage: interface-test <libpkcs11-proxy>
 */
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include "pkcs11/v3.2/pkcs11-platform.h"
#include "pkcs11/v3.2/pkcs11.h"

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { printf("FAIL: " __VA_ARGS__); printf("\n"); fails++; } else { printf("ok:   " __VA_ARGS__); printf("\n"); } } while (0)
#define RV(name, rv, want) do { CK_RV _r = (rv); CHECK(_r == (want), "%s -> 0x%lx (want 0x%lx)", name, (unsigned long)_r, (unsigned long)(want)); } while (0)

static CK_C_GetInterface gi;

static CK_RV mx_create(CK_VOID_PTR_PTR m) { *m = NULL; return CKR_OK; }
static CK_RV mx_op(CK_VOID_PTR m) { return CKR_OK; }

static CK_FUNCTION_LIST_3_2_PTR get(const char *name, int major, int minor, CK_FLAGS flags, CK_RV *rv)
{
	CK_VERSION v = { major, minor };
	CK_INTERFACE_PTR i = NULL;
	*rv = gi((CK_UTF8CHAR_PTR)name, major < 0 ? NULL : &v, &i, flags);
	return *rv == CKR_OK ? i->pFunctionList : NULL;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	void *h = dlopen(argv[1], RTLD_NOW);
	if (!h) { printf("dlopen: %s\n", dlerror()); return 2; }
	gi = dlsym(h, "C_GetInterface");
	CK_C_GetInterfaceList gl = dlsym(h, "C_GetInterfaceList");
	CK_RV rv;

	/* exact versions: each list announces the version that was asked for */
	static const int want[][2] = { {3, 2}, {3, 1}, {3, 0} };
	CK_FUNCTION_LIST_3_2_PTR lists[3];
	for (int i = 0; i < 3; i++) {
		lists[i] = get("PKCS 11", want[i][0], want[i][1], 0, &rv);
		CHECK(rv == CKR_OK && lists[i] && lists[i]->version.major == want[i][0] && lists[i]->version.minor == want[i][1],
		      "interface %d.%d announces its version", want[i][0], want[i][1]);
	}
	if (lists[0] && lists[1] && lists[2]) {
		CHECK(lists[1]->C_Initialize == lists[0]->C_Initialize && lists[2]->C_EncryptMessage == lists[0]->C_EncryptMessage &&
		      lists[2]->C_MessageVerifyFinal == lists[0]->C_MessageVerifyFinal,
		      "3.0 and 3.1 lists have the same functions as 3.2");
	}
	CK_FUNCTION_LIST_3_2_PTR two = get("PKCS 11", 2, 40, 0, &rv);
	CHECK(rv == CKR_OK && two && ((CK_FUNCTION_LIST_PTR)two)->version.major == 2 && ((CK_FUNCTION_LIST_PTR)two)->version.minor == 40,
	      "interface 2.40 is the 2.x list");
	CK_FUNCTION_LIST_3_2_PTR def = get(NULL, -1, 0, 0, &rv);
	CHECK(rv == CKR_OK && def == lists[0], "no name/version -> the newest (3.2)");
	get("PKCS 11", 3, 3, 0, &rv);   RV("version 3.3 unknown", rv, CKR_ARGUMENTS_BAD);
	get("PKCS 11", 2, 20, 0, &rv);  RV("version 2.20 unknown", rv, CKR_ARGUMENTS_BAD);
	get("PKCS 11", 3, 2, CKF_INTERFACE_FORK_SAFE, &rv); RV("flags nothing satisfies", rv, CKR_ARGUMENTS_BAD);
	get("Vendor X", -1, 0, 0, &rv); RV("unknown interface name", rv, CKR_ARGUMENTS_BAD);
	{
		CK_INTERFACE_PTR none = (CK_INTERFACE_PTR)1;
		gi((CK_UTF8CHAR_PTR)"nope", NULL, &none, 0);
		CHECK(none == NULL, "*ppInterface cleared on failure");
	}

	/* the list: 3.2, 3.1, 3.0 and 2.40, with the usual two-call protocol */
	CK_ULONG n = 0;
	RV("C_GetInterfaceList(count)", gl(NULL, &n), CKR_OK);
	CHECK(n == 4, "4 interfaces (%lu)", (unsigned long)n);
	CK_INTERFACE il[8]; CK_ULONG small = 2;
	RV("C_GetInterfaceList(too small)", gl(il, &small), CKR_BUFFER_TOO_SMALL);
	CHECK(small == 4, "required count reported (%lu)", (unsigned long)small);
	n = 8;
	RV("C_GetInterfaceList", gl(il, &n), CKR_OK);
	if (n == 4) {
		int vers[4][2] = { {3, 2}, {3, 1}, {3, 0}, {2, 40} }, ok = 1;
		for (int i = 0; i < 4; i++) {
			CK_VERSION *v = (CK_VERSION *)il[i].pFunctionList;
			if (strcmp((char *)il[i].pInterfaceName, "PKCS 11") || v->major != vers[i][0] || v->minor != vers[i][1]) ok = 0;
		}
		CHECK(ok, "list is 3.2, 3.1, 3.0, 2.40 named \"PKCS 11\"");
	}

	/* ---- C_Initialize locking (PKCS#11 section on C_Initialize) ---- */
	CK_FUNCTION_LIST_3_2_PTR f = lists[0];
	CK_C_INITIALIZE_ARGS a;

	memset(&a, 0, sizeof a);
	RV("no locking requested (single-threaded caller)", f->C_Initialize(&a), CKR_OK);
	RV("C_Finalize", f->C_Finalize(NULL), CKR_OK);

	memset(&a, 0, sizeof a); a.flags = CKF_LIBRARY_CANT_CREATE_OS_THREADS;
	RV("CANT_CREATE_OS_THREADS only", f->C_Initialize(&a), CKR_OK);
	RV("C_Finalize", f->C_Finalize(NULL), CKR_OK);

	memset(&a, 0, sizeof a); a.flags = CKF_OS_LOCKING_OK;
	RV("OS locking allowed", f->C_Initialize(&a), CKR_OK);
	RV("C_Finalize", f->C_Finalize(NULL), CKR_OK);

	memset(&a, 0, sizeof a); a.CreateMutex = mx_create; a.DestroyMutex = mx_op; a.LockMutex = mx_op; a.UnlockMutex = mx_op;
	RV("mutex functions without OS locking: we can't use them", f->C_Initialize(&a), CKR_CANT_LOCK);

	a.flags = CKF_OS_LOCKING_OK;
	RV("mutex functions and OS locking allowed", f->C_Initialize(&a), CKR_OK);
	RV("C_Finalize", f->C_Finalize(NULL), CKR_OK);

	memset(&a, 0, sizeof a); a.CreateMutex = mx_create; a.flags = CKF_OS_LOCKING_OK;
	RV("only some mutex functions", f->C_Initialize(&a), CKR_ARGUMENTS_BAD);

	RV("C_Initialize(NULL)", f->C_Initialize(NULL), CKR_OK);
	RV("C_Initialize twice", f->C_Initialize(NULL), CKR_CRYPTOKI_ALREADY_INITIALIZED);
	RV("C_Finalize", f->C_Finalize(NULL), CKR_OK);
	RV("C_Finalize when not initialized", f->C_Finalize(NULL), CKR_CRYPTOKI_NOT_INITIALIZED);
	RV("C_Finalize with pReserved", f->C_Finalize((CK_VOID_PTR)1), CKR_ARGUMENTS_BAD);

	printf("\n%d failure(s)\n", fails);
	return fails != 0;
}
