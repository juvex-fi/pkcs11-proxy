/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-rpc-daemon-standalone.c - A sample daemon.

   Copyright (C) 2008, Stef Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "pkcs11/pkcs11.h"

#include "gck-rpc-layer.h"
#include "gck-rpc-tls-psk.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>

#include <dlfcn.h>
#include <pthread.h>

#include <syslog.h>

#ifdef __MINGW32__
# include <winsock2.h>
#endif

#define SOCKET_PATH "tcp://127.0.0.1"

#ifdef SECCOMP
#include <seccomp.h>
#ifdef DEBUG_SECCOMP
# include "syscall-reporter.h"
#endif /* DEBUG_SECCOMP */
#include <fcntl.h> /* for seccomp init */
#include <sys/socket.h>
#endif /* SECCOMP */


static int install_syscall_filter(const int sock, const char *tls_psk_keyfile, const char *path)
{
#ifdef SECCOMP
	int rc = -1;
	scmp_filter_ctx ctx;

#ifdef DEBUG_SECCOMP
	ctx = seccomp_init(SCMP_ACT_TRAP);
#else
	ctx = seccomp_init(SCMP_ACT_KILL);
#endif /* DEBUG_SECCOMP */
	if (ctx == NULL)
		goto failure_scmp;
	/*
	 * SCMP_SYS() of a syscall that doesn't exist on this architecture
	 * (e.g. open/stat/select on aarch64) makes seccomp_rule_add() fail
	 * harmlessly, so no per-arch #ifdefs are needed.
	 */
#define ALLOW(name) seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(name), 0)

	/* Basics, also needed by the syscall-reporter and the SIGTERM handler */
	ALLOW(write);
	ALLOW(rt_sigreturn);
	ALLOW(sigreturn);
	ALLOW(exit);
	ALLOW(exit_group);

	/*
	 * Network related syscalls.
	 */
	ALLOW(read);
	ALLOW(select);
	ALLOW(pselect6);
	ALLOW(poll);
	if (sock) {
		/* Allow accept() only for the listening socket */
		seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(accept), 1,
				 SCMP_A0(SCMP_CMP_EQ, sock));
		seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(accept4), 1,
				 SCMP_A0(SCMP_CMP_EQ, sock));
	}
	ALLOW(sendto);
	ALLOW(recvfrom);
	/* OpenSSL probes for kernel TLS (TCP_ULP) */
	ALLOW(setsockopt);
	/* syslog() connects to /dev/log */
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(socket), 1,
			 SCMP_A0(SCMP_CMP_EQ, AF_UNIX));
	ALLOW(connect);

	/*
	 * Memory management, threads, signals (glibc, OpenSSL 3.x).
	 */
	ALLOW(brk);
	ALLOW(mmap);
	ALLOW(munmap);
	ALLOW(mprotect);
	ALLOW(madvise);
	ALLOW(munlock);
	ALLOW(clone);
	ALLOW(clone3);
	ALLOW(set_robust_list);
	ALLOW(rseq);
	ALLOW(membarrier);
	ALLOW(futex);
	ALLOW(getpid);
	ALLOW(gettid);
	ALLOW(rt_sigaction);
	ALLOW(rt_sigprocmask);
	ALLOW(sigaltstack);
	ALLOW(getrandom);
	ALLOW(clock_gettime);
	ALLOW(sysinfo);
	ALLOW(ioctl);

	/*
	 * Allow spawned threads to initialize a new seccomp policy (subset of this).
	 */
	ALLOW(prctl);
	ALLOW(seccomp);

	/*
	 * File I/O: TLS-PSK keyfile, the Unix socket and the PKCS#11 module.
	 * open()/openat() can't be limited to O_RDONLY since e.g. SoftHSM
	 * creates and rewrites its token files.
	 */
	ALLOW(open);
	ALLOW(openat);
	ALLOW(close);
	ALLOW(getcwd);
	ALLOW(stat);
	ALLOW(newfstatat);
	ALLOW(fstat);
	ALLOW(fcntl);
	ALLOW(lseek);
	ALLOW(pread64);
	ALLOW(pwrite64);
	ALLOW(access);
	ALLOW(faccessat);
	ALLOW(fsync);
	ALLOW(fdatasync);
	ALLOW(ftruncate);
	ALLOW(getdents64);
	ALLOW(unlink);
	ALLOW(unlinkat);
#undef ALLOW

#ifdef DEBUG_SECCOMP
	/* Dumps the generated BPF rules in sort-of human readable syntax. */
	seccomp_export_pfc(ctx,STDERR_FILENO);

	/* Print the name of syscalls stopped by seccomp. Should not be used in production. */
        if (install_syscall_reporter())
                return 1;
#endif /* DEBUG_SECCOMP */

	rc = seccomp_load(ctx);
	if (rc < 0)
		goto failure_scmp;
	seccomp_release(ctx);

	return 0;

failure_scmp:
	errno = -rc;
	fprintf(stderr, "Seccomp filter initialization failed: %s (errno %u); "
		"use --no-seccomp if seccomp is unavailable\n", strerror(errno), errno);
	return errno;
#else /* SECCOMP */
        return 0;
#endif /* SECCOMP */
}


#if 0
/* Sample configuration for loading NSS remotely */
static CK_C_INITIALIZE_ARGS p11_init_args = {
	NULL,
	NULL,
	NULL,
	NULL,
	CKF_OS_LOCKING_OK,
	"init-string = configdir='/tmp' certPrefix='' keyPrefix='' secmod='/tmp/secmod.db' flags="
};
#endif

static volatile sig_atomic_t is_running = 1;

static int usage(void)
{
	fprintf(stderr, "usage: pkcs11-daemon pkcs11-module [<socket>|\"-\"] [--drop-privs <user>] [--no-seccomp]\n"
		"\tUsing \"-\" results in a single-thread inetd-type daemon\n"
		"\t--drop-privs <user>  switch to <user> after the socket is bound (when started as root)\n"
		"\t--no-seccomp         don't install the seccomp syscall filters\n");
	exit(2);
}

void termination_handler (int signum)
{
	is_running = 0;
}

/*
 * Switch to an unprivileged user. Called after the module is initialized
 * and the socket is bound, so those may still need root.
 */
static int drop_privileges(const char *username)
{
	struct passwd *pw;

	if (getuid() != 0 && geteuid() != 0) {
		fprintf(stderr, "not running as root, ignoring --drop-privs %s\n",
			username);
		return 0;
	}

	pw = getpwnam(username);
	if (!pw) {
		fprintf(stderr, "couldn't find user '%s'\n", username);
		return -1;
	}

	/* Group first: setgid() is no longer permitted once uid is dropped */
	if (initgroups(pw->pw_name, pw->pw_gid) < 0 ||
	    setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0) {
		fprintf(stderr, "couldn't switch to user '%s': %s\n", username,
			strerror(errno));
		return -1;
	}

	if (pw->pw_uid != 0 && (setuid(0) == 0 || seteuid(0) == 0)) {
		fprintf(stderr, "was able to regain root after dropping privileges\n");
		return -1;
	}

	syslog(LOG_INFO, "dropped privileges to user '%s' (uid=%u, gid=%u)",
	       username, (unsigned)pw->pw_uid, (unsigned)pw->pw_gid);
	return 0;
}

enum {
	/* Used to un-confuse clang checker */
	GCP_RPC_DAEMON_MODE_INETD = 0,
	GCP_RPC_DAEMON_MODE_SOCKET
};

int main(int argc, char *argv[])
{
	CK_C_GetFunctionList func_get_list;
	CK_FUNCTION_LIST_PTR funcs;
	void *module;
	const char *path, *tls_psk_keyfile;
	const char *socket_arg = NULL, *drop_privs_user = NULL;
	int use_seccomp = 1;
	fd_set read_fds;
	int sock, ret, mode, i;
	CK_RV rv;
	CK_C_INITIALIZE_ARGS init_args;
	GckRpcTlsPskState *tls;

	/* The module to load is the first argument, then an optional socket
	 * and options in any order */
	if (argc < 2 || argv[1][0] == '-')
		usage();
	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--drop-privs") == 0) {
			if (++i >= argc || !argv[i][0])
				usage();
			drop_privs_user = argv[i];
		} else if (strcmp(argv[i], "--no-seccomp") == 0) {
			use_seccomp = 0;
		} else if (strncmp(argv[i], "--", 2) == 0 || socket_arg) {
			usage();
		} else {
			socket_arg = argv[i];
		}
	}

        openlog("pkcs11-proxy",LOG_CONS|LOG_PID,LOG_DAEMON);

	/* Load the library */
	module = dlopen(argv[1], RTLD_NOW);
	if (!module) {
		fprintf(stderr, "couldn't open library: %s: %s\n", argv[1],
			dlerror());
		exit(1);
	}

	/* Lookup the appropriate function in library */
	func_get_list =
	    (CK_C_GetFunctionList) dlsym(module, "C_GetFunctionList");
	if (!func_get_list) {
		fprintf(stderr,
			"couldn't find C_GetFunctionList in library: %s: %s\n",
			argv[1], dlerror());
		exit(1);
	}

	/* Get the function list */
	rv = (func_get_list) (&funcs);
	if (rv != CKR_OK || !funcs) {
		fprintf(stderr,
			"couldn't get function list from C_GetFunctionList"
			"in libary: %s: 0x%08x\n",
			argv[1], (int)rv);
		exit(1);
	}

	/* RPC layer expects initialized module */
	memset(&init_args, 0, sizeof(init_args));
	init_args.flags = CKF_OS_LOCKING_OK;

	rv = (funcs->C_Initialize) (&init_args);
	if (rv != CKR_OK) {
		fprintf(stderr, "couldn't initialize module: %s: 0x%08x\n",
			argv[1], (int)rv);
		exit(1);
	}

	/* Optionally get the v3.2 function list for extended API support */
	{
		CK_C_GetInterface func_get_iface =
		    (CK_C_GetInterface) dlsym(module, "C_GetInterface");
		if (func_get_iface) {
			CK_INTERFACE_PTR iface = NULL;
			CK_VERSION ver32 = {3, 2};
			if (func_get_iface((CK_UTF8CHAR_PTR)"PKCS 11", &ver32,
					   &iface, 0) == CKR_OK && iface &&
			    iface->pFunctionList)
				gck_rpc_layer_set_module_v32(
				    (CK_FUNCTION_LIST_3_2_PTR)iface->pFunctionList);
		}
	}

	path = getenv("PKCS11_DAEMON_SOCKET");
	if (!path)
           path = socket_arg;
        if (!path)
	   path = SOCKET_PATH;

	/* Initialize TLS, if appropriate */
	tls = NULL;
	tls_psk_keyfile = NULL;
	if (! strncmp("tls://", path, 6)) {
		tls_psk_keyfile = getenv("PKCS11_PROXY_TLS_PSK_FILE");
		if (! tls_psk_keyfile || ! tls_psk_keyfile[0]) {
			fprintf(stderr, "key file must be specified for tls:// socket.\n");
			exit(1);
		}

		tls = calloc(1, sizeof(GckRpcTlsPskState));
		if (tls == NULL) {
			fprintf(stderr, "can't allocate memory for TLS-PSK");
			exit(1);
		}

		if (! gck_rpc_init_tls_psk(tls, tls_psk_keyfile, NULL, GCK_RPC_TLS_PSK_SERVER)) {
			fprintf(stderr, "TLS-PSK initialization failed");
			exit(1);
		}
	}

	if (strcmp(path,"-") == 0) {
		/* inetd mode */
		sock = 0;
		mode = GCP_RPC_DAEMON_MODE_INETD;
	} else {
		/* Do some initialization before enabling seccomp. */
		sock = gck_rpc_layer_initialize(path, funcs);
		if (sock == -1)
			exit(1);

		/* Shut down gracefully on SIGTERM. */
		if (signal (SIGTERM, termination_handler) == SIG_IGN)
			signal (SIGTERM, SIG_IGN);

		mode = GCP_RPC_DAEMON_MODE_SOCKET;
	}

	if (drop_privs_user && drop_privileges(drop_privs_user) < 0)
		exit(1);

	/*
	 * Enable seccomp. This is essentially a whitelist containing all the syscalls
	 * we expect to call from here on. Anything not whitelisted will cause the
	 * process to terminate.
	 */
	gck_rpc_layer_set_seccomp(use_seccomp);
	if (use_seccomp) {
		if (install_syscall_filter(sock, tls_psk_keyfile, path))
			return 1;
	} else {
		syslog(LOG_WARNING, "seccomp disabled by --no-seccomp");
	}

        if (mode == GCP_RPC_DAEMON_MODE_INETD) {
           gck_rpc_layer_inetd(funcs);
        } else if (mode == GCP_RPC_DAEMON_MODE_SOCKET) {
	   is_running = 1;
	   while (is_running) {
		FD_ZERO(&read_fds);
		FD_SET(sock, &read_fds);
		ret = select(sock + 1, &read_fds, NULL, NULL, NULL);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "error watching socket: %s\n",
				strerror(errno));
			exit(1);
		}

		if (FD_ISSET(sock, &read_fds))
			gck_rpc_layer_accept(tls);
	   }

	   gck_rpc_layer_uninitialize();
        } else {
		/* Not reached */
		exit(-1);
	}

	rv = (funcs->C_Finalize) (NULL);
	if (rv != CKR_OK)
		fprintf(stderr, "couldn't finalize module: %s: 0x%08x\n",
			argv[1], (int)rv);

	dlclose(module);

	if (tls) {
		gck_rpc_close_tls(tls);
		free(tls);
		tls = NULL;
	}

	return 0;
}
