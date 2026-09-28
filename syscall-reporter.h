/*
 * syscall reporting example for seccomp
 *
 * Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Authors:
 *  Kees Cook <keescook@chromium.org>
 *  Will Drewry <wad@chromium.org>
 *
 * The code may be used by anyone for any purpose, and can serve as a
 * starting point for developing applications using mode 2 seccomp.
 */
#ifndef _BPF_REPORTER_H_
#define _BPF_REPORTER_H_

#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifndef SYS_SECCOMP
# define SYS_SECCOMP 1
#endif

/* The reporter goes with filters that TRAP instead of KILL, so make sure
 * it stands out in the build as it should not be used in the final program.
 */
#ifdef DEBUG_SECCOMP
#warning "You've included the syscall reporter. Do not use in production!"
#endif

extern int install_syscall_reporter(void);

#endif
