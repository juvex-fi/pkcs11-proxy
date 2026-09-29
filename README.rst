
PKCS11 Proxy
============

This fork has the following additional features:

- support for running in "inetd mode", useful for calling directly from stunnel
- seccomp syscall filtering, on by default for Linux builds (see USAGE)
- privilege dropping with ``--drop-privs <user>``
- getaddrinfo support for IPv6, fallback and DNS resolution
- TLS-PSK support to optionally encrypt communication

Plus a number of important bug fixes. This version passes the SoftHSM test
suite.

An ubuntu PPA that tracks this version is ppa:leifj

PKCS#11 v3.2
============

Built against the OASIS v3.2 headers by default (``-DPKCS11_V32=ON``). All
104 functions are proxied, ``C_GetInterface``/``C_GetInterfaceList`` are
exported, and the post-quantum mechanisms (ML-KEM, ML-DSA, SLH-DSA, HSS, XMSS)
work, including the optional signing context. AES-GCM, AES-CCM and
ChaCha20-Poly1305 are supported both as single-part mechanisms and in the
message-based API; their parameter structures are serialized field by field,
so no client pointer reaches the module in the daemon.

Tests
=====

::

  cmake -B build -DPKCS11_TESTS=ON && cmake --build build && (cd build && ctest)

This runs a fuzzer for the daemon's parameter parser and an end-to-end test of
the message-based, single-part AEAD and async functions against a mock module.
To also test ML-KEM/ML-DSA through the proxy, pass a SoftHSM built with them::

  -DPKCS11_TEST_SOFTHSM_MODULE=/path/to/libsofthsm2.so \
  -DPKCS11_TEST_SOFTHSM_UTIL=/path/to/softhsm2-util

Credits
=======

This tree is `juvex-fi/pkcs11-proxy <https://github.com/juvex-fi/pkcs11-proxy>`_,
which descends from
`SUNET/pkcs11-proxy <https://github.com/SUNET/pkcs11-proxy>`_ and
`Absolight/pkcs11-proxy <https://github.com/Absolight/pkcs11-proxy>`_. See
also THANKS.

- PKCS#11 v3.2 support: Jukka Kangas (Juvex)

Patches from other forks of SUNET/pkcs11-proxy:

- Nate Anderson (`n8raid/pkcs11-proxy <https://github.com/n8raid/pkcs11-proxy>`_):
  fix for an infinite loop when a TLS write fails
  (`e1980b0 <https://github.com/n8raid/pkcs11-proxy/commit/e1980b0fe4115a70907a06690bf26d3e394a0654>`_).
  Applied as is.

- `minhow88/pkcs11-proxy <https://github.com/minhow88/pkcs11-proxy>`_:
  the fixes below were reviewed and adapted rather than merged as is.
  Plain tcp:// support was kept, and open() is not limited to read-only
  under seccomp.

  - `b265722 <https://github.com/minhow88/pkcs11-proxy/commit/b2657228b91e095cae70b67fa94c1487079f3c03>`_:
    security hardening. Adapted from it: fix for an accept() mutex
    deadlock, per-connection TLS state, inetd partial read/write handling,
    egg-buffer overflow checks, response size limit, /dev/urandom app id,
    sun_path termination, signal-safe run flag, and seccomp on by default
    with ``--drop-privs``.
  - `cede215 <https://github.com/minhow88/pkcs11-proxy/commit/cede215614da3ff653cd788524deb372c3062585>`_
    and `6d90343 <https://github.com/minhow88/pkcs11-proxy/commit/6d90343a182884f3be6c4308f00ae769e4c52524>`_:
    seccomp syscalls for aarch64 and modern kernels, draining the
    connection pool in C_Finalize, and more mechanisms (the subset whose
    parameters can safely be copied verbatim).
  - `e35bc93 <https://github.com/minhow88/pkcs11-proxy/commit/e35bc9364fcad6f0b3036c41222535db1396011f>`_:
    seccomp syscalls for OpenSSL 3.x and ``--no-seccomp``.
  - `8634bf6 <https://github.com/minhow88/pkcs11-proxy/commit/8634bf65854bbdaef9428a1f5a77f800864cc2e7>`_:
    TLS-PSK client sends its keyfile's first identity when none is
    configured.
