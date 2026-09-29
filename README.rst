
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
104 functions are proxied. ``C_GetInterface``/``C_GetInterfaceList`` are
exported and offer the 3.2, 3.1, 3.0 and 2.40 interfaces, each matched by its
exact version.

The daemon is the trust boundary: it applies the mechanism allow-list and
parameter checks itself, and never hands the module a pointer received from a
client. Mechanism parameters and attribute templates that contain pointers are
serialized field by field and rebuilt in the daemon's memory.

Supported mechanisms (about 350 of the 470 names in the header):

- everything without a parameter, digests, HMACs and key generation/derivation
  (SHA-2, SHA-3, BLAKE2b, ...), RSA/ECDSA/DSA with hashes, EdDSA
- post-quantum: ML-KEM, ML-DSA, SLH-DSA, HSS and XMSS, including the optional
  signing context
- structures with pointers: AES-GCM/CCM and ChaCha20/Salsa20-Poly1305 (also
  in the message-based API), RSA-OAEP, RSA-AES key wrap, ECDH derive and
  ECDH-AES wrap, HKDF, EdDSA context, ChaCha20/Salsa20, key derivation from
  data, ``*_ENCRYPT_DATA``
- flat parameters: RSA-PSS, IVs, AES-CTR, key wrap, general-length MACs, ...

Not supported (refused, and left out of ``C_GetMechanismList``): the
protocol-specific mechanisms that return values through their parameter or
carry arrays of structures (TLS/SSL/WTLS/IKE PRF and key derivation, X3DH,
X2Ratchet, SP800-108 KDFs, PKCS5-PBKDF2, PBE), plus obsolete ones (Skipjack,
Baton, Juniper, KEA, GOST, SecurID/HOTP/ACTI, RC5 CBC, ECMQV, X9.42 DH, AES-XTS
and the SHA512/t family).

Tests
=====

::

  cmake -B build -DPKCS11_TESTS=ON && cmake --build build && (cd build && ctest)

This runs a fuzzer for the daemon's parsers, tests that feed the daemon hostile
input, and end-to-end tests of the message-based and single-part AEAD, async,
mechanism-parameter and interface functions against a mock module. To also
test against a real module (ML-KEM/ML-DSA, attribute templates, OAEP, PSS,
GCM, ECDSA, ECDH, EdDSA), pass a SoftHSM built with ML-DSA and ML-KEM::

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
