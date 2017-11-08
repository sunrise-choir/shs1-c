# SHS - Secret Handshake Crypto

This repository contains a C implementation of the crypto in [secret-handshake](https://github.com/auditdrivencrypto/secret-handshake). The code only covers the [actual crypto](https://github.com/AljoschaMeyer/shs1-crypto-js) part of the protocol, there's no I/O happening here.

This code depends on libsodium. Before calling any function of this module, call [`sodium_init()`](https://download.libsodium.org/doc/usage/) first.

See `shs1.h` for the API and `example.c` for a usage example.

To run the [integration tests](https://github.com/AljoschaMeyer/shs1-testsuite), use `make testClient` and `make testServer` to generate the executables to test.
