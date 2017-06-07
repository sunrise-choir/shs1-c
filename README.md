# SHS - Secret Handshake Crypto

This repository contains a C implementation of the crypto in [secret-handshake](https://github.com/auditdrivencrypto/secret-handshake). The code only covers the actual crypto part of the protocol (corresponding files in different implementations: [js](https://github.com/auditdrivencrypto/secret-handshake/blob/master/crypto.js), [go](https://github.com/cryptix/secretstream/blob/master/secrethandshake/state.go), [python](https://github.com/pferreir/PySecretHandshake/blob/master/secret_handshake/crypto.py)), there's no I/O happening here.

This code depends on libsodium. Before calling any function of this module, call [`sodium_init()`](https://download.libsodium.org/doc/usage/) first.

See `shs1.h` for the API and `example.c` for a usage example.
