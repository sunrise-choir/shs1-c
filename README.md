# SHS - Secret Handshake Crypto

This repository contains a C implementation of the crypto in [secret-handshake](https://github.com/auditdrivencrypto/secret-handshake). The code only covers the actual crypto part of the protocol (corresponding files in different implementations: [js](https://github.com/auditdrivencrypto/secret-handshake/blob/master/crypto.js), [go](https://github.com/cryptix/secretstream/blob/master/secrethandshake/state.go), [python](https://github.com/pferreir/pyssb/blob/master/ssb/shs/crypto.py)), there's no I/O happening here.

This aims to be a clear reference implementation, indicating exactly how the libsodium primitives are used. Due to being written in C, it also happens to be quite efficient and can serve as the basis for bindings.

```c
#ifndef SHS_H
#define SHS_H

#include <stdbool.h>

#define SHS_CLIENT_CHALLENGE_BYTES 64
#define SHS_SERVER_CHALLENGE_BYTES 64
#define SHS_CLIENT_AUTH_BYTES 64
#define SHS_SERVER_AUTH_BYTES 64

typedef struct SHS_Client SHS_Client;

void shs_init_client(
  SHS_Client *client,
  const unsigned char *pub_key, // length crypto_sign_PUBLICKEYBYTES
  const unsigned char *sec_key, // length crypto_sign_SECRETKEYBYTES
  const unsigned char *server_pub, // length crypto_sign_PUBLICKEYBYTES
  const unsigned char *app_key, // length crypto_auth_KEYBYTES
  const unsigned char *eph_pub, // length crypto_box_PUBLICKEYBYTES
  const unsigned char *eph_sec // length crypto_box_SECRETKEYBYTES
);

// Writes the client challenge into `challenge`.
//
// Must have previously called `shs_init_client` on `client` to work correctly.
void shs_create_client_challenge(
  unsigned char *challenge, // length SHS_CLIENT_CHALLENGE_BYTES
  SHS_Client *client
);

// Returns true if the server challenge is valid.
//
// Must have previously called `shs_create_client_challenge` on `client` to work
// correctly.
bool shs_verify_server_challenge(
  const unsigned char *challenge, // length SHS_SERVER_CHALLENGE_BYTES
  SHS_Client *client
);

// Returns true if the server challenge is valid.
//
// Must have previously called `shs_create_client_challenge` on `client` to work
// correctly.
//
// This is only provided for compatibility with an error in the original
// implementation of shs. Use `shs_verify_server_challenge` instead if possible.
bool shs_legacy_verify_server_challenge(
  const unsigned char *challenge, // length SHS_SERVER_CHALLENGE_BYTES
  SHS_Client *client
);

// Writes the client authentication into `auth`.
//
// Must have previously called `shs_verify_server_challenge` or
// `shs_legacy_verify_server_challenge` on `client` to work correctly.
void shs_create_client_auth(
  unsigned char *auth, // length SHS_CLIENT_AUTH_BYTES
  SHS_Client *client
);

// Returns true if the server authentication is valid.
//
// Must have previously called `shs_create_client_auth` on `client` to work
// correctly.
bool shs_verify_server_auth(
  const unsigned char *auth, //length SHS_SERVER_AUTH_BYTES
  SHS_Client *client
)

// Copies the result of the handshake into `outcome`, then zeroes all
// crypto-related data in `client`.
//
// Must have previously called `shs_verify_server_auth` on `client` to work
// correctly.
void shs_client_finish(Outcome *outcome, SHS_Client *client);

typedef struct SHS_Server SHS_Server;

void shs_init_server(
  SHS_Server *server,
  const unsigned char *pub_key, // length crypto_sign_PUBLICKEYBYTES
  const unsigned char *sec_key, // length crypto_sign_SECRETKEYBYTES
  const unsigned char *app_key, // length crypto_auth_KEYBYTES
  const unsigned char *eph_pub, // length crypto_box_PUBLICKEYBYTES
  const unsigned char *eph_sec // length crypto_box_SECRETKEYBYTES
);

// Returns true if the client challenge is valid.
//
// Must have previously called `shs_init_server` on `server` to work
// correctly.
bool shs_verify_client_challenge(
  const unsigned char *challenge, // length SHS_CLIENT_CHALLENGE_BYTES
  SHS_Server *server
);

// Writes the server challenge into `challenge`.
//
// Must have previously called `shs_verify_client_challenge` on `server` to work
// correctly.
void shs_create_server_challenge(
  unsigned char *challenge, // length SHS_SERVER_CHALLENGE_BYTES
  SHS_Server *server
);

// Writes the server challenge into `challenge`.
//
// Must have previously called `shs_verify_client_challenge` on `server` to work
// correctly.
//
// This is only provided for compatibility with an error in the original
// implementation of shs. Use `shs_create_server_challenge` instead if possible.
void shs_legacy_create_server_challenge(
  unsigned char *challenge, // length SHS_SERVER_CHALLENGE_BYTES
  SHS_Server *server
);

// Returns true if the client authentication is valid.
//
// Must have previously called `shs_create_server_challenge` or
// `shs_legacy_create_server_challenge` on `server` to work correctly.
bool shs_verify_client_auth(
  const unsigned char *auth, //length SHS_CLIENT_AUTH_BYTES
  SHS_Server *server
)

// Writes the server authentication into `auth`.
//
// Must have previously called `shs_verify_client_auth` on `server` to work
// correctly.
void shs_create_server_auth(
  unsigned char *auth, // length SHS_SERVER_AUTH_BYTES
  SHS_Server *server
);

// Copies the result of the handshake into `outcome`, then zeroes all
// crypto-related data in `server`.
//
// Must have previously called `shs_create_server_auth` on `server` to work
// correctly.
void shs_server_finish(Outcome *outcome, SHS_Server *server);
#endif
```
