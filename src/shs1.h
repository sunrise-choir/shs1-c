#ifndef SHS1_H
#define SHS1_H

#include <stdbool.h>
#include <sodium.h>

#define SHS1_CLIENT_CHALLENGE_BYTES 64
#define SHS1_SERVER_CHALLENGE_BYTES 64
#define SHS1_CLIENT_AUTH_BYTES 64
#define SHS1_SERVER_AUTH_BYTES 64

// The data resulting from a handshake: Keys and nonces suitable for encrypted
// two-way communication with the peer via sodium secretboxes.
typedef struct {
	unsigned char encryption_key[crypto_secretbox_KEYBYTES];
  unsigned char encryption_nonce[crypto_secretbox_NONCEBYTES];
  unsigned char decryption_key[crypto_secretbox_KEYBYTES];
  unsigned char decryption_nonce[crypto_secretbox_NONCEBYTES];
} SHS1_Outcome;

// Carries state during the handshake process.
typedef struct SHS1_Client SHS1_Client;

SHS1_Client *shs1_init_client(
  const unsigned char *pub, // length crypto_sign_PUBLICKEYBYTES
  const unsigned char *sec, // length crypto_sign_SECRETKEYBYTES
  const unsigned char *server_pub, // length crypto_sign_PUBLICKEYBYTES
  const unsigned char *app, // length crypto_auth_KEYBYTES
  const unsigned char *eph_pub, // length crypto_box_PUBLICKEYBYTES
  const unsigned char *eph_sec // length crypto_box_SECRETKEYBYTES
);

// Writes the client challenge into `challenge`.
//
// `client` must have been freshly obtained via `shs1_init_client`.
void shs1_create_client_challenge(
  unsigned char *challenge, // length SHS1_CLIENT_CHALLENGE_BYTES
  SHS1_Client *client
);

// Returns true if the server challenge is valid.
//
// Must have previously called `shs1_create_client_challenge` on `client` to work
// correctly.
bool shs1_verify_server_challenge(
  const unsigned char *challenge, // length SHS1_SERVER_CHALLENGE_BYTES
  SHS1_Client *client
);

// Writes the client authentication into `auth`.
//
// Must have previously called `shs1_verify_server_challenge` on `client` to
// work correctly.
void shs1_create_client_auth(
  unsigned char *auth, // length SHS1_CLIENT_AUTH_BYTES
  SHS1_Client *client
);

// Returns true if the server authentication is valid.
//
// Must have previously called `shs1_create_client_auth` on `client` to work
// correctly.
bool shs1_verify_server_auth(
  const unsigned char *auth, //length SHS1_SERVER_AUTH_BYTES
  SHS1_Client *client
);

// Copies the result of the handshake into `outcome`, then zeroes all
// crypto-related data in `client` and deallocates it.
//
// Must have previously called `shs1_verify_server_auth` on `client` to work
// correctly.
void shs1_client_finish(SHS1_Outcome *outcome, SHS1_Client *client);

// Carries state during the handshake process.
typedef struct SHS1_Server SHS1_Server;

SHS1_Server *shs1_init_server(
  const unsigned char *pub, // length crypto_sign_PUBLICKEYBYTES
  const unsigned char *sec, // length crypto_sign_SECRETKEYBYTES
  const unsigned char *app, // length crypto_auth_KEYBYTES
  const unsigned char *eph_pub, // length crypto_box_PUBLICKEYBYTES
  const unsigned char *eph_sec // length crypto_box_SECRETKEYBYTES
);

// Returns true if the client challenge is valid.
//
// `server` must have been freshly obtained via `shs1_init_server`.
bool shs1_verify_client_challenge(
  const unsigned char *challenge, // length SHS1_CLIENT_CHALLENGE_BYTES
  SHS1_Server *server
);

// Writes the server challenge into `challenge`.
//
// Must have previously called `shs1_verify_client_challenge` on `server` to work
// correctly.
void shs1_create_server_challenge(
  unsigned char *challenge, // length SHS1_SERVER_CHALLENGE_BYTES
  SHS1_Server *server
);

// Returns true if the client authentication is valid.
//
// Must have previously called `shs1_create_server_challenge` on `server` to
// work correctly.
bool shs1_verify_client_auth(
  const unsigned char *auth, //length SHS1_CLIENT_AUTH_BYTES
  SHS1_Server *server
);

// Writes the server authentication into `auth`.
//
// Must have previously called `shs1_verify_client_auth` on `server` to work
// correctly.
void shs1_create_server_auth(
  unsigned char *auth, // length SHS1_SERVER_AUTH_BYTES
  SHS1_Server *server
);

// Copies the result of the handshake into `outcome`, then zeroes all
// crypto-related data in `server` and deallocates it.
//
// Must have previously called `shs1_create_server_auth` on `server` to work
// correctly.
void shs1_server_finish(SHS1_Outcome *outcome, SHS1_Server *server);
#endif
