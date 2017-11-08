#ifndef SHS1_H
#define SHS1_H

#include <stdbool.h>
#include <stdint.h>
#include <sodium.h>

// These #defines provide naming consistent with the js crypto implementation at https://github.com/AljoschaMeyer/shs1-crypto-js
#define SHS1_NETWORKIDENTIFIERBYTES crypto_auth_KEYBYTES
#define SHS1_MSG1_BYTES SHS1_CLIENT_CHALLENGE_BYTES
#define SHS1_MSG2_BYTES SHS1_SERVER_CHALLENGE_BYTES
#define SHS1_MSG3_BYTES SHS1_CLIENT_AUTH_BYTES
#define SHS1_MSG4_BYTES SHS1_SERVER_ACK_BYTES
#define shs1_create_msg1 shs1_create_client_challenge
#define shs1_verify_msg1 shs1_verify_client_challenge
#define shs1_create_msg2 shs1_create_server_challenge
#define shs1_verify_msg2 shs1_verify_server_challenge
#define shs1_create_msg3 shs1_create_client_auth
#define shs1_verify_msg3 shs1_verify_client_auth
#define shs1_create_msg4 shs1_create_server_ack
#define shs1_verify_msg4 shs1_verify_server_ack

#define SHS1_CLIENT_CHALLENGE_BYTES 64
#define SHS1_SERVER_CHALLENGE_BYTES 64
#define SHS1_CLIENT_AUTH_BYTES 112
#define SHS1_SERVER_ACK_BYTES 80

#define SHS1_CLIENT_SIZE 6 * sizeof(void *) + 2 * crypto_scalarmult_BYTES + crypto_sign_BYTES + crypto_sign_PUBLICKEYBYTES + crypto_hash_sha256_BYTES + crypto_box_PUBLICKEYBYTES

#define SHS1_SERVER_SIZE 5 * sizeof(void *) + crypto_sign_BYTES + crypto_sign_PUBLICKEYBYTES + 2* crypto_hash_sha256_BYTES + crypto_box_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES

// The data resulting from a handshake: Keys and nonces suitable for encrypted
// two-way communication with the peer via sodium secretboxes.
typedef struct {
  uint8_t encryption_key[crypto_secretbox_KEYBYTES];
  uint8_t encryption_nonce[32]; // nonce only occupies the first crypto_secretbox_NONCEBYTES = 24 bytes
  uint8_t decryption_key[crypto_secretbox_KEYBYTES];
  uint8_t decryption_nonce[32]; // nonce only occupies the first crypto_secretbox_NONCEBYTES = 24 bytes
} SHS1_Outcome;

// Carries state during the handshake process.
typedef uint8_t SHS1_Client[SHS1_CLIENT_SIZE];

// Initializes the client state. The pointers must stay valid throughout the whole handshake.
void shs1_init_client(
  SHS1_Client *client,
  const uint8_t app[crypto_auth_KEYBYTES],
  const uint8_t pub[crypto_sign_PUBLICKEYBYTES],
  const uint8_t sec[crypto_sign_SECRETKEYBYTES],
  const uint8_t eph_pub[crypto_box_PUBLICKEYBYTES],
  const uint8_t eph_sec[crypto_box_SECRETKEYBYTES],
  const uint8_t server_pub[crypto_sign_PUBLICKEYBYTES]
);

// Writes the client challenge into `challenge`.
//
// `client` must have been freshly obtained via `shs1_init_client`.
void shs1_create_client_challenge(
  uint8_t challenge[SHS1_CLIENT_CHALLENGE_BYTES],
  SHS1_Client *client
);

// Returns true if the server challenge is valid.
//
// Must have previously called `shs1_create_client_challenge` on `client` to work
// correctly.
bool shs1_verify_server_challenge(
  const uint8_t challenge[SHS1_SERVER_CHALLENGE_BYTES],
  SHS1_Client *client
);

// Writes the client authentication into `auth`. Returns nonzero if any of the
// inner crypto operations fail (e.g. scalarmult).
//
// Must have previously called `shs1_verify_server_challenge` on `client` to
// work correctly.
int shs1_create_client_auth(
  uint8_t auth[SHS1_CLIENT_AUTH_BYTES],
  SHS1_Client *client
);

// Returns true if the server authentication is valid.
//
// Must have previously called `shs1_create_client_auth` on `client` to work
// correctly.
bool shs1_verify_server_ack(
  const uint8_t ack[SHS1_SERVER_ACK_BYTES],
  SHS1_Client *client
);

// Copies the result of the handshake into `outcome`.
//
// Must have previously called `shs1_verify_server_ack` on `client` to work
// correctly.
void shs1_client_outcome(SHS1_Outcome *outcome, SHS1_Client *client);

// Zeros out all sensitive data in the `SHS_Client`.
// This does *not* clear the data pointed to by the `shs1_init_client` arguments.
void shs1_client_clean(SHS1_Client *client);

// Carries state during the handshake process.
typedef uint8_t SHS1_Server[SHS1_SERVER_SIZE];

// Initializes the server state. The pointers must stay valid throughout the whole handshake.
void shs1_init_server(
  SHS1_Server *server,
  const uint8_t app[crypto_auth_KEYBYTES],
  const uint8_t pub[crypto_sign_PUBLICKEYBYTES],
  const uint8_t sec[crypto_sign_SECRETKEYBYTES],
  const uint8_t eph_pub[crypto_box_PUBLICKEYBYTES],
  const uint8_t eph_sec[crypto_box_SECRETKEYBYTES]
);

// Returns true if the client challenge is valid.
//
// `server` must have been freshly obtained via `shs1_init_server`.
bool shs1_verify_client_challenge(
  const uint8_t challenge[SHS1_CLIENT_CHALLENGE_BYTES],
  SHS1_Server *server
);

// Writes the server challenge into `challenge`.
//
// Must have previously called `shs1_verify_client_challenge` on `server` to work
// correctly.
void shs1_create_server_challenge(
  uint8_t challenge[SHS1_SERVER_CHALLENGE_BYTES],
  SHS1_Server *server
);

// Returns true if the client authentication is valid.
//
// Must have previously called `shs1_create_server_challenge` on `server` to
// work correctly.
bool shs1_verify_client_auth(
  const uint8_t auth[SHS1_CLIENT_AUTH_BYTES],
  SHS1_Server *server
);

// Writes the server authentication into `ack`.
//
// Must have previously called `shs1_verify_client_auth` on `server` to work
// correctly.
void shs1_create_server_ack(
  uint8_t ack[SHS1_SERVER_ACK_BYTES],
  SHS1_Server *server
);

// Copies the result of the handshake into `outcome`.
//
// Must have previously called `shs1_create_server_ack` on `server` to work
// correctly.
void shs1_server_outcome(SHS1_Outcome *outcome, SHS1_Server *server);

// Zeros out all sensitive data in the `SHS_Server`.
// This does *not* clear the data pointed to by the `shs1_init_server` arguments.
void shs1_server_clean(SHS1_Server *server);
#endif
