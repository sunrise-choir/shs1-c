#ifndef SHS1_H
#define SHS1_H

#include <stdbool.h>
#include <sodium.h>

#define SHS1_CLIENT_CHALLENGE_BYTES 64
#define SHS1_SERVER_CHALLENGE_BYTES 64
#define SHS1_CLIENT_AUTH_BYTES 112
#define SHS1_SERVER_ACC_BYTES 80

#define SHS1_CLIENT_SIZE 6 * sizeof(void *) + 2 * crypto_scalarmult_BYTES + crypto_sign_BYTES + crypto_sign_PUBLICKEYBYTES + crypto_hash_sha256_BYTES + crypto_box_PUBLICKEYBYTES

#define SHS1_Server_SIZE 5 * sizeof(void *) + crypto_sign_BYTES + crypto_sign_PUBLICKEYBYTES + 2* crypto_hash_sha256_BYTES + crypto_box_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES

// The data resulting from a handshake: Keys and nonces suitable for encrypted
// two-way communication with the peer via sodium secretboxes.
typedef struct {
  unsigned char encryption_key[crypto_secretbox_KEYBYTES];
  unsigned char encryption_nonce[32]; // nonce only occupies the first crypto_secretbox_NONCEBYTES = 24 bytes
  unsigned char decryption_key[crypto_secretbox_KEYBYTES];
  unsigned char decryption_nonce[32]; // nonce only occupies the first crypto_secretbox_NONCEBYTES = 24 bytes
} SHS1_Outcome;

// Carries state during the handshake process.
typedef unsigned char SHS1_Client[SHS1_CLIENT_SIZE];

// Initializes the client state. The pointers must stay valid throughout the whole handshake.
void shs1_init_client(
  SHS1_Client *client,
  const unsigned char *app, // length crypto_auth_KEYBYTES
  const unsigned char *pub, // length crypto_sign_PUBLICKEYBYTES
  const unsigned char *sec, // length crypto_sign_SECRETKEYBYTES
  const unsigned char *eph_pub, // length crypto_box_PUBLICKEYBYTES
  const unsigned char *eph_sec, // length crypto_box_SECRETKEYBYTES
  const unsigned char *server_pub // length crypto_sign_PUBLICKEYBYTES
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

// Writes the client authentication into `auth`. Returns nonzero if any of the
// inner crypto operations fail (e.g. scalarmult).
//
// Must have previously called `shs1_verify_server_challenge` on `client` to
// work correctly.
int shs1_create_client_auth(
  unsigned char *auth, // length SHS1_CLIENT_AUTH_BYTES
  SHS1_Client *client
);

// Returns true if the server authentication is valid.
//
// Must have previously called `shs1_create_client_auth` on `client` to work
// correctly.
bool shs1_verify_server_acc(
  const unsigned char *acc, //length SHS1_SERVER_ACC_BYTES
  SHS1_Client *client
);

// Copies the result of the handshake into `outcome`.
//
// Must have previously called `shs1_verify_server_acc` on `client` to work
// correctly.
void shs1_client_outcome(SHS1_Outcome *outcome, SHS1_Client *client);

// Carries state during the handshake process.
typedef unsigned char SHS1_Server[SHS1_Server_SIZE];

// Initializes the server state. The pointers must stay valid throughout the whole handshake.
void shs1_init_server(
  SHS1_Server *server,
  const unsigned char *app, // length crypto_auth_KEYBYTES
  const unsigned char *pub, // length crypto_sign_PUBLICKEYBYTES
  const unsigned char *sec, // length crypto_sign_SECRETKEYBYTES
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

// Writes the server authentication into `acc`.
//
// Must have previously called `shs1_verify_client_auth` on `server` to work
// correctly.
void shs1_create_server_acc(
  unsigned char *acc, // length SHS1_SERVER_ACC_BYTES
  SHS1_Server *server
);

// Copies the result of the handshake into `outcome`.
//
// Must have previously called `shs1_create_server_acc` on `server` to work
// correctly.
void shs1_server_outcome(SHS1_Outcome *outcome, SHS1_Server *server);
#endif
