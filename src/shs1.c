#include "shs1.h"

#include <string.h>
#include <sodium.h>

#define HELLO_BYTES crypto_sign_BYTES + crypto_sign_PUBLICKEYBYTES

static unsigned char zero_nonce[crypto_box_NONCEBYTES] = {0};

struct SHS1_Client {
  // inputs
  unsigned const char *app; // K, length: crypto_auth_KEYBYTES
  unsigned const char *pub; // A_p, length: crypto_sign_PUBLICKEYBYTES
  unsigned const char *sec; // A_s, length: crypto_sign_SECRETKEYBYTES
  unsigned const char *eph_pub; // a_p, length: crypto_box_PUBLICKEYBYTES
  unsigned const char *eph_sec; //a_s, length: crypto_box_SECRETKEYBYTES
  unsigned const char *server_pub; // B_p, length: crypto_sign_PUBLICKEYBYTES
  // intermediate results
  unsigned char shared_secret[crypto_scalarmult_BYTES]; // (a_s * b_p)
  unsigned char server_lterm_shared[crypto_scalarmult_BYTES]; // (a_s * B_p)
  unsigned char server_eph_pub[crypto_box_PUBLICKEYBYTES]; //b_p
  unsigned char shared_hash[crypto_hash_sha256_BYTES]; // hash(a_s * b_p)
  unsigned char hello[HELLO_BYTES]; // H = sign_{A_s}(K | B_p | hash(a_s * b_p)) | A_p
  unsigned char box_sec[crypto_hash_sha256_BYTES]; // hash(K | a_s * b_p | a_s * B_p | A_s * b_p)
};

SHS1_Client *shs1_init_client(
  const unsigned char *app,
  const unsigned char *pub,
  const unsigned char *sec,
  const unsigned char *eph_pub,
  const unsigned char *eph_sec,
  const unsigned char *server_pub
)
{
  SHS1_Client *client = malloc(sizeof(SHS1_Client));

  client->app = app;
  client->pub = pub;
  client->sec = sec;
  client->eph_pub = eph_pub;
  client->eph_sec = eph_sec;
  client->server_pub = server_pub;

  return client;
}

// challenge <- hmac_{K}(a_p) | a_p
void shs1_create_client_challenge(
  unsigned char *challenge,
  SHS1_Client *client
)
{
  // hmac_{K}(a_p)
  crypto_auth(challenge, client->eph_pub, crypto_box_PUBLICKEYBYTES, client->app);
  // hmac_{K}(a_p) is also recomputed in `shs1_client_outcome`, it could be stored in the state instead.
  // Recomputing saves memory and seems feasible since the handshake is network-bound rather than cpu-bound.

  memcpy(challenge + crypto_auth_BYTES, client->eph_pub, crypto_box_PUBLICKEYBYTES);
}

bool shs1_verify_server_challenge(
  const unsigned char *challenge,
  SHS1_Client *client
)
{
  if (crypto_auth_verify(
        challenge, challenge + crypto_auth_BYTES,
        crypto_box_PUBLICKEYBYTES, client->app
      ) != 0) {
    return false;
  }

  // b_p
  memcpy(client->server_eph_pub, challenge + crypto_auth_BYTES, crypto_box_PUBLICKEYBYTES);

  // TODO move these to later when the computed values are actually needed
  // (a_s * b_p)
  if (crypto_scalarmult(client->shared_secret, client->eph_sec, client->server_eph_pub) != 0) {
    return false;
  };
  // hash(a_s * b_p)
  crypto_hash_sha256(client->shared_hash, client->shared_secret, crypto_scalarmult_BYTES);

  return true;
}

// auth <- secretbox_{hash(K | a_s * b_p | a_s * B_p)}(H)
int shs1_create_client_auth(
  unsigned char *auth,
  SHS1_Client *client
)
{
  unsigned char curve_server_pub[crypto_scalarmult_curve25519_BYTES];
  if (crypto_sign_ed25519_pk_to_curve25519(curve_server_pub, client->server_pub) != 0) {
    return -1;
  };

  // (a_s * B_p)
  if (crypto_scalarmult(client->server_lterm_shared, client->eph_sec, curve_server_pub) != 0) {
    return -2;
  };

  // K | a_s * b_p | a_s * B_p
  unsigned char tmp[crypto_auth_KEYBYTES + 2 * crypto_scalarmult_BYTES];
  memcpy(tmp, client->app, crypto_auth_KEYBYTES);
  memcpy(tmp + crypto_auth_KEYBYTES, client->shared_secret, crypto_scalarmult_BYTES);
  memcpy(tmp + crypto_auth_KEYBYTES + crypto_scalarmult_BYTES, client->server_lterm_shared, crypto_scalarmult_BYTES);

  // hash(K | a_s * b_p | a_s * B_p)
  unsigned char box_sec[crypto_secretbox_KEYBYTES]; // same as crypto_hash_sha256_BYTES
  crypto_hash_sha256(box_sec, tmp, sizeof(tmp));

  // K | B_p | hash(a_s * b_p)
  unsigned char tmp2[crypto_auth_KEYBYTES + crypto_sign_PUBLICKEYBYTES + crypto_hash_sha256_BYTES];
  memcpy(tmp2, client->app, crypto_auth_KEYBYTES);
  memcpy(tmp2 + crypto_auth_KEYBYTES, client->server_pub, crypto_sign_PUBLICKEYBYTES);
  memcpy(tmp2 + crypto_auth_KEYBYTES + crypto_sign_PUBLICKEYBYTES, client->shared_hash, crypto_hash_sha256_BYTES);

  // sign_{A_s}(K | B_p | hash(a_s * b_p))
  unsigned char sig[crypto_sign_BYTES];
  crypto_sign_detached(
    sig, NULL, tmp2,
    crypto_auth_KEYBYTES + crypto_sign_PUBLICKEYBYTES + crypto_hash_sha256_BYTES,
    client->sec
  );

  // H = sign_{A_s}(K | B_p | hash(a_s * b_p)) | A_p
  memcpy(client->hello, sig, sizeof(sig));
  memcpy(client->hello + crypto_sign_BYTES, client->pub, crypto_sign_PUBLICKEYBYTES);

  // secretbox_{hash(K | a_s * b_p | a_s * B_p)}(H)
  crypto_secretbox_easy(
    auth, client->hello, HELLO_BYTES,
    zero_nonce, box_sec
  );

  return 0;
}

bool shs1_verify_server_acc(
  const unsigned char *acc,
  SHS1_Client *client
)
{
  unsigned char curve_sec[crypto_scalarmult_curve25519_BYTES];
  if (crypto_sign_ed25519_sk_to_curve25519(curve_sec, client->sec) != 0) {
    return false;
  };

  // (A_s * b_p)
  unsigned char client_lterm_shared[crypto_scalarmult_BYTES];
  if (crypto_scalarmult(client_lterm_shared, curve_sec, client->server_eph_pub) != 0) {
    return false;
  };

  // K | a_s * b_p | a_s * B_p | A_s * b_p
  unsigned char tmp[crypto_auth_KEYBYTES + 3 * crypto_scalarmult_BYTES];
  memcpy(tmp, client->app, crypto_auth_KEYBYTES);
  memcpy(tmp + crypto_auth_KEYBYTES, client->shared_secret, crypto_scalarmult_BYTES);
  memcpy(tmp + crypto_auth_KEYBYTES + crypto_scalarmult_BYTES, client->server_lterm_shared, crypto_scalarmult_BYTES);
  if (crypto_scalarmult(tmp + crypto_auth_KEYBYTES + 2 * crypto_scalarmult_BYTES, curve_sec, client->server_eph_pub) != 0) {
    return false;
  };

  // hash(K | a_s * b_p | a_s * B_p | A_s * b_p)
  crypto_hash_sha256(client->box_sec, tmp, crypto_auth_KEYBYTES + 3 * crypto_scalarmult_BYTES);

  unsigned char sig[crypto_sign_BYTES];
  if (crypto_secretbox_open_easy(sig, acc, SHS1_SERVER_ACC_BYTES, zero_nonce, client->box_sec) != 0) {
    return false;
  }

  // K | H | hash(a_s * b_p)
  unsigned char expected[crypto_auth_KEYBYTES + HELLO_BYTES + crypto_hash_sha256_BYTES];
  memcpy(expected, client->app, crypto_auth_KEYBYTES);
  memcpy(expected + crypto_auth_KEYBYTES, client->hello, HELLO_BYTES);
  memcpy(expected + crypto_auth_KEYBYTES + HELLO_BYTES, client->shared_hash, crypto_hash_sha256_BYTES);

  return crypto_sign_verify_detached(sig, expected, sizeof(expected), client->server_pub) == 0;
}

void shs1_client_outcome(
  SHS1_Outcome *outcome,
  const SHS1_Client *client
)
{
  // hash(hash(hash(K | a_s * b_p | a_s * B_p | A_s * b_p)) | B_p)
  unsigned char tmp[crypto_hash_sha256_BYTES + crypto_sign_PUBLICKEYBYTES];
  crypto_hash_sha256(tmp, client->box_sec, crypto_hash_sha256_BYTES);
  memcpy(tmp + crypto_hash_sha256_BYTES, client->server_pub, crypto_sign_PUBLICKEYBYTES);
  crypto_hash_sha256(outcome->encryption_key, tmp, crypto_hash_sha256_BYTES + crypto_sign_PUBLICKEYBYTES);


  // hmac_{K}(b_p)
  crypto_auth(outcome->encryption_nonce, client->server_eph_pub, crypto_box_PUBLICKEYBYTES, client->app);

  // hash(hash(hash(K | a_s * b_p | a_s * B_p | A_s * b_p)) | A_p)
  memcpy(tmp + crypto_hash_sha256_BYTES, client->pub, crypto_sign_PUBLICKEYBYTES);
  crypto_hash_sha256(outcome->decryption_key, tmp, crypto_hash_sha256_BYTES + crypto_sign_PUBLICKEYBYTES);

  // hmac_{K}(a_p)
  crypto_auth(outcome->decryption_nonce, client->eph_pub, crypto_box_PUBLICKEYBYTES, client->app);
}

struct SHS1_Server {
  // begin K | b_s * a_p | B_s * a_p
  unsigned char app[crypto_auth_KEYBYTES]; // K
  unsigned char shared_secret[crypto_scalarmult_BYTES]; // (b_s * a_p)
  // TODO remove these and do some copying in verify_client_auth?
  unsigned char server_lterm_shared[crypto_scalarmult_BYTES]; // (B_s * a_p) only here to save copying later
  unsigned char client_lterm_shared[crypto_scalarmult_BYTES]; // (b_s * A_p) only here to save copying later
  // end K | b_s * a_p | B_s * a_p | b_s * A_p
  // begin K | B_p | hash(a_s * b_p)
  unsigned char app_copy[crypto_auth_KEYBYTES]; // same as app, put here to save some copying later TODO suggest to change concatenation order in shs2 so this is not needed
  unsigned char pub[crypto_sign_PUBLICKEYBYTES]; // B_p
  unsigned char shared_hash[crypto_hash_sha256_BYTES]; // hash(b_s * a_p)
  // end K | B_p | hash(a_s * b_p)
  unsigned char sec[crypto_sign_SECRETKEYBYTES]; // B_s
  unsigned char eph_pub[crypto_box_PUBLICKEYBYTES]; // b_p
  unsigned char eph_sec[crypto_box_SECRETKEYBYTES]; // b_s
  unsigned char app_hmac[crypto_auth_BYTES]; // hmac_{K}(b_p)
  unsigned char client_eph_pub[crypto_box_PUBLICKEYBYTES]; //a_p
  unsigned char client_hello[HELLO_BYTES]; // H = sign_{A_s}(K | B_p | hash(a_s * b_p)) | A_p
  unsigned char client_pub[crypto_sign_PUBLICKEYBYTES]; // A_p
  unsigned char box_sec[crypto_hash_sha256_BYTES]; // hash(K | b_s * a_p | B_s * a_p | b_s * A_p) , also temporarily stores hash(K | b_s * a_p | B_s * a_p)
};

SHS1_Server *shs1_init_server(
  const unsigned char *app,
  const unsigned char *pub,
  const unsigned char *sec,
  const unsigned char *eph_pub,
  const unsigned char *eph_sec
)
{
  SHS1_Server *server = malloc(sizeof(SHS1_Server));

  memcpy(server->pub, pub, crypto_sign_PUBLICKEYBYTES);
  memcpy(server->sec, sec, crypto_sign_SECRETKEYBYTES);
  memcpy(server->app, app, crypto_auth_KEYBYTES);
  memcpy(server->app_copy, app, crypto_auth_KEYBYTES);
  memcpy(server->eph_pub, eph_pub, crypto_box_PUBLICKEYBYTES);
  memcpy(server->eph_sec, eph_sec, crypto_box_SECRETKEYBYTES);

  // hmac_{K}(b_p)
  crypto_auth(server->app_hmac, server->eph_pub, crypto_box_PUBLICKEYBYTES, server->app);

  return server;
}

bool shs1_verify_client_challenge(
  const unsigned char *challenge,
  SHS1_Server *server
)
{
  if (crypto_auth_verify(
        challenge, challenge + crypto_auth_BYTES,
        crypto_box_PUBLICKEYBYTES, server->app
      ) != 0) {
    return false;
  }

  // a_p
  memcpy(server->client_eph_pub, challenge + crypto_auth_BYTES, crypto_box_PUBLICKEYBYTES);
  // (b_s * a_p)
  if (crypto_scalarmult(server->shared_secret, server->eph_sec, server->client_eph_pub) != 0) {
    return false;
  };
  // hash(b_s * a_p)
  crypto_hash_sha256(server->shared_hash, server->shared_secret, crypto_scalarmult_BYTES);

  return true;
}

void shs1_create_server_challenge(
  unsigned char *challenge,
  SHS1_Server *server
)
{
  memcpy(challenge, server->app_hmac, crypto_auth_BYTES);
  memcpy(challenge + crypto_auth_BYTES, server->eph_pub, crypto_box_PUBLICKEYBYTES);
}

bool shs1_verify_client_auth(
  const unsigned char *auth,
  SHS1_Server *server
)
{
  unsigned char curve_sec[crypto_scalarmult_curve25519_BYTES];
  if (crypto_sign_ed25519_sk_to_curve25519(curve_sec, server->sec) != 0) {
    return false;
  };

  // (B_s * a_p)
  if (crypto_scalarmult(server->server_lterm_shared, curve_sec, server->client_eph_pub) != 0) {
    return false;
  };

  // hash(K | b_s * a_p | B_s * a_p)
  // write to server->box_sec is only temporary, this is overwritten later
  crypto_hash_sha256(server->box_sec, server->app, crypto_auth_KEYBYTES + 2 * crypto_scalarmult_BYTES);

  // H = sign_{A_s}(K | B_p | hash(a_s * b_p)) | A_p
  if (crypto_secretbox_open_easy(server->client_hello, auth, SHS1_CLIENT_AUTH_BYTES, zero_nonce, server->box_sec) != 0) {
    return false;
  }

  memcpy(server->client_pub, server->client_hello + crypto_sign_BYTES, crypto_sign_PUBLICKEYBYTES);

  // expected: K | B_p | hash(a_s * b_p)
  if (crypto_sign_verify_detached(server->client_hello, server->app_copy, crypto_auth_KEYBYTES + crypto_sign_PUBLICKEYBYTES + crypto_hash_sha256_BYTES, server->client_pub) != 0) {
    return false;
  }

  unsigned char curve_client_pub[crypto_scalarmult_curve25519_BYTES];
  if (crypto_sign_ed25519_pk_to_curve25519(curve_client_pub, server->client_pub) != 0) {
    return false;
  };

  // b_s * A_p
  if (crypto_scalarmult(server->client_lterm_shared, server->eph_sec, curve_client_pub) != 0) {
    return false;
  }

  // hash(K | b_s * a_p | B_s * a_p | b_s * A_p)
  crypto_hash_sha256(server->box_sec, server->app, crypto_auth_KEYBYTES + 3 * crypto_scalarmult_BYTES);

  return true;
}

void shs1_create_server_acc(
  unsigned char *acc,
  SHS1_Server *server
)
{
  // K | H | hash(b_s * a_p)
  unsigned char to_sign[crypto_auth_KEYBYTES + HELLO_BYTES + crypto_hash_sha256_BYTES];
  memcpy(to_sign, server->app, crypto_auth_KEYBYTES);
  memcpy(to_sign + crypto_auth_KEYBYTES, server->client_hello, HELLO_BYTES);
  memcpy(to_sign + crypto_auth_KEYBYTES + HELLO_BYTES, server->shared_hash, crypto_hash_sha256_BYTES);

  // sign_{B_s}(K | H | hash(b_s * a_p))
  unsigned char sig[crypto_sign_BYTES];
  crypto_sign_detached(sig, NULL, to_sign, sizeof(to_sign), server->sec);

  // box_{hash(K | b_s * a_p | B_s * a_p | b_s * A_p)}(sign_{B_s}(K | H | hash(b_s * a_p)))
  crypto_secretbox_easy(acc, sig, crypto_sign_BYTES, zero_nonce, server->box_sec);
}

void shs1_server_outcome(
  SHS1_Outcome *outcome,
  const SHS1_Server *server
)
{
  // hash(hash(hash(K | a_s * b_p | a_s * B_p | A_s * b_p)) | B_p)
  unsigned char tmp[crypto_hash_sha256_BYTES + crypto_sign_PUBLICKEYBYTES];
  crypto_hash_sha256(tmp, server->box_sec, crypto_hash_sha256_BYTES);
  memcpy(tmp + crypto_hash_sha256_BYTES, server->client_pub, crypto_sign_PUBLICKEYBYTES);
  crypto_hash_sha256(outcome->encryption_key, tmp, crypto_hash_sha256_BYTES + crypto_sign_PUBLICKEYBYTES);

  // hmac_{K}(a_p)
  crypto_auth(outcome->encryption_nonce, server->client_eph_pub, crypto_box_PUBLICKEYBYTES, server->app);

  // hash(hash(hash(K | a_s * b_p | a_s * B_p | A_s * b_p)) | A_p)
  memcpy(tmp + crypto_hash_sha256_BYTES, server->pub, crypto_sign_PUBLICKEYBYTES);
  crypto_hash_sha256(outcome->decryption_key, tmp, crypto_hash_sha256_BYTES + crypto_sign_PUBLICKEYBYTES);

  memcpy(outcome->decryption_nonce, server->app_hmac, crypto_box_NONCEBYTES);
}

// TODO change API to expose sizeof Client and Server, make init functions take a pointer to them, and remove free/zero

// TODO put API into the readme

// TODO add to readme: libsodium dependency and sodium_init()

// TODO reuse storage in the Server struct: It's not necessary to keep all data arund for the whole handshake

// TODO add tests for non-successful handshakes

// TODO check whether some keys are *only* used in curvified form
