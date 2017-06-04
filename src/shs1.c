#include "shs1.h"

#include <sodium.h>

struct SHS1_Client {
  unsigned char pub[crypto_sign_PUBLICKEYBYTES]; // A_p
  unsigned char sec[crypto_sign_SECRETKEYBYTES]; // A_s
  unsigned char server_pub[crypto_sign_PUBLICKEYBYTES]; // B_p
  unsigned char app[crypto_auth_KEYBYTES]; // K
  unsigned char eph_pub[crypto_box_PUBLICKEYBYTES]; // a_p
  unsigned char eph_sec[crypto_box_SECRETKEYBYTES]; // a_s
  unsigned char app_hmac[crypto_auth_BYTES]; // hmac_{K}(a_p)
  unsigned char server_eph_pub[crypto_box_PUBLICKEYBYTES]; //b_p
  unsigned char shared_secret[crypto_scalarmult_BYTES]; // (a_s * b_p)
  unsigned char shared_hash[crypto_hash_sha256_BYTES]; // hash(a_s * b_p)
  unsigned char server_lterm_shared[crypto_scalarmult_BYTES]; // (a_s * B_p)
  unsigned char hello[crypto_sign_BYTES + crypto_sign_PUBLICKEYBYTES]; // H = sign_{A_s}(K | B_p | hash(a_s * b_p)) | A_p
  unsigned char box_secret[crypto_hash_sha256_BYTES]; // hash(K | a_s * b_p | a_s * B_p | A_s * b_p)
};
