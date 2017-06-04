#include "shs1.h"

#include <string.h>
#include <sodium.h>

// TODO remove this
void print_hex(void *mem, int size) {
  int i;
  unsigned char *p = (unsigned char *)mem;
  for (i=0;i<size;i++) {
    printf("0x%02x ", p[i]);
  }
  printf("\n");
}

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

SHS1_Client *shs1_init_client(
  const unsigned char *pub, // length crypto_sign_PUBLICKEYBYTES
  const unsigned char *sec, // length crypto_sign_SECRETKEYBYTES
  const unsigned char *server_pub, // length crypto_sign_PUBLICKEYBYTES
  const unsigned char *app, // length crypto_auth_KEYBYTES
  const unsigned char *eph_pub, // length crypto_box_PUBLICKEYBYTES
  const unsigned char *eph_sec // length crypto_box_SECRETKEYBYTES
)
{
  SHS1_Client *client = malloc(sizeof(SHS1_Client));

  memcpy(client->pub, pub, crypto_sign_PUBLICKEYBYTES);
  memcpy(client->sec, sec, crypto_sign_SECRETKEYBYTES);
  memcpy(client->server_pub, server_pub, crypto_sign_PUBLICKEYBYTES);
  memcpy(client->app, app, crypto_auth_KEYBYTES);
  memcpy(client->eph_pub, eph_pub, crypto_box_PUBLICKEYBYTES);
  memcpy(client->eph_sec, eph_sec, crypto_box_SECRETKEYBYTES);

  // hmac_{K}(a_p)
  crypto_auth(client->app_hmac, client->eph_pub, crypto_box_PUBLICKEYBYTES, client->app);

  return client;

  // TODO remove this
  // print_hex(client->app_hmac, crypto_auth_BYTES);
  // printf("%lu\n", sizeof client);
  // printf("%lu\n", sizeof *client);
  // printf("%lu\n", sizeof client->pub);
  // printf("%lu\n", sizeof *client->pub);
  // printf("%lu\n", sizeof pub);
  // printf("%lu\n", sizeof *pub);
  // printf("%p\n", client->pub);
}
