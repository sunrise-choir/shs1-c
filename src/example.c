#include "shs1.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>

void print_hex(void *mem, int size) {
  int i;
  unsigned char *p = (unsigned char *)mem;
  for (i=0;i<size;i++) {
    printf("%02x ", p[i]);
  }
  printf("\n");
}

int main()
{
  unsigned char app[crypto_auth_KEYBYTES];

  unsigned char client_pub[crypto_sign_PUBLICKEYBYTES];
  unsigned char client_sec[crypto_sign_SECRETKEYBYTES];
  unsigned char client_eph_pub[crypto_box_PUBLICKEYBYTES];
  unsigned char client_eph_sec[crypto_box_SECRETKEYBYTES];

  unsigned char server_pub[crypto_sign_PUBLICKEYBYTES];
  unsigned char server_sec[crypto_sign_SECRETKEYBYTES];
  unsigned char server_eph_pub[crypto_box_PUBLICKEYBYTES];
  unsigned char server_eph_sec[crypto_box_SECRETKEYBYTES];

  unsigned char client_challenge[SHS1_CLIENT_CHALLENGE_BYTES];
  unsigned char client_auth[SHS1_CLIENT_AUTH_BYTES];
  unsigned char server_challenge[SHS1_SERVER_CHALLENGE_BYTES];
  unsigned char server_auth[SHS1_SERVER_AUTH_BYTES];

  SHS1_Outcome client_outcome;
  SHS1_Outcome server_outcome;

  assert(sodium_init() != -1);

  randombytes_buf(app, sizeof app);
  crypto_sign_keypair(client_pub, client_sec);
  crypto_box_keypair(client_eph_pub, client_eph_sec);
  crypto_sign_keypair(server_pub, server_sec);
  crypto_box_keypair(server_eph_pub, server_eph_sec);

  SHS1_Client *client = shs1_init_client(app, client_pub, client_sec, client_eph_pub, client_eph_sec, server_pub);
  SHS1_Server *server = shs1_init_server(app, server_pub, server_sec, server_eph_pub, server_eph_sec);

  printf("%s\n", "");

  shs1_create_client_challenge(client_challenge, client);
  printf("%s", "client challenge: ");
  print_hex(client_challenge, SHS1_CLIENT_CHALLENGE_BYTES);
  printf("%s\n", "");

  assert(shs1_verify_client_challenge(client_challenge, server));

  shs1_create_server_challenge(server_challenge, server);
  printf("%s", "server challenge: ");
  print_hex(server_challenge, SHS1_SERVER_CHALLENGE_BYTES);
  printf("%s\n", "");

  assert(shs1_verify_server_challenge(server_challenge, client));

  assert(shs1_create_client_auth(client_auth, client) == 0);
  printf("%s", "client auth: ");
  print_hex(client_auth, SHS1_CLIENT_AUTH_BYTES);
  printf("%s\n", "");

  assert(shs1_verify_client_auth(client_auth, server));

  shs1_create_server_auth(server_auth, server);
  printf("%s", "server auth: ");
  print_hex(server_auth, SHS1_SERVER_AUTH_BYTES);
  printf("%s\n", "");

  assert(shs1_verify_server_auth(server_auth, client));

  shs1_client_outcome(&client_outcome, client);
  shs1_server_outcome(&server_outcome, server);

  printf("%s\n", "");
  printf("%s", "client: encryption key: ");
  print_hex(&(client_outcome.encryption_key), crypto_secretbox_KEYBYTES);
  printf("%s", "client: encryption nonce: ");
  print_hex(&(client_outcome.encryption_nonce), crypto_secretbox_NONCEBYTES);
  printf("%s", "client: decryption key: ");
  print_hex(&(client_outcome.decryption_key), crypto_secretbox_KEYBYTES);
  printf("%s", "client: decryption nonce: ");
  print_hex(&(client_outcome.decryption_nonce), crypto_secretbox_NONCEBYTES);
  printf("%s\n", "");
  printf("%s", "server: encryption key: ");
  print_hex(&(server_outcome.encryption_key), crypto_secretbox_KEYBYTES);
  printf("%s", "server: encryption nonce: ");
  print_hex(&(server_outcome.encryption_nonce), crypto_secretbox_NONCEBYTES);
  printf("%s", "server: decryption key: ");
  print_hex(&(server_outcome.decryption_key), crypto_secretbox_KEYBYTES);
  printf("%s", "server: decryption nonce: ");
  print_hex(&(server_outcome.decryption_nonce), crypto_secretbox_NONCEBYTES);

  assert(memcmp(&(client_outcome.encryption_key), &(server_outcome.decryption_key), crypto_secretbox_KEYBYTES) == 0);
  assert(memcmp(&(client_outcome.encryption_nonce), &(server_outcome.decryption_nonce), crypto_secretbox_NONCEBYTES) == 0);
}
