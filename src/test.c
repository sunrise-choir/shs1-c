#include "shs1.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>

void print_hex(void *mem, int size) {
  int i;
  unsigned char *p = (unsigned char *)mem;
  for (i=0;i<size;i++) {
    printf("0x%02x ", p[i]);
  }
  printf("\n");
}

int main()
{
  // test data generated via https://gist.github.com/AljoschaMeyer/d8766ce2ee6bc8e1e20194567863f25c
  unsigned char app[crypto_auth_KEYBYTES] = {111,97,159,86,19,13,53,115,66,209,32,84,255,140,143,85,157,74,32,154,156,90,29,185,141,19,184,255,104,107,124,198};

  unsigned char client_pub[crypto_sign_PUBLICKEYBYTES] = {225,162,73,136,73,119,94,84,208,102,233,120,23,46,225,245,198,79,176,0,151,208,70,146,111,23,94,101,25,192,30,35};
  unsigned char client_sec[crypto_sign_SECRETKEYBYTES] = {243,168,6,50,44,78,192,183,210,241,189,36,183,154,132,119,115,84,47,151,32,32,26,237,64,180,69,20,95,133,92,176,225,162,73,136,73,119,94,84,208,102,233,120,23,46,225,245,198,79,176,0,151,208,70,146,111,23,94,101,25,192,30,35};
  unsigned char client_eph_pub[crypto_box_PUBLICKEYBYTES] = {79,79,77,238,254,215,129,197,235,41,185,208,47,32,146,37,255,237,208,215,182,92,201,106,85,86,157,41,53,165,177,32};
  unsigned char client_eph_sec[crypto_box_SECRETKEYBYTES] = {80,169,55,157,134,142,219,152,125,240,174,209,225,109,46,188,97,224,193,187,198,58,226,193,24,235,213,214,49,55,213,104};

  unsigned char server_pub[crypto_sign_PUBLICKEYBYTES] = {42,190,113,153,16,248,187,195,163,201,187,204,86,238,66,151,52,115,160,4,244,1,12,76,170,129,66,12,202,54,1,70};
  unsigned char server_sec[crypto_sign_SECRETKEYBYTES] = {118,98,17,77,86,116,58,146,99,84,198,164,35,220,73,213,246,224,242,230,175,116,71,218,56,37,212,66,163,14,74,209,42,190,113,153,16,248,187,195,163,201,187,204,86,238,66,151,52,115,160,4,244,1,12,76,170,129,66,12,202,54,1,70};
  unsigned char server_eph_pub[crypto_box_PUBLICKEYBYTES] = {166,12,63,218,235,136,61,99,232,142,165,147,88,93,79,177,23,148,129,57,179,24,192,174,90,62,40,83,51,9,97,82};
  unsigned char server_eph_sec[crypto_box_SECRETKEYBYTES] = {176,248,210,185,226,76,162,153,239,144,57,206,218,97,2,215,155,5,223,189,22,28,137,85,228,233,93,79,217,203,63,125};

  unsigned char client_challenge[SHS1_CLIENT_CHALLENGE_BYTES];
  unsigned char client_auth[SHS1_CLIENT_AUTH_BYTES];
  unsigned char server_challenge[SHS1_SERVER_CHALLENGE_BYTES];
  unsigned char server_auth[SHS1_SERVER_AUTH_BYTES];

  unsigned char expected_client_challenge[SHS1_CLIENT_CHALLENGE_BYTES] = {211,6,20,155,178,209,30,107,1,3,140,242,73,101,116,234,249,127,131,227,142,66,240,195,13,50,38,96,7,208,124,180,79,79,77,238,254,215,129,197,235,41,185,208,47,32,146,37,255,237,208,215,182,92,201,106,85,86,157,41,53,165,177,32};
  unsigned char expected_server_challenge[SHS1_SERVER_CHALLENGE_BYTES] = {44,140,79,227,23,153,202,203,81,40,114,59,56,167,63,166,201,9,50,152,0,255,226,147,22,43,84,99,107,198,198,219,166,12,63,218,235,136,61,99,232,142,165,147,88,93,79,177,23,148,129,57,179,24,192,174,90,62,40,83,51,9,97,82};
  unsigned char expected_client_auth[SHS1_CLIENT_AUTH_BYTES] = {80,34,24,195,46,211,235,66,91,89,65,98,137,26,86,197,32,4,153,142,160,18,56,180,12,171,127,38,44,53,74,64,55,188,22,25,161,25,7,243,200,196,145,249,207,211,88,178,0,206,173,234,188,20,251,240,199,169,94,180,212,32,150,226,138,44,141,235,33,152,91,215,31,126,48,48,220,239,97,225,103,79,190,56,227,103,142,195,124,10,21,76,66,11,194,11,220,15,163,66,138,232,228,12,130,172,4,137,52,159,64,98};
  unsigned char expected_server_auth[SHS1_SERVER_AUTH_BYTES] = {72,114,92,105,109,48,17,14,25,150,242,50,148,70,49,25,222,254,255,124,194,144,84,114,190,148,252,189,159,132,157,173,92,14,247,198,87,232,141,83,84,79,226,43,194,95,14,8,138,233,96,40,126,153,205,36,95,203,200,202,221,118,126,99,47,216,209,219,3,133,240,216,166,182,182,226,215,116,177,66};

  SHS1_Outcome client_outcome;
  SHS1_Outcome server_outcome;

  unsigned char expected_client_encryption_key[crypto_secretbox_KEYBYTES] = {162,29,153,150,123,225,10,173,175,201,160,34,190,179,158,14,176,105,232,238,97,66,133,194,250,148,199,7,34,157,174,24};
  unsigned char expected_client_encryption_nonce[crypto_secretbox_NONCEBYTES] = {44,140,79,227,23,153,202,203,81,40,114,59,56,167,63,166,201,9,50,152,0,255,226,147};
  unsigned char expected_client_decryption_key[crypto_secretbox_KEYBYTES] = {125,136,153,7,109,241,239,84,228,176,141,23,58,129,90,228,188,93,191,224,209,67,147,187,45,204,178,17,77,225,117,98};
  unsigned char expected_client_decryption_nonce[crypto_secretbox_NONCEBYTES] = {211,6,20,155,178,209,30,107,1,3,140,242,73,101,116,234,249,127,131,227,142,66,240,195};
  unsigned char expected_server_encryption_key[crypto_secretbox_KEYBYTES] = {125,136,153,7,109,241,239,84,228,176,141,23,58,129,90,228,188,93,191,224,209,67,147,187,45,204,178,17,77,225,117,98};
  unsigned char expected_server_encryption_nonce[crypto_secretbox_NONCEBYTES] = {211,6,20,155,178,209,30,107,1,3,140,242,73,101,116,234,249,127,131,227,142,66,240,195};
  unsigned char expected_server_decryption_key[crypto_secretbox_KEYBYTES] = {162,29,153,150,123,225,10,173,175,201,160,34,190,179,158,14,176,105,232,238,97,66,133,194,250,148,199,7,34,157,174,24};
  unsigned char expected_server_decryption_nonce[crypto_secretbox_NONCEBYTES] = {44,140,79,227,23,153,202,203,81,40,114,59,56,167,63,166,201,9,50,152,0,255,226,147};

  assert(sodium_init() != -1);

  SHS1_Client *client = shs1_init_client(client_pub, client_sec, server_pub, app, client_eph_pub, client_eph_sec);
  SHS1_Server *server = shs1_init_server(server_pub, server_sec, app, server_eph_pub, server_eph_sec);

  shs1_create_client_challenge(client_challenge, client);
  assert(memcmp(client_challenge, expected_client_challenge, SHS1_CLIENT_CHALLENGE_BYTES) == 0);

  assert(shs1_verify_client_challenge(client_challenge, server));

  shs1_create_server_challenge(server_challenge, server);
  assert(memcmp(server_challenge, expected_server_challenge, SHS1_SERVER_CHALLENGE_BYTES) == 0);

  assert(shs1_verify_server_challenge(server_challenge, client));

  assert(shs1_create_client_auth(client_auth, client) == 0);
  assert(memcmp(client_auth, expected_client_auth, SHS1_CLIENT_AUTH_BYTES) == 0);

  assert(shs1_verify_client_auth(client_auth, server));

  shs1_create_server_auth(server_auth, server);
  // print_hex(server_auth, SHS1_SERVER_AUTH_BYTES);
  // print_hex(expected_server_auth, SHS1_SERVER_AUTH_BYTES);
  assert(memcmp(server_auth, expected_server_auth, SHS1_SERVER_AUTH_BYTES) == 0);

  assert(shs1_verify_server_auth(server_auth, client));

  shs1_client_outcome(&client_outcome, client);
  shs1_server_outcome(&server_outcome, server);

  assert(memcmp(&(client_outcome.encryption_key), expected_client_encryption_key, crypto_secretbox_KEYBYTES) == 0);
  assert(memcmp(&(client_outcome.encryption_nonce), expected_client_encryption_nonce, crypto_secretbox_NONCEBYTES) == 0);
  assert(memcmp(&(client_outcome.decryption_key), expected_client_decryption_key, crypto_secretbox_KEYBYTES) == 0);
  assert(memcmp(&(client_outcome.decryption_nonce), expected_client_decryption_nonce, crypto_secretbox_NONCEBYTES) == 0);
  assert(memcmp(&(server_outcome.encryption_key), expected_server_encryption_key, crypto_secretbox_KEYBYTES) == 0);
  assert(memcmp(&(server_outcome.encryption_nonce), expected_server_encryption_nonce, crypto_secretbox_NONCEBYTES) == 0);
  assert(memcmp(&(server_outcome.decryption_key), expected_server_decryption_key, crypto_secretbox_KEYBYTES) == 0);
  assert(memcmp(&(server_outcome.decryption_nonce), expected_server_decryption_nonce, crypto_secretbox_NONCEBYTES) == 0);
}
