#include "shs1.h"

#include <stdio.h>
#include <sodium.h>

int main()
{
    unsigned char c_pub[crypto_sign_PUBLICKEYBYTES];
    unsigned char c_sec[crypto_sign_SECRETKEYBYTES];
    unsigned char s_pub[crypto_sign_PUBLICKEYBYTES];
    unsigned char s_sec[crypto_sign_SECRETKEYBYTES];
    unsigned char app[crypto_auth_KEYBYTES];
    unsigned char c_eph_pub[crypto_box_PUBLICKEYBYTES];
    unsigned char c_eph_sec[crypto_box_SECRETKEYBYTES];
    unsigned char s_eph_pub[crypto_box_PUBLICKEYBYTES];
    unsigned char s_eph_sec[crypto_box_SECRETKEYBYTES];

    if (sodium_init() == -1) {
        return 1;
    }

    crypto_sign_keypair(s_pub, s_sec);
    crypto_sign_keypair(c_pub, c_sec);
    randombytes_buf(app, sizeof app);
    crypto_box_keypair(c_eph_pub, c_eph_sec);
    crypto_box_keypair(s_eph_pub, s_eph_sec);

    SHS1_Client *client = shs1_init_client(c_pub, c_sec, s_pub, app, c_eph_pub, c_eph_sec);

    free(client);

    // printf("%lu\n", sizeof client);
}
