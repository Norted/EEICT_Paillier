#ifndef __SCHEME3_H__
#define __SCHEME3_H__

#include <parameters.h>
#include <paillier_scheme3.h>

struct PrivateKey_scheme3 {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *alpha;
    BIGNUM *mi;     // modular multiplicative inverse (L(g^alpha mod n^2))^(-1) mod n
};

struct Keychain_scheme3 {
    struct PrivateKey_scheme3 sk;
    struct PublicKey *pk;
};

unsigned int scheme3_generate_keypair(struct Keychain_scheme3 *keyring);
unsigned int scheme3_encrypt(struct PublicKey *pk, unsigned char *plain, unsigned char *cipher);
unsigned int scheme3_decrypt(struct Keychain_scheme3 *keyring, unsigned char *cipher, unsigned char *plain);
void scheme3_init_keychain(struct Keychain_scheme3 *keychain);
void scheme3_free_keychain(struct Keychain_scheme3 *keychain);

#endif