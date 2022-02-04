#ifndef __PAILLIER_H__
#define __PAILLIER_H__

#include <parameters.h>

struct PrivateKey_scheme1 {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *lambda;
    BIGNUM *mi;     // modular multiplicative inverse (L(g^lambda mod n^2))^(-1) mod n
};

struct Keychain_scheme1 {
    struct PrivateKey_scheme1 sk;
    struct PublicKey pk;
};

unsigned int scheme1_generate_keypair(struct Keychain_scheme1 *keyring);
unsigned int scheme1_encrypt(struct PublicKey pk, BIGNUM *plain, BIGNUM *cipher);
unsigned int scheme1_decrypt(struct Keychain_scheme1 *keyring, BIGNUM *cipher, BIGNUM *plain);

#endif