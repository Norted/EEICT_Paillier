#ifndef __SCHEME3_H__
#define __SCHEME3_H__

#include <parameters.h>
#include <paillier_scheme3.h>

unsigned int scheme3_generate_keypair(struct Keychain *keychain);
unsigned int scheme3_encrypt(struct PublicKey *pk, BIGNUM *alpha, BIGNUM *plain, BIGNUM *cipher);
unsigned int scheme3_decrypt(struct Keychain *keychain, BIGNUM *cipher, BIGNUM *plain);
void scheme3_init_keychain(struct Keychain *keychain);
void scheme3_free_keychain(struct Keychain *keychain);

#endif