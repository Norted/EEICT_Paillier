#ifndef __PAILLIER_H__
#define __PAILLIER_H__

#include <parameters.h>

unsigned int scheme1_generate_keypair(struct Keychain *keychain);
unsigned int scheme1_encrypt(struct PublicKey *pk, BIGNUM *plain, BIGNUM *cipher);
unsigned int scheme1_decrypt(struct Keychain *keychain, BIGNUM *cipher, BIGNUM *plain);
void scheme1_init_keychain(struct Keychain *keychain);
void scheme1_free_keychain(struct Keychain *keychain);

#endif