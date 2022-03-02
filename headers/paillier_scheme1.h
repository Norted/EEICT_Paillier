#ifndef __PAILLIER_H__
#define __PAILLIER_H__

#include <parameters.h>

unsigned int scheme1_generate_keypair(struct Keychain *keychain);
unsigned int scheme1_encrypt(struct PublicKey *pk, BIGNUM *plain, BIGNUM *cipher, BIGNUM *precomp_message, BIGNUM *precomp_noise);
unsigned int scheme1_decrypt(struct Keychain *keychain, BIGNUM *cipher, BIGNUM *plain);

#endif