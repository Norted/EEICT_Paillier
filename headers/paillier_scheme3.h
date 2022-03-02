#ifndef __SCHEME3_H__
#define __SCHEME3_H__

#include <parameters.h>
#include <paillier_scheme3.h>

unsigned int scheme3_generate_keypair(struct Keychain *keychain);
unsigned int scheme3_encrypt(struct PublicKey *pk, BIGNUM *alpha, BIGNUM *plain, BIGNUM *cipher, BIGNUM *precomp_message, BIGNUM *precomp_noise);
unsigned int scheme3_decrypt(struct Keychain *keychain, BIGNUM *cipher, BIGNUM *plain);

#endif