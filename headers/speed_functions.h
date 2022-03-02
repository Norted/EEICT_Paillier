#ifndef __SPEED_FUNCTIONS_H__
#define __SPEED_FUNCTIONS_H__

#include <parameters.h>

void reduced_moduli();
int precomputation(const char *restrict file_name, struct Keychain *keychain, unsigned int range, unsigned int type); // type: 1 ... message, 0 ... noise
cJSON *message_precomp(BIGNUM *range, BIGNUM *base, BIGNUM *mod);
cJSON *noise_precomp(BIGNUM *range, BIGNUM *exp_value, BIGNUM *mod);

#endif