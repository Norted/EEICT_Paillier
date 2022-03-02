#ifndef __HOMOMORPHY_FUNCTIONS_H__
#define __HOMOMORPHY_FUNCTIONS_H__

#include <parameters.h>

unsigned int add(struct PublicKey *pk, BIGNUM *a, BIGNUM *b, BIGNUM *res);
unsigned int add_const(struct PublicKey *pk, BIGNUM *a, BIGNUM *n, BIGNUM *res);
unsigned int mul_const(struct PublicKey *pk, BIGNUM *a, BIGNUM *n, BIGNUM *res);

#endif