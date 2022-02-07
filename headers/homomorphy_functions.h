#ifndef __HOMOMORPHY_FUNCTIONS_H__
#define __HOMOMORPHY_FUNCTIONS_H__

#include <parameters.h>
#include <paillier_scheme1.h>

unsigned int add(struct PublicKey *pk, BIGNUM *a, BIGNUM *b, BIGNUM *res);
unsigned int add_const(struct PublicKey *pk, BIGNUM *a, BIGNUM *n, BIGNUM *res);
unsigned int mul_const(struct PublicKey *pk, BIGNUM *a, BIGNUM *n, BIGNUM *res);
unsigned int test_homomorphic_scheme1();
unsigned int test_homomorphic_scheme3();

#endif