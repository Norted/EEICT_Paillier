#ifndef __OPENSSL_BN_H__
#define __OPENSSL_BN_H__

#include <parameters.h>

unsigned int gen_pqg_params(BIGNUM *p, BIGNUM *q, BIGNUM *g);
unsigned int lcm(BIGNUM *a, BIGNUM *b, BIGNUM *res);
unsigned int count_mi(BIGNUM *mi, BIGNUM *g, BIGNUM *l_or_a, BIGNUM *n_sq, BIGNUM *n);

#endif