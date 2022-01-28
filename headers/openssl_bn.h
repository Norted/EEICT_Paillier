#ifndef __OPENSSL_BN_H__
#define __OPENSSL_BN_H__

#include <globals.h>

unsigned int bn_add(unsigned char *a, unsigned char *b, unsigned char *res);
unsigned int bn_sub(unsigned char *a, unsigned char *b, unsigned char *res);
unsigned int bn_mul(unsigned char *a, unsigned char *b, unsigned char *res);
unsigned int bn_div(unsigned char *a, unsigned char *b, unsigned char *res, unsigned char *rem);
unsigned int bn_exp(unsigned char *base, unsigned char *exp, unsigned char *res);
unsigned int bn_mod(unsigned char *a, unsigned char *mod, unsigned char *res);
unsigned int bn_modadd(unsigned char *a, unsigned char *b, unsigned char *mod, unsigned char *res);
unsigned int bn_modsub(unsigned char *a, unsigned char *b, unsigned char *mod, unsigned char *res);
unsigned int bn_modmul(unsigned char *a, unsigned char *b, unsigned char *mod, unsigned char *res);
unsigned int bn_modexp(unsigned char *base, unsigned char *exp, unsigned char *mod, unsigned char *res);
unsigned int bn_gcd(unsigned char *a, unsigned char *b, unsigned char *res);
unsigned int bn_lcm(unsigned char *a, unsigned char *b, unsigned char *res);
unsigned int hash(unsigned char *res, unsigned char *Y, unsigned char *t_s, unsigned char *kappa);
unsigned int random_str_num(unsigned char *str);
unsigned int random_str_num_in_range(unsigned char *str, unsigned int max, unsigned int min);
unsigned int bn_genPrime(unsigned char *prime, int bits);
unsigned int bn_modinverse(unsigned char *a, unsigned char *n, unsigned char *inverse);
int bn_cmp(unsigned char *a, unsigned char *b);
unsigned int bn_gen_params(DSA *dsa, unsigned char *p, unsigned char *q, unsigned char *g);
unsigned int bn_gen_keys(DSA *dsa, unsigned char *sk, unsigned char *pk);

#endif