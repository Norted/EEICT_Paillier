#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/dsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <support_functions.h>
#include <paillier_scheme1.h>
#include <paillier_scheme3.h>
#include <homomorphy_functions.h>

#define NUM_THREADS 2
#define BUFFER 1024
#define BITS 512        // 512, 1024, 1500, 2048
#define BITS_STR "1024" // BITS * 2
#define ALPHA_BITS 320  // 512   //jen pro 4096
#define MAXITER 10000
#define RANGE 100000

struct PrivateKey
{
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *l_or_a; // lambda (for scheme 1) or alpha (for scheme 3)
    BIGNUM *mi;     // modular multiplicative inverse (L(g^lambda mod n^2))^(-1) mod n
};

struct PublicKey
{
    BIGNUM *n;
    BIGNUM *g2n; // used in scheme 3
    BIGNUM *n_sq;
    BIGNUM *g;
};

struct Keychain
{
    struct PrivateKey sk;
    struct PublicKey *pk;
};

#endif