#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#define G_MAXRANDOMNUMBER   100
#define G_MINRANDOMNUMBER   1
#define SEED                "paillier"
#define BITS                512
#define BUFFER              BITS*32
#define MAXITER             10000

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/dsa.h>
#include <support_functions.h>
#include <paillier_scheme1.h>
#include <paillier_scheme3.h>
#include <homomorphy_functions.h>

struct PublicKey {
    BIGNUM *n;
    BIGNUM *n_sq;
    BIGNUM *g;
};

#endif