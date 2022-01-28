#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#define G_NUMOFDEVICES      10
#define G_POLYDEGREE        2
#define G_GENERATORSLEN     6
#define G_MAXRANDOMNUMBER   100
#define G_MINRANDOMNUMBER   1
#define Q_PARAM_BITS        160
#define BITS                256
#define BUFFER              BITS*4
#define BIG_BUFFER          BITS*32
#define BUFFER100           100
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
#include <openssl_bn.h>


struct ServerSign {
    unsigned char tau_s[BUFFER];
    unsigned char kappa[BIG_BUFFER];
};

struct ClientProof {
    unsigned char tau_c[BUFFER];
    struct SchnorrSignature *signature;
    unsigned char kappa[BUFFER];
};

struct DeviceProof {
    unsigned char s_i[BUFFER];
    unsigned char kappa_i[BUFFER];
};

/*  === GLOBALS ===
 *  ||---> params .............. Schnorr's Signature struct with p, q, g params
 *  ||---> g_idCounter ......... helping couter for CID generation
 */

struct globals {
    struct SchnorrParams *params;
    unsigned int idCounter;
};

extern struct globals g_globals;

#endif