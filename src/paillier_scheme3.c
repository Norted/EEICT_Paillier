#include <paillier_scheme3.h>

unsigned int _keyring_gen(struct Keychain_scheme3 *keyring);
unsigned int _CRT_part(BIGNUM *prod, BIGNUM *n, BIGNUM *a, BIGNUM *res);

unsigned int scheme3_generate_keypair(struct Keychain_scheme3 *keyring) {
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;

    struct Keychain_scheme3 keyring1 = {{""}};
    err += _keyring_gen(&keyring1);
    struct Keychain_scheme3 keyring2 = {{""}};
    err += _keyring_gen(&keyring2);

    strcpy(keyring->sk.p, keyring1.sk.p);
    strcpy(keyring->sk.q, keyring2.sk.p);
    err += BN_mul(keyring->pk->n, keyring->sk.p, keyring->sk.q, ctx);
    err += BN_exp(keyring->pk->n_sq, keyring->pk->n, "2", ctx);

    BIGNUM *lambda = BN_new();
    err += lcm(keyring->sk.p, keyring->sk.q, lambda);

    //Chinese Remainder Theorem
        BIGNUM *prod = BN_value_one();
        BIGNUM *p_sq = BN_new();
        BIGNUM *q_sq = BN_new();
        err += BN_exp(p_sq, keyring->sk.p, "2", ctx);
        err += BN_exp(q_sq, keyring->sk.q, "2", ctx);
        err += BN_mul(prod, p_sq, q_sq, ctx);

        BIGNUM *res1 = BN_new();
        BIGNUM *res2 = BN_new();
        err += _CRT_part(prod, p_sq, keyring1.pk->g, res1);
        err += _CRT_part(prod, q_sq, keyring2.pk->g, res2);
        err += BN_mod_add(keyring->pk->g, res1, res2, prod, ctx);
    //
    BN_free(prod);
    BN_free(p_sq);
    BN_free(q_sq);
    BN_free(res1);
    BN_free(res2);

    err += BN_mul(keyring->sk.alpha, keyring1.sk.q, keyring2.sk.q, ctx);
    
    // Check if alpha is divisor of lambda
    BIGNUM *chck1 = BN_new();
    err += BN_mod(chck1, lambda, keyring->sk.alpha, ctx);
    if(BN_cmp(chck1, "0") != 0) {
        BN_free(chck1);
        return 0;
    }
    BN_free(chck1);

    // Check if g is the order of alpha*n in Z*_nsquared
    BIGNUM *chck2 = BN_new();
    BIGNUM *alpha_mul_n = BN_new();
    err += BN_mul(alpha_mul_n, keyring->sk.alpha, keyring->pk->n, ctx);
    err += BN_mod_exp(chck2, keyring->pk->g, alpha_mul_n, keyring->pk->n_sq, ctx);
    if(BN_cmp(chck2, "0") != 1) {
        BN_free(chck2);
        BN_free(alpha_mul_n);
        return 0;
    }
    BN_free(chck2);
    BN_free(alpha_mul_n);
    
    err += count_mi(keyring->sk.mi, keyring->pk->g, keyring->sk.alpha, keyring->pk->n_sq, keyring->pk->n);

    BN_CTX_free(ctx);

    if(err != 16)
        return 0;
    return 1;
}

unsigned int scheme3_encrypt(struct PublicKey *pk, unsigned char *plain, unsigned char *cipher) {

}

unsigned int scheme3_decrypt(struct Keychain_scheme3 *keyring, unsigned char *cipher, unsigned char *plain) {

}

// Support functions
unsigned int _keyring_gen(struct Keychain_scheme3 *keyring) {
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    BIGNUM *two = BN_new();
    BN_dec2bn(&two, "2");
    
    err += gen_pqg_params(keyring->sk.p, keyring->sk.q, keyring->pk->g);
    err += BN_mul(keyring->pk->n, keyring->sk.p, keyring->sk.q, ctx);
    err += BN_exp(keyring->pk->n_sq, keyring->pk->n, two, ctx);

    BIGNUM *psq = BN_new();
    BIGNUM *mod = BN_new();
    err += BN_exp(psq, keyring->sk.p, two, ctx);
    err += BN_mod_exp(mod, keyring->pk->g, keyring->pk->n, psq, ctx);

    BN_free(psq);
    BN_free(mod);
    BN_free(two);
    BN_CTX_free(ctx);
    
    if (err != 5 || BN_cmp(mod, "1") != 0)
        return 0;
    return 1;

    /* OLD CODE
        err += bn_genPrime(keyring->sk.p, BITS);
        err += bn_genPrime(keyring->sk.q, BITS);
        err += bn_mul(keyring->sk.p, keyring->sk.q, keyring->pk.n);
        
        err += bn_exp(keyring->pk.n, "2", keyring->pk.n_sq);
        

        for(int i = 0; i < MAXITER; i++) {
            random_str_num_in_range(keyring->pk.g, atoi(keyring->pk.n_sq), 1);
            unsigned char psq[BUFFER];
            unsigned char mod[BUFFER];
            err += bn_exp(keyring->sk.p, "2", psq);
            err += bn_modexp(keyring->pk.g, keyring->pk.n, psq, mod);
            if(bn_cmp(mod, "1") != 0) {
                err -= 2;
                continue;
            }
            break;
        }

        if (err != 6)
            return 0;
        return 1;
    */
}

unsigned int _CRT_part(BIGNUM *prod, BIGNUM *n, BIGNUM *a, BIGNUM *res) {
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;

    BIGNUM *rem = BN_new();
    BIGNUM *inv = BN_new();
    BIGNUM *mul = BN_new();
    BIGNUM *pp = BN_new();

    err += BN_div(pp, rem, prod, n, ctx);
    BN_free(rem);

    BN_mod_inverse(inv, pp, n, ctx);
    if(BN_cmp(inv, "0") != 1) {
        BN_free(inv);
        BN_free(mul);
        BN_free(pp);
        BN_CTX_free(ctx);
        return 0;
    }
    err += BN_mul(res, a, inv, ctx);
    err += BN_mul(res, pp, res, ctx);

    BN_free(inv);
    BN_free(mul);
    BN_free(pp);
    BN_CTX_free(ctx);

    if (err != 3)
        return 0;
    return 1;
}

void scheme3_init_keychain(struct Keychain_scheme3 *keychain) {
    keychain->pk->g = BN_new();
    keychain->pk->n = BN_new();
    keychain->pk->n_sq = BN_new();
    keychain->sk.alpha = BN_new();
    keychain->sk.mi = BN_new();
    keychain->sk.p = BN_new();
    keychain->sk.q = BN_new();

    return;
}

void scheme3_free_keychain(struct Keychain_scheme3 *keychain) {
    BN_free(keychain->pk->g);
    BN_free(keychain->pk->n);
    BN_free(keychain->pk->n_sq);
    BN_free(keychain->sk.alpha);
    BN_free(keychain->sk.mi);
    BN_free(keychain->sk.p);
    BN_free(keychain->sk.q);

    return;
}