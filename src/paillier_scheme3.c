#include <paillier_scheme3.h>

unsigned int _keychain_gen(struct Keychain *keychain);
unsigned int _CRT_part(BIGNUM *prod, BIGNUM *n, BIGNUM *a, BIGNUM *res);

unsigned int scheme3_generate_keypair(struct Keychain *keychain) {
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;

    struct Keychain keychain1 = {{""}};
    init_keychain(&keychain1);
    err += _keychain_gen(&keychain1);
    if(err != 1) {
        BN_free(ctx);
        free_keychain(&keychain1);
        return 0;
    }

    struct Keychain keychain2 = {{""}};
    init_keychain(&keychain2);
    err += _keychain_gen(&keychain2);
    if(err != 2) {
        BN_free(ctx);
        free_keychain(&keychain1);
        free_keychain(&keychain2);
        return 0;
    }

    BIGNUM *two = BN_new();
    BN_dec2bn(&two, "2");

    BN_copy(keychain->sk.p, keychain1.sk.p);
    BN_copy(keychain->sk.q, keychain2.sk.p);
    err += BN_mul(keychain->pk->n, keychain->sk.p, keychain->sk.q, ctx);
    err += BN_exp(keychain->pk->n_sq, keychain->pk->n, two, ctx);

    BIGNUM *lambda = BN_new();
    err += l_or_a_computation(keychain->sk.p, keychain->sk.q, lambda);

    //Chinese Remainder Theorem
        BIGNUM *p_sq = BN_new();
        BIGNUM *q_sq = BN_new();
        err += BN_exp(p_sq, keychain->sk.p, two, ctx);
        err += BN_exp(q_sq, keychain->sk.q, two, ctx);
        
        BIGNUM *num[] = {p_sq, q_sq};
        BIGNUM *rem[] = {keychain1.pk->g, keychain2.pk->g};
        int size = sizeof(num) / sizeof(num[0]);
        err += chinese_remainder_theorem(num, rem, size, keychain->pk->g);
    //
    BN_free(two);
    BN_free(p_sq);
    BN_free(q_sq);

    err += BN_mul(keychain->sk.l_or_a, keychain1.sk.q, keychain2.sk.q, ctx);
    
    // Check if l_or_a is divisor of lambda
    BIGNUM *chck = BN_new();
    err += BN_mod(chck, lambda, keychain->sk.l_or_a, ctx);
    if(BN_is_zero(chck) == 0) {
        BN_free(chck);
        BN_free(lambda);
        free_keychain(&keychain1);
        free_keychain(&keychain2);
        return 0;
    }
    BN_free(lambda);

    // Check if g is the order of l_or_a*n in Z*_nsquared
    BIGNUM *l_or_a_mul_n = BN_new();
    err += BN_mul(l_or_a_mul_n, keychain->sk.l_or_a, keychain->pk->n, ctx);
    err += BN_mod_exp(chck, keychain->pk->g, l_or_a_mul_n, keychain->pk->n_sq, ctx);
    if(BN_is_one(chck) == 0) {
        BN_free(chck);
        BN_free(l_or_a_mul_n);
        free_keychain(&keychain1);
        free_keychain(&keychain2);
        return 0;
    }
    BN_free(chck);
    BN_free(l_or_a_mul_n);
    
    err += BN_mod_exp(keychain->pk->g2n, keychain->pk->g, keychain->pk->n, keychain->pk->n_sq, ctx);
    err += count_mi(keychain->sk.mi, keychain->pk->g, keychain->sk.l_or_a, keychain->pk->n_sq, keychain->pk->n);

    BN_CTX_free(ctx);
    free_keychain(&keychain1);
    free_keychain(&keychain2);

    if(err != 14)
        return 0;
    return 1;
}

unsigned int scheme3_encrypt(struct PublicKey *pk, BIGNUM *l_or_a, BIGNUM *plain, BIGNUM *cipher, BIGNUM *precomp_message, BIGNUM *precomp_noise) {
    clock_t start, end;
    double consumed_time = 0;
    
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    if(BN_cmp(plain, pk->n) != -1)
        return 0;
    
    unsigned int err = 0;
    BIGNUM *tmp_rnd = BN_new();

    // FIX ME!!!
    // SLOW CODE!!!
        if (BN_is_zero(precomp_message) == 1)
            err += BN_mod_exp(precomp_message, pk->g, plain, pk->n_sq, ctx);
        else
        {
            err += 1;
        }
        
        if (BN_is_zero(precomp_noise) == 1)
        {
            err += generate_rnd(l_or_a, l_or_a, tmp_rnd, BITS/2);
            err += BN_mod_exp(precomp_noise, pk->g2n, tmp_rnd, pk->n_sq, ctx);    // BOTTLENECK!!!
        }
        else
        {
            err += 2;
        }
    //
    
    err += BN_mod_mul(cipher, precomp_message, precomp_noise, pk->n_sq, ctx);

    BN_CTX_free(ctx);
    BN_free(tmp_rnd);

    if(err != 4)
        return 0;
    
    return 1;
}

unsigned int scheme3_decrypt(struct Keychain *keychain, BIGNUM *cipher, BIGNUM *plain) {
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    BIGNUM *u = BN_new();

    err += BN_mod_exp(u, cipher, keychain->sk.l_or_a, keychain->pk->n_sq, ctx);
    err += L(u, keychain->pk->n, u, ctx);
    err += BN_mod_mul(plain, u, keychain->sk.mi, keychain->pk->n, ctx);

    BN_free(u);

    if(err != 3)
        return 0;
    
    return 1;
}

// Support functions
unsigned int _keychain_gen(struct Keychain *keychain) {
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    BIGNUM *two = BN_new();
    BN_dec2bn(&two, "2");
    
    err += gen_DSA_params(keychain->sk.p, keychain->sk.q, keychain->pk->g);
    err += BN_mul(keychain->pk->n, keychain->sk.p, keychain->sk.q, ctx);
    err += BN_exp(keychain->pk->n_sq, keychain->pk->n, two, ctx);

    BIGNUM *p_sq = BN_new();
    BIGNUM *mod = BN_new();
    err += BN_exp(p_sq, keychain->sk.p, two, ctx);
    err += BN_mod_exp(mod, keychain->pk->g, keychain->pk->n, p_sq, ctx);

    BN_free(p_sq);
    BN_free(two);
    BN_CTX_free(ctx);
    
    if (err != 5 || BN_is_one(mod) != 1) {
        BN_free(mod);
        return 0;
    }

    BN_free(mod);
    return 1;
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