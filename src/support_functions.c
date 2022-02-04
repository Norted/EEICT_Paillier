#include <support_functions.h>

unsigned int gen_pqg_params(BIGNUM *p, BIGNUM *q, BIGNUM *g) {
    DSA *dsa = DSA_new();
    BN_GENCB *cb = BN_GENCB_new();
    unsigned char *rnd_seed = SEED;
    int counter_ret = 0;
    unsigned long h_ret = 0;
    RAND_seed(rnd_seed, sizeof(rnd_seed));

    unsigned int err = DSA_generate_parameters_ex(&dsa, BITS, rnd_seed, sizeof(rnd_seed), &counter_ret, &h_ret, &cb);
    DSA_get0_pqg(dsa, p, q, g);

    DSA_free(dsa);
    BN_GENCB_free(cb);

    return err;
}

unsigned int lcm(BIGNUM *a, BIGNUM *b, BIGNUM *res) {
    unsigned int err = 0;
    // ((p-1) * (q-1)) / gcd((p-1), (q-1));
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    const BIGNUM *one = BN_value_one();
    BIGNUM *bn_sub_a = BN_new();
    BIGNUM *bn_sub_b = BN_new();

    err = BN_sub(bn_sub_a, a, one);
    if(err == 0) {
        BN_free(one);
        BN_free(bn_sub_a);
        BN_free(bn_sub_b);
        BN_CTX_free(ctx);
        return err;
    }
    err = BN_sub(bn_sub_b, b, one);
    if(err == 0) {
        BN_free(one);
        BN_free(bn_sub_a);
        BN_free(bn_sub_b);
        BN_CTX_free(ctx);
        return err;
    }

    BN_free(one);

    BIGNUM *bn_mul = BN_new();
    err = BN_mul(bn_mul, bn_sub_a, bn_sub_b, ctx);
    if(err == 0) {
        BN_free(bn_sub_a);
        BN_free(bn_sub_b);
        BN_free(bn_mul);
        BN_CTX_free(ctx);
        return err;
    }
    
    BIGNUM *bn_gcd = BN_new();
    err = BN_gcd(bn_gcd, bn_sub_a, bn_sub_b, ctx);
    if(err == 0) {
        BN_free(bn_sub_a);
        BN_free(bn_sub_b);
        BN_free(bn_mul);
        BN_free(bn_gcd);
        BN_CTX_free(ctx);
        return err;
    }
    
    BIGNUM *bn_rem = BN_new();
    err = BN_div(res, bn_rem, bn_mul, bn_gcd, ctx);
    
    BN_free(bn_sub_a);
    BN_free(bn_sub_b);
    BN_free(bn_mul);
    BN_free(bn_gcd);
    BN_free(bn_rem);
    BN_CTX_free(ctx);

    return err;
}

unsigned int count_mi(BIGNUM *mi, BIGNUM *g, BIGNUM *l_or_a, BIGNUM *n_sq, BIGNUM *n) {
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    BIGNUM *p_1 = BN_new();
    BIGNUM *p_2 = BN_new();
    BIGNUM *p_3 = BN_new();
    BIGNUM *rem = BN_new();
    const BIGNUM *one = BN_value_one();

    err = BN_mod_exp(p_1, g, l_or_a, n_sq, ctx);
    if(err == 0) {
        BN_free(p_1);
        BN_CTX_free(ctx);
        return err;
    }
    err = BN_sub(p_1, one, p_2);
    if(err == 0) {
        BN_free(p_1);
        BN_free(p_2);
        BN_CTX_free(ctx);
        return err;
    }
    err = BN_div(p_3, rem, p_2, n, ctx);
    if(err == 0) {
        BN_free(p_1);
        BN_free(p_2);
        BN_free(rem);
        BN_CTX_free(ctx);
        return err;
    }
    
    BN_free(p_1);
    BN_free(p_2);
    BN_free(rem);

    BN_mod_inverse(mi, p_3, n, ctx);
    if(BN_cmp(mi, "0") != 1) {
        BN_free(p_3);
        BN_CTX_free(ctx);
        return 0;
    }

    BN_free(p_3);
    BN_CTX_free(ctx);
    
    return err;
}