#include <support_functions.h>

unsigned int gen_pqg_params(BIGNUM *p, BIGNUM *q, BIGNUM *g) {
    unsigned int err = 0;
    const DSA *dsa = DSA_new();
    BIGNUM *dsa_p = BN_new();
    BIGNUM *dsa_q = BN_new();
    BIGNUM *dsa_g = BN_new();

    err += DSA_generate_parameters_ex(dsa, BITS, NULL, 0, NULL, NULL, NULL);
    DSA_get0_pqg(dsa, &dsa_p, &dsa_q, &dsa_g);

    BN_copy(p, dsa_p);
    BN_copy(q, dsa_q);
    BN_copy(g, dsa_g);

    DSA_free(dsa);

    if(err != 1)
        return 0;
    return 1;
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

    err = BN_mod_exp(p_1, g, l_or_a, n_sq, ctx);
    if(err == 0) {
        BN_free(p_1);
        BN_CTX_free(ctx);
        return err;
    }

    BIGNUM *p_2 = BN_new();
    const BIGNUM *one = BN_value_one();
    err = BN_sub(p_1, one, p_2);
    if(err == 0) {
        BN_free(p_1);
        BN_free(p_2);
        BN_CTX_free(ctx);
        return err;
    }

    BIGNUM *p_3 = BN_new();
    BIGNUM *rem = BN_new();
    err = BN_div(p_3, rem, p_2, n, ctx);
    if(err == 0) {
        BN_free(p_1);
        BN_free(p_2);
        BN_free(p_3);
        BN_free(rem);
        BN_CTX_free(ctx);
        return err;
    }
    
    BN_free(p_1);
    BN_free(p_2);
    BN_free(rem);

    BIGNUM *inv = BN_new();
    BIGNUM *zero = BN_new();
    BN_dec2bn(&zero, "0");

    BN_mod_inverse(inv, p_3, n, ctx); // FIX ME!!!
    if(BN_cmp(inv, zero) == 1) {
        BN_free(p_3);
        BN_free(inv);
        BN_free(zero);
        BN_CTX_free(ctx);
        return 0;
    }
    BN_copy(mi, inv);

    BN_free(p_3);
    BN_free(inv);
    BN_free(zero);
    BN_CTX_free(ctx);
    
    return err;
}