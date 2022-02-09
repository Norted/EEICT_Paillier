#include <support_functions.h>

unsigned int gen_pqg_params(BIGNUM *p, BIGNUM *q, BIGNUM *l_or_a, struct PublicKey *pk) {
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;

    const BIGNUM *one = BN_value_one();
    BIGNUM *p_sub = BN_new();
    BIGNUM *q_sub = BN_new();
    BIGNUM *pq_sub = BN_new();
    BIGNUM *tmp_gcd = BN_new();
    int i = 0;

    for(i; i < MAXITER; i ++) {
        err += BN_generate_prime_ex2(p, BITS, 1, NULL, NULL, NULL, ctx);
        err += BN_generate_prime_ex2(q, BITS, 1, NULL, NULL, NULL, ctx);
        err += BN_mul(pk->n, p, q, ctx);

        err += BN_sub(p_sub, p, one);
        err += BN_sub(q_sub, q, one);
        err += BN_mul(pq_sub, p_sub, q_sub, ctx);

        err += BN_gcd(tmp_gcd, pk->n, pq_sub, ctx);
        if(BN_is_one(tmp_gcd) == 1)
            break;
        err -= 7;
    }
    BN_free(one);
    BN_free(p_sub);
    BN_free(q_sub);
    BN_free(pq_sub);

    if(i == MAXITER) {
        printf("MAXITER! P, Q not generated!\n");
        BN_free(tmp_gcd);
        BN_CTX_free(ctx);
        return 0;
    }
    
    const BIGNUM *two = BN_new();
    BN_dec2bn(&two, "2");
    err += BN_exp(pk->n_sq, pk->n, two, ctx);
    BN_free(two);

    err += lcm(p, q, l_or_a); // operation in function ((p-1) * (q-1)) / gcd((p-1), (q-1)) 

    i = 0;
    BIGNUM *tmp_g = BN_new();
    BIGNUM *tmp_u = BN_new();
    for(i; i < MAXITER; i++) {
        err += BN_rand_range(tmp_g, pk->n_sq);
        err += BN_gcd(tmp_gcd, tmp_g, pk->n_sq, ctx);
        if(BN_is_one(tmp_gcd) != 1) {
            err -= 2;
            continue;
        }
        
        err += BN_mod_exp(tmp_u, tmp_g, l_or_a, pk->n_sq, ctx);
        err += L(tmp_u, pk->n, tmp_u);
        err += BN_gcd(tmp_gcd, tmp_u, pk->n, ctx);
        if(BN_is_one(tmp_gcd) == 1) {
            BN_copy(pk->g, tmp_g);
            break;
        }
        err -= 5;
    }
    BN_free(tmp_g);
    BN_free(tmp_gcd);
    BN_free(tmp_u);

    if(i == MAXITER) {
        printf("MAXITER! G not found!\n");
        return 0;
    }

    if(err != 14)
        return 0;
    return 1;
}

unsigned int gen_DSA_params(BIGNUM *p, BIGNUM *q, BIGNUM *g) {
    unsigned int err = 0;
    const DSA *dsa = DSA_new();
    BIGNUM *dsa_p = BN_new();
    BIGNUM *dsa_q = BN_new();
    BIGNUM *dsa_g = BN_new();

    err += DSA_generate_parameters_ex(dsa, BITS*2, NULL, 0, NULL, NULL, NULL);
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
    
    BIGNUM *u = BN_new();

    err = BN_mod_exp(u, g, l_or_a, n_sq, ctx);
    if(err == 0) {
        BN_free(u);
        BN_CTX_free(ctx);
        return err;
    }

    err = L(u, n, u);
    if(err == 0) {
        BN_free(u);
        BN_CTX_free(ctx);
        return err;
    }

    BIGNUM *inv = BN_new();
    BN_mod_inverse(inv, u, n, ctx);

    if(BN_is_zero(inv) == 1) {
        BN_free(u);
        BN_free(inv);
        BN_CTX_free(ctx);
        return 0;
    }
    BN_copy(mi, inv);

    BN_free(u);
    BN_free(inv);
    BN_CTX_free(ctx);
    
    return err;
}

unsigned int L(BIGNUM *u, BIGNUM *n, BIGNUM *res) {
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    const BIGNUM *one = BN_value_one();

    err = BN_sub(u, u, one);
    if(err == 0) {
        BN_free(one);
        BN_CTX_free(ctx);
        return err;
    }

    BN_free(one);

    BIGNUM *rem = BN_new();
    err = BN_div(res, rem, u, n, ctx);
    if(err == 0) {
        BN_free(one);
        BN_free(rem);
        BN_CTX_free(ctx);
        return err;
    }
    
    BN_free(rem);

    return err;
}