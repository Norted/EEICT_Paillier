#include <openssl_bn.h>

unsigned int bn_add(unsigned char *a, unsigned char *b, unsigned char *res) {
    BIGNUM *bn_a = BN_new();
    BIGNUM *bn_b = BN_new();
    BIGNUM *bn_res = BN_new();
    BN_dec2bn(&bn_a, a);
    BN_dec2bn(&bn_b, b);

    unsigned int err = BN_add(bn_res, bn_a, bn_b);
    if(err != 0)
        strcpy(res, BN_bn2dec(bn_res));
    
    BN_free(bn_a);
    BN_free(bn_b);
    BN_free(bn_res);
    
    return err;
}

unsigned int bn_sub(unsigned char *a, unsigned char *b, unsigned char *res) {
    BIGNUM *bn_a = BN_new();
    BIGNUM *bn_b = BN_new();
    BIGNUM *bn_res = BN_new();
    BN_dec2bn(&bn_a, a);
    BN_dec2bn(&bn_b, b);

    unsigned int err = BN_sub(bn_res, bn_a, bn_b);
    if(err != 0)
        strcpy(res, BN_bn2dec(bn_res));
    
    BN_free(bn_a);
    BN_free(bn_b);
    BN_free(bn_res);
    return err;
}

unsigned int bn_mul(unsigned char *a, unsigned char *b, unsigned char *res) {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    BIGNUM *bn_a = BN_new();
    BIGNUM *bn_b = BN_new();
    BIGNUM *bn_res = BN_new();
    BN_dec2bn(&bn_a, a);
    BN_dec2bn(&bn_b, b);

    unsigned int err = BN_mul(bn_res, bn_a, bn_b, ctx);
    if(err != 0)
        strcpy(res, BN_bn2dec(bn_res));
    
    BN_free(bn_a);
    BN_free(bn_b);
    BN_free(bn_res);
    BN_CTX_free(ctx);
    return err;
}

unsigned int bn_div(unsigned char *a, unsigned char *b, unsigned char *res, unsigned char * rem) {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    BIGNUM *bn_a = BN_new();
    BIGNUM *bn_b = BN_new();
    BIGNUM *bn_res = BN_new();
    BIGNUM *bn_rem = BN_new();
    BN_dec2bn(&bn_a, a);
    BN_dec2bn(&bn_b, b);

    unsigned int err = BN_div(bn_res, bn_rem, bn_a, bn_b, ctx);
    if(err != 0) {
        strcpy(res, BN_bn2dec(bn_res));
        strcpy(rem, BN_bn2dec(bn_rem));
    }

    BN_free(bn_a);
    BN_free(bn_b);
    BN_free(bn_res);
    BN_free(bn_rem);
    BN_CTX_free(ctx);
    return err;
}

unsigned int bn_exp(unsigned char *base, unsigned char *exp, unsigned char *res) {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    BIGNUM *bn_base = BN_new();
    BIGNUM *bn_exp = BN_new();
    BIGNUM *bn_res = BN_new();
    BN_dec2bn(&bn_base, base);
    BN_dec2bn(&bn_exp, exp);

    unsigned int err = BN_exp(bn_res, bn_base, bn_exp, ctx);
    if(err != 0)
        strcpy(res, BN_bn2dec(bn_res));
    
    BN_free(bn_base);
    BN_free(bn_exp);
    BN_free(bn_res);
    BN_CTX_free(ctx);
    return err;
}

unsigned int bn_mod(unsigned char *a, unsigned char *mod, unsigned char *res) {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    BIGNUM *bn_a = BN_new();
    BIGNUM *bn_mod = BN_new();
    BIGNUM *bn_res = BN_new();
    BN_dec2bn(&bn_a, a);
    BN_dec2bn(&bn_mod, mod);

    unsigned int err = BN_nnmod(bn_res, bn_a, bn_mod, ctx);
    if(err != 0)
        strcpy(res, BN_bn2dec(bn_res));
    
    BN_free(bn_a);
    BN_free(bn_mod);
    BN_free(bn_res);
    BN_CTX_free(ctx);
    return err;
}

unsigned int bn_modadd(unsigned char *a, unsigned char *b, unsigned char *mod, unsigned char *res) {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    BIGNUM *bn_a = BN_new();
    BIGNUM *bn_b = BN_new();
    BIGNUM *bn_mod = BN_new();
    BIGNUM *bn_res = BN_new();
    BN_dec2bn(&bn_a, a);
    BN_dec2bn(&bn_b, b);
    BN_dec2bn(&bn_mod, mod);

    unsigned int err = BN_mod_add(bn_res, bn_a, bn_b, bn_mod, ctx);
    if(err != 0)
        strcpy(res, BN_bn2dec(bn_res));
    
    BN_free(bn_a);
    BN_free(bn_b);
    BN_free(bn_mod);
    BN_free(bn_res);
    BN_CTX_free(ctx);
    return err;
}

unsigned int bn_modsub(unsigned char *a, unsigned char *b, unsigned char *mod, unsigned char *res) {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    BIGNUM *bn_a = BN_new();
    BIGNUM *bn_b = BN_new();
    BIGNUM *bn_mod = BN_new();
    BIGNUM *bn_res = BN_new();
    BN_dec2bn(&bn_a, a);
    BN_dec2bn(&bn_b, b);
    BN_dec2bn(&bn_mod, mod);

    unsigned int err = BN_mod_sub(bn_res, bn_a, bn_b, bn_mod, ctx);
    if(err != 0)
        strcpy(res, BN_bn2dec(bn_res));
    
    BN_free(bn_a);
    BN_free(bn_b);
    BN_free(bn_mod);
    BN_free(bn_res);
    BN_CTX_free(ctx);
    return err;
}

unsigned int bn_modmul(unsigned char *a, unsigned char *b, unsigned char *mod, unsigned char *res) {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    BIGNUM *bn_a = BN_new();
    BIGNUM *bn_b = BN_new();
    BIGNUM *bn_mod = BN_new();
    BIGNUM *bn_res = BN_new();
    BN_dec2bn(&bn_a, a);
    BN_dec2bn(&bn_b, b);
    BN_dec2bn(&bn_mod, mod);

    unsigned int err = BN_mod_mul(bn_res, bn_a, bn_b, bn_mod, ctx);
    if(err != 0)
        strcpy(res, BN_bn2dec(bn_res));
    
    BN_free(bn_a);
    BN_free(bn_b);
    BN_free(bn_mod);
    BN_free(bn_res);
    BN_CTX_free(ctx);
    return err;
}

unsigned int bn_modexp(unsigned char *base, unsigned char *exp, unsigned char *mod, unsigned char *res) {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    BIGNUM *bn_base = BN_new();
    BIGNUM *bn_exp = BN_new();
    BIGNUM *bn_mod = BN_new();
    BIGNUM *bn_res = BN_new();
    BN_dec2bn(&bn_base, base);
    BN_dec2bn(&bn_exp, exp);
    BN_dec2bn(&bn_mod, mod);

    unsigned int err = BN_mod_exp(bn_res, bn_base, bn_exp, bn_mod, ctx);
    if(err != 0)
        strcpy(res, BN_bn2dec(bn_res));
    
    BN_free(bn_base);
    BN_free(bn_exp);
    BN_free(bn_res);
    BN_CTX_free(ctx);
    return err;
}

unsigned int bn_gcd(unsigned char *a, unsigned char *b, unsigned char *res) {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    BIGNUM *bn_a = BN_new();
    BIGNUM *bn_b = BN_new();
    BIGNUM *bn_res = BN_new();
    BN_dec2bn(&bn_a, a);
    BN_dec2bn(&bn_b, b);

    unsigned int err = BN_gcd(bn_res, bn_a, bn_b, ctx);
    if(err != 0)
        strcpy(res, BN_bn2dec(bn_res));
    
    BN_free(bn_a);
    BN_free(bn_b);
    BN_free(bn_res);
    BN_CTX_free(ctx);
    return err;
}

unsigned int bn_lcm(unsigned char *a, unsigned char *b, unsigned char *res) {
    // ((p-1) * (q-1)) / gcd((p-1), (q-1));
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    BIGNUM *bn_a = BN_new();
    BIGNUM *bn_b = BN_new();
    BIGNUM *bn_res = BN_new();
    BIGNUM *one = BN_value_one();
    BN_dec2bn(&bn_a, a);
    BN_dec2bn(&bn_b, b);

    BIGNUM *bn_sub_a = BN_new();
    BIGNUM *bn_sub_b = BN_new();

    unsigned int err = BN_sub(bn_sub_a, bn_a, one);
    if(err == 0) {
        BN_free(bn_a);
        BN_free(bn_b);
        BN_free(one);
        BN_free(bn_sub_a);
        BN_free(bn_sub_b);
        BN_free(bn_res);
        return err;
    }
    err = BN_sub(bn_sub_b, bn_b, one);
    if(err == 0) {
        BN_free(bn_a);
        BN_free(bn_b);
        BN_free(one);
        BN_free(bn_sub_a);
        BN_free(bn_sub_b);
        BN_free(bn_res);
        return err;
    }

    BIGNUM *bn_mul = BN_new();
    err = BN_mul(bn_mul, bn_sub_a, bn_sub_b, ctx);
    if(err == 0) {
        BN_free(bn_a);
        BN_free(bn_b);
        BN_free(one);
        BN_free(bn_sub_a);
        BN_free(bn_sub_b);
        BN_free(bn_mul);
        BN_free(bn_res);
        return err;
    }
    
    BIGNUM *bn_gcd = BN_new();
    err = BN_gcd(bn_gcd, bn_sub_a, bn_sub_b, ctx);
    if(err == 0) {
        BN_free(bn_a);
        BN_free(bn_b);
        BN_free(one);
        BN_free(bn_sub_a);
        BN_free(bn_sub_b);
        BN_free(bn_mul);
        BN_free(bn_gcd);
        BN_free(bn_res);
        return err;
    }
    
    BIGNUM *bn_rem = BN_new();
    err = BN_div(bn_res, bn_rem, bn_mul, bn_gcd, ctx);
    if(err != 0)
        strcpy(res, BN_bn2dec(bn_res));
    
    BN_free(bn_a);
    BN_free(bn_b);
    BN_free(one);
    BN_free(bn_sub_a);
    BN_free(bn_sub_b);
    BN_free(bn_mul);
    BN_free(bn_gcd);
    BN_free(bn_rem);
    BN_free(bn_res);

    return err;
}

unsigned int hash(unsigned char *res, unsigned char *Y, unsigned char *t_s, unsigned char *kappa) {
    unsigned char inbuf[BUFFER];
    inbuf[0] = '\0';
    for (int i = 1; i < BUFFER; i++)
        inbuf[i] = '0';
    strcat(inbuf, Y);
    strcat(inbuf, t_s);
    if(strcmp(kappa, "0") != 0)
        strcat(inbuf, kappa);

    unsigned char outbuf[SHA256_DIGEST_LENGTH];
    SHA256(inbuf, strlen(inbuf), outbuf);

    unsigned char digest[SHA256_DIGEST_LENGTH*2 + 1];
    digest[SHA256_DIGEST_LENGTH*2] = '\0';
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(&(digest[i*2]), SHA256_DIGEST_LENGTH, "%02x", (unsigned int) outbuf[i] );

    //strcpy(res, digest);
    BIGNUM *bn_hash = BN_new();
    BN_hex2bn(&bn_hash, digest);
    strcpy(res, BN_bn2dec(bn_hash));
    BN_free(bn_hash);
    
    return 1;
}

unsigned int random_str_num(unsigned char *str) {
    sprintf(str, "%d", rand());
    return 1;
}

unsigned int random_str_num_in_range(unsigned char *str, unsigned int max, unsigned int min) {
    sprintf(str, "%u", (rand() % (max - min + 1)) + min);
    return 1;
}

unsigned int bn_genPrime(unsigned char *prime, int bits) {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;

    BN_GENCB *cb = BN_GENCB_new();

    BIGNUM *bn_res = BN_new();
    BIGNUM *bn_rem = BN_new();

    unsigned char *rnd_seed = "seed";
    RAND_seed(rnd_seed, sizeof(rnd_seed));
    unsigned int err = BN_generate_prime_ex2(bn_res, bits, 1, NULL, NULL, NULL, ctx);
    if(err != 0)
        strcpy(prime, BN_bn2dec(bn_res));

    BN_free(bn_res);
    BN_free(bn_rem);
    BN_CTX_free(ctx);
    BN_GENCB_free(cb);

    return err;
}

unsigned int bn_modinverse(unsigned char *a, unsigned char *n, unsigned char *inverse) {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;

    BIGNUM *bn_inverse = BN_new();
    BIGNUM *bn_a = BN_new();
    BIGNUM *bn_n = BN_new();
    BN_dec2bn(&bn_a, a);
    BN_dec2bn(&bn_n, n);

    BN_mod_inverse(bn_inverse, bn_a, bn_n, ctx);
    strcpy(inverse, BN_bn2dec(bn_inverse));

    BN_free(bn_inverse);
    BN_free(bn_a);
    BN_free(bn_n);
    BN_CTX_free(ctx);

    return 1;
}

int bn_cmp(unsigned char *a, unsigned char *b) {
    BIGNUM *bn_a = BN_new();
    BIGNUM *bn_b = BN_new();
    BN_dec2bn(&bn_a, a);
    BN_dec2bn(&bn_b, b);

    unsigned int res = BN_cmp(bn_a, bn_b);
    // a < b    →   res == -1
    // a == b   →   res ==  0
    // a > b    →   res ==  1
    
    BN_free(bn_a);
    BN_free(bn_b);

    return res;
}

unsigned int bn_gen_params(DSA *dsa, unsigned char *p, unsigned char *q, unsigned char *g) {
    BIGNUM *bn_p = BN_new();
    BIGNUM *bn_q = BN_new();
    BIGNUM *bn_g = BN_new();

    unsigned int err = DSA_generate_parameters_ex(dsa, BUFFER, NULL, 0, NULL, NULL, NULL);
    DSA_get0_pqg(dsa, &bn_p, &bn_q, &bn_g);

    if(err != 0) {
        strcpy(p, BN_bn2dec(BN_dup(bn_p)));
        strcpy(q, BN_bn2dec(BN_dup(bn_q)));
        strcpy(g, BN_bn2dec(BN_dup(bn_g)));
    }

    return err;
}

unsigned int bn_gen_keys(DSA *dsa, unsigned char *sk, unsigned char *pk) {
    //unsigned int err = 0;
    BIGNUM *bn_sk = BN_new();
    BIGNUM *bn_pk = BN_new();

    unsigned int err = DSA_generate_key(dsa);
    DSA_get0_key(dsa, &bn_pk, &bn_sk);

    if(err != 0) {
        strcpy(sk, BN_bn2dec(BN_dup(bn_sk)));
        strcpy(pk, BN_bn2dec(BN_dup(bn_pk)));
    }

    return err;
}