#include <paillier_scheme1.h>

unsigned int scheme1_generate_keypair(struct Keychain_scheme1 *keyring) {
    unsigned int err = 0;

    err += gen_pqg_params(keyring->sk.p, keyring->sk.q, keyring->pk.g);

    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    err += BN_mul(keyring->pk.n, keyring->sk.p, keyring->sk.q, ctx);
    err += BN_exp(keyring->pk.n_sq, keyring->pk.n, "2", ctx);
    err += lcm(keyring->sk.p, keyring->sk.q, keyring->sk.lambda);
    err += count_mi(keyring->sk.mi, keyring->pk.g, keyring->sk.lambda, keyring->pk.n_sq, keyring->pk.n);

    if(err != 5)
        return 0;
    
    return 1;

    /* OLD CODE
        err += bn_genPrime(keyring->sk.p, BITS);
        err += bn_genPrime(keyring->sk.q, BITS);
        err += bn_mul(keyring->sk.p, keyring->sk.q, keyring->pk.n);
        
        err += bn_exp(keyring->pk.n, "2", keyring->pk.n_sq);
        random_str_num_in_range(keyring->pk.g, atoi(keyring->pk.n_sq), 1);

        err += lcm(keyring->sk.p, keyring->sk.q, keyring->sk.lambda);
        unsigned char p_1[BUFFER];
        err += bn_modexp(keyring->pk.g, keyring->sk.lambda, keyring->pk.n_sq, p_1);
        unsigned char p_2[BUFFER];
        err += bn_sub(p_1, "1", p_2);
        unsigned char p_3[BUFFER];
        unsigned char rem[BUFFER];
        err += bn_div(p_2, keyring->pk.n, p_3, rem);
        err += bn_modinverse(p_3, keyring->pk.n, keyring->sk.mi);

        if(err != 9)
            return 0;

        return 1;
    */
}

unsigned int scheme1_encrypt(struct PublicKey pk, BIGNUM *plain, BIGNUM *cipher) {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    if(BN_cmp(plain, pk.n) != -1)
        return 0;
    
    unsigned int stop = 0;
    unsigned int err = 0;
    BIGNUM *rnd = BN_new();
    BIGNUM *gcd = BN_new();

    while (stop < MAXITER) {
        err += BN_rand_range_ex(rnd, pk.n, BITS, ctx);
        err += BN_gcd(gcd, rnd, pk.n, ctx);
        if (BN_cmp(gcd, "1") == 0 && BN_cmp(rnd, "0") == 1 && BN_cmp(rnd, pk.n) == -1 && err == 2)
            break;
        stop ++;
        err -= 2;
    }

    BN_free(gcd);
        
    if(BN_cmp(rnd, "0") == 0 || stop == MAXITER)
        return 0;

    BIGNUM *c_1 = BN_new();
    err += BN_mod_exp(c_1, pk.g, plain, pk.n_sq, ctx);
    BIGNUM *c_2 = BN_new();
    err += BN_mod_exp(c_2, rnd, pk.n, pk.n_sq, ctx);
    err += BN_mod_mul(cipher, c_1, c_2, pk.n_sq, ctx);

    BN_free(rnd);
    BN_free(c_1);
    BN_free(c_2);
    BN_CTX_free(ctx);

    if(err != 5)
        return 0;
    
    return 1;
    
    /* OLD CODE
        if(bn_cmp(plain, pk.n) != -1)
            return 0;
        
        int stop = 0;
        unsigned int err = 0;
        unsigned char r[BUFFER];
        unsigned char *rnd = malloc(sizeof(int));
        unsigned char gcd[sizeof(int)];
        
        while (stop < MAXITER) {
            random_str_num(rnd);
            bn_mod(rnd, pk.n, r);
            bn_gcd(r, pk.n, gcd);
            if (bn_cmp(gcd, "1") == 0 && bn_cmp(r, "0") == 1 && bn_cmp(r, pk.n) == -1)
                break;
            stop ++;
        }
        err += 2;
        free(rnd);
        
        if(bn_cmp(r, "0") == 0 || stop == MAXITER) {
            return 0;
        }

        unsigned char c_1[BUFFER];
        err += bn_modexp(pk.g, plain, pk.n_sq, c_1);
        unsigned char c_2[BUFFER];
        err += bn_modexp(r, pk.n, pk.n_sq, c_2);
        err += bn_modmul(c_1, c_2, pk.n_sq, cipher);

        if(err != 5)
            return 0;
        
        return 1;
    */
}

unsigned int scheme1_decrypt(struct Keychain_scheme1 *keyring, BIGNUM *cipher, BIGNUM *plain) {
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    BIGNUM *p_1 = BN_new();
    BIGNUM *p_2 = BN_new();
    BIGNUM *p_3 = BN_new();
    BIGNUM *rem = BN_new();
    BIGNUM *one = BN_value_one();

    err += BN_mod_exp(p_1, cipher, keyring->sk.lambda, keyring->pk.n_sq, ctx);
    err += BN_sub(p_2, p_1, one);
    err += BN_div(p_3, rem, p_2, keyring->pk.n, ctx);
    err += BN_mod_mul(plain, p_3, keyring->sk.mi, keyring->pk.n, ctx);

    BN_free(p_1);
    BN_free(p_2);
    BN_free(p_3);
    BN_free(rem);
    BN_free(one);

    if(err != 4)
        return 0;
    
    return 1;

    /* OLD CODE
        unsigned char p_1[BUFFER];
        err += bn_modexp(cipher, keyring->sk.lambda, keyring->pk.n_sq, p_1);
        unsigned char p_2[BUFFER];
        err += bn_sub(p_1, "1", p_2);
        unsigned char p_3[BUFFER];
        unsigned char rem[BUFFER];
        err += bn_div(p_2, keyring->pk.n, p_3, rem);
        err += bn_modmul(p_3, keyring->sk.mi, keyring->pk.n, plain);

        if(err != 4)
            return 0;
        
        return 1;
    */
}