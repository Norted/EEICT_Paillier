#include <paillier_scheme1.h>

unsigned int scheme1_generate_keypair(struct Keychain_scheme1 *keyring) {
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;

    BIGNUM *two = BN_new();
    BN_dec2bn(&two, "2");

    err += gen_pqg_params(keyring->sk.p, keyring->sk.q, keyring->sk.lambda, keyring->pk);
    err += count_mi(keyring->sk.mi, keyring->pk->g, keyring->sk.lambda, keyring->pk->n_sq, keyring->pk->n);

    BN_free(two);
    if(err != 2)
        return 0;
    
    return 1;
}

unsigned int scheme1_encrypt(struct PublicKey *pk, BIGNUM *plain, BIGNUM *cipher) {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    if(BN_cmp(plain, pk->n) != -1)
        return 0;
    
    unsigned int stop = 0;
    unsigned int err = 0;
    BIGNUM *rnd = BN_new();
    BIGNUM *tmp_gcd = BN_new();

    while (stop < MAXITER) {
        err += BN_rand_range_ex(rnd, pk->n, BITS, ctx);
        err += BN_gcd(tmp_gcd, rnd, pk->n, ctx);
        if (BN_is_one(tmp_gcd) == 1 && BN_is_zero(rnd) == 0 && BN_cmp(rnd, pk->n) == -1 && err == 2)
            break;
        stop ++;
        err -= 2;
    }
    BN_free(tmp_gcd);
        
    if(BN_is_zero(rnd) == 1 || stop == MAXITER)
        return 0;

    BIGNUM *c_1 = BN_new();
    BIGNUM *c_2 = BN_new();
    err += BN_mod_exp(c_1, pk->g, plain, pk->n_sq, ctx);
    err += BN_mod_exp(c_2, rnd, pk->n, pk->n_sq, ctx);
    err += BN_mod_mul(cipher, c_1, c_2, pk->n_sq, ctx);

    BN_free(rnd);
    BN_free(c_1);
    BN_free(c_2);
    BN_CTX_free(ctx);

    if(err != 5)
        return 0;
    
    return 1;
}

unsigned int scheme1_decrypt(struct Keychain_scheme1 *keyring, BIGNUM *cipher, BIGNUM *plain) {
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    BIGNUM *u = BN_new();
    BIGNUM *p_2 = BN_new();
    BIGNUM *p_3 = BN_new();
    BIGNUM *rem = BN_new();
    BIGNUM *one = BN_value_one();

    err += BN_mod_exp(u, cipher, keyring->sk.lambda, keyring->pk->n_sq, ctx);
    err += L(u, keyring->pk->n, u);
    err += BN_mod_mul(plain, u, keyring->sk.mi, keyring->pk->n, ctx);

    BN_free(u);

    if(err != 3)
        return 0;
    
    return 1;
}

void scheme1_init_keychain(struct Keychain_scheme1 *keychain) {
    keychain->pk = malloc(sizeof(struct PublicKey));
    keychain->pk->g = BN_new();
    keychain->pk->n = BN_new();
    keychain->pk->n_sq = BN_new();
    keychain->sk.lambda = BN_new();
    keychain->sk.mi = BN_new();
    keychain->sk.p = BN_new();
    keychain->sk.q = BN_new();

    return;
}

void scheme1_free_keychain(struct Keychain_scheme1 *keychain) {
    BN_free(keychain->pk->g);
    BN_free(keychain->pk->n);
    BN_free(keychain->pk->n_sq);
    free(keychain->pk);
    BN_free(keychain->sk.lambda);
    BN_free(keychain->sk.mi);
    BN_free(keychain->sk.p);
    BN_free(keychain->sk.q);

    return;
}