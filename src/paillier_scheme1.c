#include <paillier_scheme1.h>

unsigned int scheme1_generate_keypair(struct Keychain *keychain) {
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;

    BIGNUM *two = BN_new();
    BN_dec2bn(&two, "2");

    err += gen_pqg_params(keychain->sk.p, keychain->sk.q, keychain->sk.l_or_a, keychain->pk);
    err += count_mi(keychain->sk.mi, keychain->pk->g, keychain->sk.l_or_a, keychain->pk->n_sq, keychain->pk->n);

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
    
    unsigned int err = 0;
    unsigned int i = 0;
    BIGNUM *rnd = BN_new();
    BIGNUM *tmp_gcd = BN_new();

    for(i; i < MAXITER; i++) {
        err += BN_rand_range_ex(rnd, pk->n, BITS, ctx);
        err += BN_gcd(tmp_gcd, rnd, pk->n, ctx);
        if (BN_is_one(tmp_gcd) == 1 && BN_is_zero(rnd) == 0 && BN_cmp(rnd, pk->n) == -1 && err == 2)
            break;
        err -= 2;
    }
    BN_free(tmp_gcd);
        
    if(BN_is_zero(rnd) == 1 || i == MAXITER)
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

unsigned int scheme1_decrypt(struct Keychain *keychain, BIGNUM *cipher, BIGNUM *plain) {
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

void scheme1_init_keychain(struct Keychain *keychain) {
    keychain->pk = malloc(sizeof(struct PublicKey));
    keychain->pk->g = BN_new();
    keychain->pk->n = BN_new();
    keychain->pk->n_sq = BN_new();
    keychain->sk.l_or_a = BN_new();
    keychain->sk.mi = BN_new();
    keychain->sk.p = BN_new();
    keychain->sk.q = BN_new();

    return;
}

void scheme1_free_keychain(struct Keychain *keychain) {
    BN_free(keychain->pk->g);
    BN_free(keychain->pk->n);
    BN_free(keychain->pk->n_sq);
    free(keychain->pk);
    BN_free(keychain->sk.l_or_a);
    BN_free(keychain->sk.mi);
    BN_free(keychain->sk.p);
    BN_free(keychain->sk.q);

    return;
}