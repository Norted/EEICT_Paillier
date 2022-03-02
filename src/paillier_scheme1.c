#include <paillier_scheme1.h>

unsigned int scheme1_generate_keypair(struct Keychain *keychain)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;

    err += gen_pqg_params(keychain->sk.p, keychain->sk.q, keychain->sk.l_or_a, keychain->pk);
    err += count_mi(keychain->sk.mi, keychain->pk->g, keychain->sk.l_or_a, keychain->pk->n_sq, keychain->pk->n);

    if (err != 2)
        return 0;

    return 1;
}

unsigned int scheme1_encrypt(struct PublicKey *pk, BIGNUM *plain, BIGNUM *cipher, BIGNUM *precomp_message, BIGNUM *precomp_noise)
{
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;

    if (BN_cmp(plain, pk->n) != -1)
        return 0;

    unsigned int err = 0;
    BIGNUM *tmp_rnd = BN_new();


    if (BN_is_zero(precomp_message) == 1)
    {
        err += BN_mod_exp(precomp_message, pk->g, plain, pk->n_sq, ctx);
    }
    else
        err += 1;
    
    if (BN_is_zero(precomp_noise) == 1)
    {
        err += generate_rnd(pk->n, pk->n, tmp_rnd, BITS);
        err += BN_mod_exp(precomp_noise, tmp_rnd, pk->n, pk->n_sq, ctx);
    }
    else
        err += 2;
    
    err += BN_mod_mul(cipher, precomp_message, precomp_noise, pk->n_sq, ctx);

    BN_free(tmp_rnd);
    BN_CTX_free(ctx);

    if (err != 4)
        return 0;

    return 1;
}

unsigned int scheme1_decrypt(struct Keychain *keychain, BIGNUM *cipher, BIGNUM *plain)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;

    BIGNUM *u = BN_new();

    err += BN_mod_exp(u, cipher, keychain->sk.l_or_a, keychain->pk->n_sq, ctx);
    err += L(u, keychain->pk->n, u, ctx);
    err += BN_mod_mul(plain, u, keychain->sk.mi, keychain->pk->n, ctx);

    BN_free(u);

    if (err != 3)
        return 0;

    return 1;
}