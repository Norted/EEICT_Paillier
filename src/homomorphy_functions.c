#include <homomorphy_functions.h>

unsigned int add(struct PublicKey *pk, BIGNUM *a, BIGNUM *b, BIGNUM *res)
{
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;
    // Add one encrypted unsigned long longeger to another
    unsigned int err = BN_mod_mul(res, a, b, pk->n_sq, ctx);

    BN_CTX_free(ctx);
    return err;
}

unsigned int add_const(struct PublicKey *pk, BIGNUM *a, BIGNUM *n, BIGNUM *res)
{
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;
    // Add constant n to an encrypted unsigned long longeger
    unsigned int err = 0;
    BIGNUM *p_1 = BN_new();
    err += BN_mod_exp(p_1, pk->g, n, pk->n_sq, ctx);
    err += BN_mod_mul(res, a, p_1, pk->n_sq, ctx);

    BN_free(p_1);
    BN_CTX_free(ctx);
    if (err != 2)
        return 0;
    return 1;
}

unsigned int mul_const(struct PublicKey *pk, BIGNUM *a, BIGNUM *n, BIGNUM *res)
{
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;
    // Multiplies an encrypted unsigned long longeger by a constant
    unsigned int err = BN_mod_exp(res, a, n, pk->n_sq, ctx);

    BN_CTX_free(ctx);
    return err;
}