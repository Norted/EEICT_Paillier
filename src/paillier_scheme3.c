#include <paillier_scheme3.h>

unsigned int _keychain_gen(struct Keychain *keychain);

unsigned int scheme3_generate_keypair(struct Keychain *keychain)
{
    unsigned int err = 0;
    //clock_t start, finish;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf("\t * Falied to generate CTX! (scheme 3, generate keypair)\n");
        return err;
    }

    struct Keychain keychain2 = {{""}};
    init_keychain(&keychain2);
    struct Keychain keychain1 = {{""}};
    init_keychain(&keychain1);

    BIGNUM *two = BN_new();
    BN_dec2bn(&two, "2");
    BIGNUM *lambda = BN_new();
    BIGNUM *p_sq = BN_new();
    BIGNUM *q_sq = BN_new();
    BIGNUM *chck = BN_new();
    BIGNUM *l_or_a_mul_n = BN_new();
    BIGNUM *num[] = {p_sq, q_sq};
    BIGNUM *rem[] = {keychain1.pk->g, keychain2.pk->g};

    err = _keychain_gen(&keychain1);
    if (err != 1)
    {
        printf("\t * Keychain 1 generation falied! (scheme 3, generate keypair)\n");
        goto end;
    }

    err = _keychain_gen(&keychain2);
    if (err != 1)
    {
        printf("\t * Keychain 2 generation falied! (scheme 3, generate keypair)\n");
        goto end;
    }

    BN_copy(keychain->sk.p, keychain1.sk.p);
    BN_copy(keychain->sk.q, keychain2.sk.p);
    err = BN_mul(keychain->pk->n, keychain->sk.p, keychain->sk.q, ctx);
    if (err != 1)
    {
        printf("\t * N computation falied! (scheme 3, generate keypair)\n");
        goto end;
    }
    err = BN_exp(keychain->pk->n_sq, keychain->pk->n, two, ctx);
    if (err != 1)
    {
        printf("\t * N_SQ compuatation falied! (scheme 3, generate keypair)\n");
        goto end;
    }

    err = l_or_a_computation(keychain->sk.p, keychain->sk.q, lambda);
    if (err != 1)
    {
        printf("\t * LAMBDA computation falied! (scheme 3, generate keypair)\n");
        goto end;
    }

    // Chinese Remainder Theorem
        err = BN_exp(p_sq, keychain->sk.p, two, ctx);
        if (err != 1)
        {
            printf("\t * P_SQ computation falied! (scheme 3, generate keypair)\n");
            goto end;
        }
        err = BN_exp(q_sq, keychain->sk.q, two, ctx);
        if (err != 1)
        {
            printf("\t * Q_SQ computation falied! (scheme 3, generate keypair)\n");
            goto end;
        }

        int size = sizeof(num) / sizeof(num[0]);
        err = chinese_remainder_theorem(num, rem, size, keychain->pk->g);
        if (err != 1)
        {
            printf("\t * CRT falied! (scheme 3, generate keypair)\n");
            goto end;
        }
    //

    err = BN_mul(keychain->sk.l_or_a, keychain1.sk.q, keychain2.sk.q, ctx); // TODO: divide 2 or 4
    if(err != 1)
    {
        printf("\t * ALPHA computation falied! (scheme 3, generate keypair)\n");
        goto end;
    }

    // Check if l_or_a is divisor of lambda
    err = BN_mod(chck, lambda, keychain->sk.l_or_a, ctx);
    if(err != 1 || BN_is_zero(chck) == 0)
    {
        printf("\t * ALPHA is not divisor of LAMBDA or operation failed! (scheme 3, generate keypair)\n");
        goto end;
    }

    // Check if g is the order of l_or_a*n in Z*_nsquared
    err = BN_mul(l_or_a_mul_n, keychain->sk.l_or_a, keychain->pk->n, ctx);
    if(err != 1)
    {
        printf("\t * ALPHA*N multiplication failed! (scheme 3, generate keypair)\n");
        goto end;
    }
    err = BN_mod_exp(chck, keychain->pk->g, l_or_a_mul_n, keychain->pk->n_sq, ctx);
    if (err != 1 || BN_is_one(chck) == 0)
    {
        printf("\t * G is not of order ALPHA or operation failed! (scheme 3, generate keypair)\n");
        goto end;
    }

    //start = clock();
    err = BN_mod_exp(keychain->pk->g2n, keychain->pk->g, keychain->pk->n, keychain->pk->n_sq, ctx);
    //finish = clock();
    //printf("G^N save: %f\n", (difftime(finish, start)/CLOCKS_PER_SEC)/0.001);
    if (err != 1)
    {
        printf("\t * G2N computation failed! (scheme 3, generate keypair)\n");
        goto end;
    }
    //start = clock();
    err = count_mi(keychain->sk.mi, keychain->pk->g, keychain->sk.l_or_a, keychain->pk->n_sq, keychain->pk->n);
    //finish = clock();
    //printf("MI 3 save: %f\n", (difftime(finish, start)/CLOCKS_PER_SEC)/0.001);
    if (err != 1)
    {
        printf("\t * MI computation failed! (scheme 3, generate keypair)\n");
        goto end;
    }

end:
    BN_free(two);
    BN_free(p_sq);
    BN_free(q_sq);
    BN_free(chck);
    BN_free(l_or_a_mul_n);
    BN_free(lambda);
    BN_free(ctx);
    free_keychain(&keychain1);
    free_keychain(&keychain2);

    return err;
}

unsigned int scheme3_encrypt(struct PublicKey *pk, BIGNUM *l_or_a, BIGNUM *plain, BIGNUM *cipher, BIGNUM *precomp_message, BIGNUM *precomp_noise)
{
    unsigned int err = 0;
    //clock_t start, finish;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf("\t * Falied to generate CTX! (scheme 3, encrypt)\n");
        return err;
    }
 
    BIGNUM *tmp_rnd = BN_new();

    if (BN_cmp(plain, pk->n) != -1)
    {
        printf("\t * Plaintext is bigger then the length of N! (scheme 3, encrypt)\n");
        goto end;
    }

    if (BN_is_zero(precomp_message) == 1)
    {
        err = BN_mod_exp(precomp_message, pk->g, plain, pk->n_sq, ctx);
        if(err != 1)
        {
            printf("\t * Message mod_exp operation falied! (scheme 3, encrypt)\n");
            goto end;
        }
    }

    if (BN_is_zero(precomp_noise) == 1)
    {
        //start = clock();
        err = generate_rnd(l_or_a, l_or_a, tmp_rnd, BITS / 2);
        if(err != 1)
        {
            printf("\t * Generate random falied! (scheme 3, encrypt)\n");
            goto end;
        }
        err = BN_mod_exp(precomp_noise, pk->g2n, tmp_rnd, pk->n_sq, ctx); // BOTTLENECK!!!
        //finish = clock();
        //printf("NOISE 3: %f\n", (difftime(finish, start)/CLOCKS_PER_SEC)/0.001);
        if(err != 1)
        {
            printf("\t * Noise mod_exp operation falied! (scheme 3, encrypt)\n");
            goto end;
        }
    }
    //

    err = BN_mod_mul(cipher, precomp_message, precomp_noise, pk->n_sq, ctx);
    if(err != 1)
    {
        printf("\t * Multiplication of message and noise falied! (scheme 3, encrypt)\n");
        goto end;
    }

end:
    BN_free(tmp_rnd);
    BN_CTX_free(ctx);

    return err;
}

unsigned int scheme3_decrypt(struct Keychain *keychain, BIGNUM *cipher, BIGNUM *plain)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf("\t * Falied to generate CTX! (scheme 3, decrypt)\n");
        return err;
    }

    BIGNUM *u = BN_new();

    err = BN_mod_exp(u, cipher, keychain->sk.l_or_a, keychain->pk->n_sq, ctx);
    if(err != 1)
    {
        printf("\t * Cipher mod_exp operation failed! (scheme 3, decrypt)\n");
        goto end;
    }
    err = L(u, keychain->pk->n, u, ctx);
    if(err != 1)
    {
        printf("\t * L function failed! (scheme 3, decrypt)\n");
        goto end;
    }
    err = BN_mod_mul(plain, u, keychain->sk.mi, keychain->pk->n, ctx);
    if(err != 1)
    {
        printf("\t * Cipher mod_mul operation failed! (scheme 3, decrypt)\n");
        goto end;
    }

end:
    BN_free(u);
    BN_CTX_free(ctx);

    return err;
}

// Support functions
unsigned int _keychain_gen(struct Keychain *keychain)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf("\t * Falied to generate CTX! (scheme 3, decrypt)\n");
        return err;
    }

    BIGNUM *two = BN_new();
    BN_dec2bn(&two, "2");
    BIGNUM *p_sq = BN_new();
    BIGNUM *mod = BN_new();

    err = gen_DSA_params(keychain->sk.p, keychain->sk.q, keychain->pk->g);
    if(err != 1)
    {
        printf("\t * Generate P, Q, G parameters failed! (scheme 3, _keychain generate)\n");
        goto end;
    }
    err = BN_mul(keychain->pk->n, keychain->sk.p, keychain->sk.q, ctx);
    if(err != 1)
    {
        printf("\t * N computation failed! (scheme 3, _keychain generate)\n");
        goto end;
    }
    err = BN_exp(keychain->pk->n_sq, keychain->pk->n, two, ctx);
    if(err != 1)
    {
        printf("\t * N_SQ computation failed! (scheme 3, _keychain generate)\n");
        goto end;
    }

    err = BN_exp(p_sq, keychain->sk.p, two, ctx);
    if(err != 1)
    {
        printf("\t * P_SQ computation failed! (scheme 3, _keychain generate)\n");
        goto end;
    }
    err = BN_mod_exp(mod, keychain->pk->g, keychain->pk->n, p_sq, ctx);
    if(err != 1 || BN_is_one(mod) != 1)
    {
        printf("\t * G2N mod P_SQ is not 1 or operation failed failed! (scheme 3, _keychain generate)\n");
        goto end;
    }

end:
    BN_free(p_sq);
    BN_free(two);
    BN_free(mod);
    BN_CTX_free(ctx);

    return err;
}