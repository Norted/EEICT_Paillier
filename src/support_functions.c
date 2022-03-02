#include <support_functions.h>

unsigned int gen_pqg_params(BIGNUM *p, BIGNUM *q, BIGNUM *l_or_a, struct PublicKey *pk)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;

    BIGNUM *p_sub = BN_new();
    BIGNUM *q_sub = BN_new();
    BIGNUM *pq_sub = BN_new();
    BIGNUM *tmp_gcd = BN_new();
    unsigned int i = 0;

    for (i; i < MAXITER; i++)
    {
        err += BN_generate_prime_ex2(p, BITS, 1, NULL, NULL, NULL, ctx);
        err += BN_generate_prime_ex2(q, BITS, 1, NULL, NULL, NULL, ctx);
        err += BN_mul(pk->n, p, q, ctx);

        err += BN_sub(p_sub, p, BN_value_one());
        err += BN_sub(q_sub, q, BN_value_one());
        err += BN_mul(pq_sub, p_sub, q_sub, ctx);

        err += BN_gcd(tmp_gcd, pk->n, pq_sub, ctx);
        if (BN_is_one(tmp_gcd) == 1)
            break;
        err -= 7;
    }

    if (i == MAXITER)
    {
        printf("\t * MAXITER! P, Q not generated!\n");
        goto end;
    }

    const BIGNUM *two = BN_new();
    BN_dec2bn(&two, "2");
    err += BN_exp(pk->n_sq, pk->n, two, ctx);
    BN_free(two);

    err += l_or_a_computation(p, q, l_or_a);

    BN_dec2bn(&pk->g2n, "0");

    i = 0;
    BIGNUM *tmp_g = BN_new();
    BIGNUM *tmp_u = BN_new();
    for (i; i < MAXITER; i++)
    {
        err += BN_rand_range(tmp_g, pk->n_sq);
        err += BN_gcd(tmp_gcd, tmp_g, pk->n_sq, ctx);
        if (BN_is_one(tmp_gcd) != 1)
        {
            err -= 2;
            continue;
        }

        err += BN_mod_exp(tmp_u, tmp_g, l_or_a, pk->n_sq, ctx);
        err += L(tmp_u, pk->n, tmp_u, ctx);
        err += BN_gcd(tmp_gcd, tmp_u, pk->n, ctx);
        if (BN_is_one(tmp_gcd) == 1)
        {
            BN_copy(pk->g, tmp_g);
            break;
        }
        err -= 5;
    }

end:
    BN_free(p_sub);
    BN_free(q_sub);
    BN_free(pq_sub);
    BN_free(tmp_g);
    BN_free(tmp_gcd);
    BN_free(tmp_u);
    BN_CTX_free(ctx);

    if (i == MAXITER)
    {
        printf("\t * MAXITER! G not found!\n");
        return 0;
    }

    if (err != 14)
        return 0;
    return 1;
}

unsigned int gen_DSA_params(BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    unsigned int err = 0;
    const DSA *dsa = DSA_new();
    BIGNUM *dsa_p = BN_new();
    BIGNUM *dsa_q = BN_new();
    BIGNUM *dsa_g = BN_new();

    err += DSA_generate_parameters_ex(dsa, BITS * 2, NULL, 0, NULL, NULL, NULL);
    DSA_get0_pqg(dsa, &dsa_p, &dsa_q, &dsa_g);

    BN_copy(p, dsa_p);
    BN_copy(q, dsa_q);
    BN_copy(g, dsa_g);

    DSA_free(dsa);

    if (err != 1)
        return 0;
    return 1;
}

unsigned int lcm(BIGNUM *a, BIGNUM *b, BIGNUM *res)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;

    BIGNUM *bn_mul = BN_new();
    err = BN_mul(bn_mul, a, b, ctx);
    if (err == 0)
    {
        goto end;
    }

    BIGNUM *bn_gcd = BN_new();
    err = BN_gcd(bn_gcd, a, b, ctx);
    if (err == 0)
    {
        goto end;
    }

    BIGNUM *bn_rem = BN_new();
    err = BN_div(res, bn_rem, bn_mul, bn_gcd, ctx);

end:
    BN_free(bn_mul);
    BN_free(bn_gcd);
    BN_free(bn_rem);
    BN_CTX_free(ctx);

    return err;
}

unsigned int count_mi(BIGNUM *mi, BIGNUM *g, BIGNUM *l_or_a, BIGNUM *n_sq, BIGNUM *n)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf("\t * Failed to generate CTX!\n");
        return 0;
    }

    BIGNUM *u = BN_new();

    err = BN_mod_exp(u, g, l_or_a, n_sq, ctx);
    if (err == 0)
    {
        goto end;
    }

    err = L(u, n, u, ctx);
    if (err == 0)
    {
        goto end;
    }

    BIGNUM *inv = BN_new();
    BN_mod_inverse(inv, u, n, ctx);
    BN_copy(mi, inv);

end:
    BN_free(u);
    BN_free(inv);
    BN_CTX_free(ctx);

    return err;
}

unsigned int L(BIGNUM *u, BIGNUM *n, BIGNUM *res, BN_CTX *ctx)
{
    unsigned int err = 0;
    if (!ctx)
        return 0;

    err = BN_sub(u, u, BN_value_one());
    if (err == 0)
    {
        goto end;
    }

    BIGNUM *rem = BN_new();
    err = BN_div(res, rem, u, n, ctx);
    if (err == 0)
    {
        goto end;
    }

end:
    BN_free(rem);

    return err;
}

unsigned int l_or_a_computation(BIGNUM *p, BIGNUM *q, BIGNUM *l_or_a)
{
    unsigned int err = 0;
    BIGNUM *p_sub = BN_new();
    BIGNUM *q_sub = BN_new();
    err += BN_sub(p_sub, p, BN_value_one());
    err += BN_sub(q_sub, q, BN_value_one());
    err += lcm(p_sub, q_sub, l_or_a);

    BN_free(p_sub);
    BN_free(q_sub);

    if (err != 3)
        return 0;
    return 1;
}

unsigned int generate_rnd(BIGNUM *range, BIGNUM *gcd_chck, BIGNUM *random, unsigned int strength)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
    {
        printf("\t * Failed to generate CTX!\n");
        return 0;
    }

    BIGNUM *tmp_gcd = BN_new();
    int i = 0;
    for(i; i < MAXITER; i++) {
        err += BN_rand_range_ex(random, range, strength, ctx);
        err += BN_gcd(tmp_gcd, random, gcd_chck, ctx);
        if (BN_is_one(tmp_gcd) == 1 && BN_is_zero(random) == 0 && BN_cmp(random, range) == -1 && err == 2)
            break;
        err -= 2;
    }
        
    if(BN_is_zero(random) == 1 || i == MAXITER) {
        printf("\tRND fail\tRND: %s, I: %d\n", BN_bn2dec(random), i);
        return 0;
    }

    if(err != 2)
        return 0;
    return 1;
}

unsigned int chinese_remainder_theorem(BIGNUM *num[], BIGNUM *rem[], int size, BIGNUM *result)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;

    BIGNUM *prod = BN_new();
    BN_dec2bn(&prod, "1");

    int i;
    for (i = 0; i < size; i++)
        err += BN_mul(prod, num[i], prod, ctx);

    BIGNUM *tmp_inv = BN_new();
    BIGNUM *tmp_prod = BN_new();
    BIGNUM *tmp_div = BN_new();

    for (i = 0; i < size; i++)
    {
        err += BN_div(tmp_div, NULL, prod, num[i], ctx);
        BN_mod_inverse(tmp_inv, tmp_div, num[i], ctx);
        err += BN_mul(tmp_prod, rem[i], tmp_inv, ctx);
        err += BN_mul(tmp_prod, tmp_prod, tmp_div, ctx);
        err += BN_add(result, result, tmp_prod);
    }

    err += BN_nnmod(result, result, prod, ctx);

    BN_free(prod);
    BN_free(tmp_inv);
    BN_free(tmp_prod);
    BN_free(tmp_div);
    BN_CTX_free(ctx);

    if (err != (unsigned int)(5 * size) + 1)
        return 0;
    return 1;
}

void init_keychain(struct Keychain *keychain) {
    keychain->pk = malloc(sizeof(struct PublicKey));
    keychain->pk->g = BN_new();
    keychain->pk->n = BN_new();
    keychain->pk->g2n = BN_new();
    keychain->pk->n_sq = BN_new();
    keychain->sk.l_or_a = BN_new();
    keychain->sk.mi = BN_new();
    keychain->sk.p = BN_new();
    keychain->sk.q = BN_new();

    return;
}

void free_keychain(struct Keychain *keychain) {
    BN_free(keychain->pk->g);
    BN_free(keychain->pk->n);
    BN_free(keychain->pk->g2n);
    BN_free(keychain->pk->n_sq);
    free(keychain->pk);
    BN_free(keychain->sk.l_or_a);
    BN_free(keychain->sk.mi);
    BN_free(keychain->sk.p);
    BN_free(keychain->sk.q);

    return;
}

cJSON *parse_JSON(const char *restrict file_name)
{
    cJSON *json = cJSON_CreateObject();
    FILE *file = fopen(file_name, "r");
    if (file == NULL)
    {
        printf("\t * Opening the file %s failed!\n", file_name);
        return NULL;
    }

    fseek(file, 0L, SEEK_END);
    long fileSize = ftell(file);
    // printf("\t * File size: %lu\n", fileSize);
    fseek(file, 0, SEEK_SET);

    char *jsonStr = (char *)malloc(sizeof(char) * fileSize + 1); // Allocate memory that matches the file size
    memset(jsonStr, 0, fileSize + 1);

    int size = fread(jsonStr, sizeof(char), fileSize, file); // Read json string in file
    if (size == 0)
    {
        printf("\t * Failed to read the file %s!\n", file_name);
        fclose(file);
        return 0;
    }
    // printf("%s", jsonStr);

    json = cJSON_Parse(jsonStr);
    if (json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            printf("\t * Error before: %s\n", error_ptr);
        }
    }

    /* unsigned char *str = NULL;
    str = cJSON_Print(json);
    printf("%s\n", str); */

    fclose(file);
    return json;
}

unsigned int find_value(cJSON *json, BIGNUM *search, BIGNUM *result)
{
    unsigned int err = 0;
    cJSON *values = NULL;
    cJSON *value = NULL;
    unsigned char *str = NULL;
    unsigned char *search_str = BN_bn2dec(search);
    values = cJSON_GetObjectItemCaseSensitive(json, "precomputed_values");
    cJSON_ArrayForEach(value, values)
    {
        str = cJSON_GetObjectItemCaseSensitive(value, "exp")->valuestring;
        if (strcmp(search_str, str) == 0)
        {
            BN_dec2bn(&result, cJSON_GetObjectItemCaseSensitive(value, "result")->valuestring);
            err = 1;
            break;
        }
    }
    return err;
}

void read_keys(const char * restrict file_name, struct Keychain *keychain)
{
    unsigned int err = 0;
    cJSON *json = cJSON_CreateObject();
    json = parse_JSON(file_name);

    cJSON *keys = NULL;
    cJSON *pk = NULL;
    cJSON *sk = NULL;
    cJSON *value = NULL;
    keys = cJSON_GetObjectItemCaseSensitive(json, "keys");
    pk = cJSON_GetObjectItemCaseSensitive(keys, "pk");
    sk = cJSON_GetObjectItemCaseSensitive(keys, "sk");
    
    BN_dec2bn(&keychain->pk->g2n, cJSON_GetObjectItemCaseSensitive(pk, "g2n")->valuestring);
    BN_dec2bn(&keychain->pk->g, cJSON_GetObjectItemCaseSensitive(pk, "g")->valuestring);
    BN_dec2bn(&keychain->pk->n, cJSON_GetObjectItemCaseSensitive(pk, "n")->valuestring);
    BN_dec2bn(&keychain->pk->n_sq, cJSON_GetObjectItemCaseSensitive(pk, "n_sq")->valuestring);

    BN_dec2bn(&keychain->sk.l_or_a, cJSON_GetObjectItemCaseSensitive(sk, "l_or_a")->valuestring);
    BN_dec2bn(&keychain->sk.mi, cJSON_GetObjectItemCaseSensitive(sk, "mi")->valuestring);
    BN_dec2bn(&keychain->sk.p, cJSON_GetObjectItemCaseSensitive(sk, "p")->valuestring);
    BN_dec2bn(&keychain->sk.q, cJSON_GetObjectItemCaseSensitive(sk, "q")->valuestring);

    cJSON_free(json);
    return;
}