#include <speed_functions.h>

void reduced_moduli()
{
    // LAST!!!
    return;
}

int precomputation(const char *restrict file_name, struct Keychain *keychain, unsigned int range, unsigned int type)
{ // type 1 ... message, 2 ... noise, 3 ... noise scheme 3
    printf("\tPrecomputation STARTED ... \t");

    unsigned int err = 0;
    FILE *file = fopen(file_name, "w");

    cJSON *monitor = cJSON_CreateObject();
    if (monitor == NULL)
    {
        goto end;
    }

    cJSON *keys = cJSON_CreateObject();
    if (keys == NULL)
    {
        goto end;
    }
    cJSON_AddItemToObject(monitor, "keys", keys);

    cJSON *pk_values = cJSON_CreateObject();
    if (pk_values == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(pk_values, "n", BN_bn2dec(keychain->pk->n)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(pk_values, "g2n", BN_bn2dec(keychain->pk->g2n)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(pk_values, "n_sq", BN_bn2dec(keychain->pk->n_sq)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(pk_values, "g", BN_bn2dec(keychain->pk->g)) == NULL)
    {
        goto end;
    }
    cJSON_AddItemToObject(keys, "pk", pk_values);

    cJSON *sk_values = cJSON_CreateObject();
    if (sk_values == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(sk_values, "p", BN_bn2dec(keychain->sk.p)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(sk_values, "q", BN_bn2dec(keychain->sk.q)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(sk_values, "l_or_a", BN_bn2dec(keychain->sk.l_or_a)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(sk_values, "mi", BN_bn2dec(keychain->sk.mi)) == NULL)
    {
        goto end;
    }
    cJSON_AddItemToObject(keys, "sk", sk_values);

    cJSON *precomp = cJSON_CreateArray();
    if(type == 1)
    {
        precomp = message_precomp(range, keychain->pk->g, keychain->pk->n_sq);
    }
    else if (type == 2)
    {
        precomp = noise_precomp(range, keychain->pk->n, keychain->pk->n_sq);
    }
    else
    {
        precomp = message_precomp(range, keychain->pk->g2n, keychain->pk->n_sq);
    }
    
    cJSON_AddItemToObject(monitor, "precomputed_values", precomp);

    printf("DONE\n\n");

    char *output = cJSON_Print(monitor);
    if (output == NULL)
    {
        printf("\t* Failed to print monitor.\n");
    }

    if(!fputs(output, file))
    {
        printf("\t * Failed to write to file %s!\n", file_name);
        return 0;
    }

end:
    cJSON_Delete(monitor);

    return fclose(file);
}

cJSON *message_precomp(BIGNUM *range, BIGNUM *base, BIGNUM *mod)
{
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        goto end;
    }
    BIGNUM *tmp_value = BN_new();
    BIGNUM *tmp_result = BN_new();

    cJSON *precomp = cJSON_CreateArray();
    if (precomp == NULL)
    {
        goto end;
    }

    cJSON *values = NULL;
    unsigned char string[BUFFER];
    for (int i = 1; i < range; i++)
    {
        sprintf(string, "%d", i);
        BN_dec2bn(&tmp_value, string);
        if (!BN_mod_exp(tmp_result, base, tmp_value, mod, ctx))
        {
            printf("\tPrecomputation STOPPED at %s!\n", BN_bn2dec(tmp_value));
            return -1;
        }

        values = cJSON_CreateObject();
        if (values == NULL)
        {
            goto end;
        }
        if (cJSON_AddStringToObject(values, "exp", string) == NULL)
        {
            goto end;
        }
        if (cJSON_AddStringToObject(values, "result", BN_bn2dec(tmp_result)) == NULL)
        {
            goto end;
        }

        cJSON_AddItemToArray(precomp, values);
    }

end:
    BN_free(tmp_value);
    BN_free(tmp_result);
    BN_CTX_free(ctx);

    return precomp;
}

cJSON *noise_precomp(BIGNUM *range, BIGNUM *exp_value, BIGNUM *mod)
{
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        goto end;
    }
    BIGNUM *tmp_value = BN_new();
    BIGNUM *tmp_result = BN_new();

    cJSON *precomp = cJSON_CreateArray();
    if (precomp == NULL)
    {
        goto end;
    }

    cJSON *values = NULL;
    unsigned char string[BUFFER];
    for (int i = 1; i < range; i++)
    {
        sprintf(string, "%d", i);
        BN_dec2bn(&tmp_value, string);
        if (!BN_mod_exp(tmp_result, tmp_value, exp_value, mod, ctx))
        {
            printf("\tPrecomputation STOPPED at %s!\n", BN_bn2dec(tmp_value));
            return -1;
        }

        values = cJSON_CreateObject();
        if (values == NULL)
        {
            goto end;
        }
        if (cJSON_AddStringToObject(values, "exp", string) == NULL)
        {
            goto end;
        }
        if (cJSON_AddStringToObject(values, "result", BN_bn2dec(tmp_result)) == NULL)
        {
            goto end;
        }

        cJSON_AddItemToArray(precomp, values);
    }

end:
    BN_free(tmp_value);
    BN_free(tmp_result);
    BN_CTX_free(ctx);

    return precomp;
}