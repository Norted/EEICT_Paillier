#include <speed_functions.h>

int precomputation(const char *restrict file_name, struct Keychain *keychain, unsigned int range, unsigned int type)
{ // type 1 ... message, 2 ... noise, 3 ... noise scheme 3
    if (type == 1)
    {
        printf("\t * Message precomputation STARTED ... \n");
    }
    else if (type == 2)
    {
        printf("\t * Noise scheme 1 precomputation STARTED ... \n");
    }
    else if (type == 3)
    {
        printf("\t * Noise scheme 3 precomputation STARTED ... \n");
    }
    else
    {
        printf("\t * Unknown precomputation type ... (%d)\n", type);
        return 1;
    }

    unsigned int err = 0;
    FILE *file = fopen(file_name, "w");

    cJSON *json = cJSON_CreateObject();
    if (json == NULL)
    {
        goto end;
    }
    
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
    
    cJSON_AddItemToObject(json, "precomputed_values", precomp);

    if (type == 1)
    {
        printf("\t * Message precomputation DONE!\n");
    }
    else if (type == 2)
    {
        printf("\t * Noise scheme 1 precomputation DONE!\n");
    }
    else
    {
        printf("\t * Noise scheme 3 precomputation DONE!\n");
    }

    char *output = cJSON_Print(json);
    if (output == NULL)
    {
        printf("\t* Failed to print json.\n");
    }

    if(!fputs(output, file))
    {
        printf("\t * Failed to write to file %s!\n", file_name);
        return 0;
    }

end:
    cJSON_Delete(json);

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