#include <speed_functions.h>

void reduced_moduli()
{
    // LAST!!!
    return;
}

int precomputation(unsigned char *file_name, struct Keychain *keychain)
{
    unsigned int err = 0;
    BIGNUM *tmp_value = BN_new();
    BIGNUM *tmp_result = BN_new();

    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        return 0;
    }
    
    printf("Precomputation STARTED ... \t");

    FILE *file = fopen(file_name, "w");

    fprintf(file, "{\n\t\"keys\": [\"pk\": {\"n\": \"%s\", \"g2n\": \"%s\", \"n_sq\": \"%s\", \"g\": \"%s\"},"
                  "\"sk\": {\"p\": \"%s\", \"q\": \"%s\", \"l_or_a\": \"%s\", \"mi\": \"%s\"}], ",
            BN_bn2dec(keychain->pk->n), BN_bn2dec(keychain->pk->g2n), BN_bn2dec(keychain->pk->n_sq), BN_bn2dec(keychain->pk->g),
            BN_bn2dec(keychain->sk.p), BN_bn2dec(keychain->sk.q), BN_bn2dec(keychain->sk.l_or_a), BN_bn2dec(keychain->sk.mi));

    fprintf(file, "\"precomputed_values\": {");
    unsigned int size = RANGE;
    unsigned char string[BUFFER];
    for (int i = 1; i < size; i++)
    {
        sprintf(string, "%d", i);
        BN_dec2bn(&tmp_value, string);
        if (!BN_mod_exp(tmp_result, keychain->pk->g, tmp_value, keychain->pk->n_sq, ctx))
        {
            printf("Precomputation STOPPED at %s!\n", BN_bn2dec(tmp_value));
            return -1;
        }
        fprintf(file, "\"%s\": \"%s\",", BN_bn2dec(tmp_value), BN_bn2dec(tmp_result));
    }
    fprintf(file, "}");
    printf("DONE\n\n");

    BN_free(tmp_result);
    BN_free(tmp_value);
    BN_CTX_free(ctx);

    return fclose(file);
}