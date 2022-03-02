#include <tests.h>

unsigned int scheme1_test(BIGNUM *message)
{
    printf("\n\t========= SCHEME 1 =================\n");
    unsigned int err = 0;

    BIGNUM *zero1 = BN_new();
    BN_dec2bn(&zero1, "0");
    BIGNUM *zero2 = BN_new();
    BN_dec2bn(&zero2, "0");
    BIGNUM *enc = BN_new();
    BIGNUM *dec = BN_new();

    struct Keychain keychain;
    init_keychain(&keychain);
    err += scheme1_generate_keypair(&keychain);
    printf("\t |----> ERR: %u\n\t KEYS:\n\t |--> LAMBDA: %s\n\t |--> MI: %s\n\t |--> N: %s\n\t |--> N_SQ: %s\n\t |--> G: %s\n",
           err, BN_bn2dec(keychain.sk.l_or_a), BN_bn2dec(keychain.sk.mi), BN_bn2dec(keychain.pk->n),
           BN_bn2dec(keychain.pk->n_sq), BN_bn2dec(keychain.pk->g));

    err += scheme1_encrypt(keychain.pk, message, enc, zero1, zero2);
    printf("\t |----> ENC: %s\n", BN_bn2dec(enc));

    err += scheme1_decrypt(&keychain, enc, dec);
    printf("\t |----> MESSAGE: %s\n", BN_bn2dec(message));
    printf("\t |----> DEC: %s\n", BN_bn2dec(dec));

    printf("\n\n");
    free_keychain(&keychain);
    BN_free(zero1);
    BN_free(zero2);
    BN_free(enc);
    BN_free(dec);
    return err;
}

unsigned int scheme3_test(BIGNUM *message)
{
    printf("\n\t========= SCHEME 3 ==================\n");
    unsigned int err = 0;

    BIGNUM *zero1 = BN_new();
    BN_dec2bn(&zero1, "0");
    BIGNUM *zero2 = BN_new();
    BN_dec2bn(&zero2, "0");
    BIGNUM *enc = BN_new();
    BIGNUM *dec = BN_new();

    struct Keychain keychain;
    init_keychain(&keychain);
    err += scheme3_generate_keypair(&keychain);
    printf("\t |----> ERR: %u\n\t KEYS:\n\t |--> ALPHA: %s\n\t |--> MI: %s\n\t |--> N: %s\n\t |--> N_SQ: %s\n\t |--> G: %s\n\t |--> G2N: %s\n",
           err, BN_bn2dec(keychain.sk.l_or_a), BN_bn2dec(keychain.sk.mi), BN_bn2dec(keychain.pk->n),
           BN_bn2dec(keychain.pk->n_sq), BN_bn2dec(keychain.pk->g), BN_bn2dec(keychain.pk->g2n));
    err += scheme3_encrypt(keychain.pk, keychain.sk.l_or_a, message, enc, zero1, zero2);
    printf("\t |----> ENC: %s\n", BN_bn2dec(enc));

    err += scheme3_decrypt(&keychain, enc, dec);
    printf("\t |----> MESSAGE: %s\n", BN_bn2dec(message));
    printf("\t |----> DEC: %s\n", BN_bn2dec(dec));
    if(BN_cmp(message, dec) != 0)
        return 1;
    
    printf("\n\n");
    free_keychain(&keychain);
    BN_free(zero1);
    BN_free(zero2);
    BN_free(enc);
    BN_free(dec);
    return 0; // err
}

unsigned int test_homomorphy_scheme1()
{
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;

    unsigned int err = 0;

    BIGNUM *zero1 = BN_new();
    BIGNUM *zero2 = BN_new();
    BIGNUM *message_1 = BN_new();
    BIGNUM *message_2 = BN_new();
    BIGNUM *message_sum = BN_new();
    BIGNUM *message_mul = BN_new();
    BIGNUM *cipher_1 = BN_new();
    BIGNUM *cipher_2 = BN_new();
    BIGNUM *cipher_sum_1 = BN_new();
    BIGNUM *dec_cipher_sum_1 = BN_new();
    BIGNUM *cipher_sum_2 = BN_new();
    BIGNUM *dec_cipher_sum_2 = BN_new();
    BIGNUM *cipher_mul = BN_new();
    BIGNUM *dec_cipher_mul = BN_new();

    struct Keychain keychain;
    init_keychain(&keychain);
    err = scheme1_generate_keypair(&keychain);
    if (err != 1)
    {
        printf("\t * Generate keychain failed (scheme 1, homomorphy)!\n");
        goto end;
    }

    BN_dec2bn(&zero1, "0");
    BN_dec2bn(&zero2, "0");
    BN_dec2bn(&message_1, "100");
    BN_dec2bn(&message_2, "50");

    err = BN_add(message_sum, message_1, message_2);
    if (err != 1)
    {
        printf("\t * Add plaintexts failed (scheme 1, homomorphy)!\n");
        goto end;
    }
    err = BN_mul(message_mul, message_1, message_2, ctx);
    if (err != 1)
    {
        printf("\t * Mul plaintexts falied (scheme 1, homomorphy)!\n");
        goto end;
    }

    err = scheme1_encrypt(keychain.pk, message_1, cipher_1, zero1, zero2);
    if (err != 1)
    {
        printf("\t * Message 1 encryption failed (scheme 1, homomorphy)!\n");
        goto end;
    }

    BN_dec2bn(&zero1, "0");
    BN_dec2bn(&zero2, "0");

    err = scheme1_encrypt(keychain.pk, message_2, cipher_2, zero1, zero2);
    if (err != 1)
    {
        printf("\t * Message 2 encryption failed (scheme 1, homomorphy)!\n");
        goto end;
    }

    err = add(keychain.pk, cipher_1, cipher_2, cipher_sum_1);
    if (err != 1)
    {
        printf("\t * Add ciphertexts failed (scheme 1, homomorphy)!\n");
        goto end;
    }
    err = scheme1_decrypt(&keychain, cipher_sum_1, dec_cipher_sum_1);
    if (err != 1)
    {
        printf("\t * Added ciphertext decryption failed (scheme 1, homomorphy)!\n");
        goto end;
    }

    err = add_const(keychain.pk, cipher_1, message_2, cipher_sum_2);
    if (err != 1)
    {
        printf("\t * Add constant failed (scheme 1, homomorphy)!\n");
        goto end;
    }
    err = scheme1_decrypt(&keychain, cipher_sum_2, dec_cipher_sum_2);
    if (err != 1)
    {
        printf("\t * Add ciphertext wih constant decryption failed (scheme 1, homomorphy)!\n");
        goto end;
    }

    err = mul_const(keychain.pk, cipher_1, message_2, cipher_mul);
    if (err != 1)
    {
        printf("\t * Mul const failed (scheme 1, homomorphy)!\n");
        goto end;
    }
    err = scheme1_decrypt(&keychain, cipher_mul, dec_cipher_mul);
    if (err != 1)
    {
        printf("\t * Mul ciphertext with const decryption failed (scheme 1, homomorphy)!\n");
        goto end;
    }

    printf("\tMESSAGE 1: %s\n\tMESSAGE 2: %s\n", BN_bn2dec(message_1), BN_bn2dec(message_2));
    printf("\tMESSAGE SUM: %s\n\tMESSAGE MUL: %s\n\n", BN_bn2dec(message_sum), BN_bn2dec(message_mul));
    printf("\tCIPHER SUM 1: %s\n\tCIPHER SUM 2: %s\n", BN_bn2dec(dec_cipher_sum_1), BN_bn2dec(dec_cipher_sum_2));
    printf("\tCIPHER MUL: %s\n", BN_bn2dec(dec_cipher_mul));

end:
    BN_free(zero1);
    BN_free(zero2);
    BN_free(message_1);
    BN_free(message_2);
    BN_free(message_sum);
    BN_free(message_mul);
    BN_free(cipher_1);
    BN_free(cipher_2);
    BN_free(cipher_sum_1);
    BN_free(cipher_sum_2);
    BN_free(dec_cipher_sum_1);
    BN_free(dec_cipher_sum_2);
    BN_free(cipher_mul);
    BN_free(dec_cipher_mul);
    BN_CTX_free(ctx);

    free_keychain(&keychain);

    return err;
}

unsigned int test_homomorphy_scheme3()
{
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;

    unsigned int err = 0;

    BIGNUM *zero1 = BN_new();
    BIGNUM *zero2 = BN_new();
    BIGNUM *message_1 = BN_new();
    BIGNUM *message_2 = BN_new();
    BIGNUM *message_sum = BN_new();
    BIGNUM *message_mul = BN_new();
    BIGNUM *cipher_1 = BN_new();
    BIGNUM *cipher_2 = BN_new();
    BIGNUM *cipher_sum_1 = BN_new();
    BIGNUM *dec_cipher_sum_1 = BN_new();
    BIGNUM *cipher_sum_2 = BN_new();
    BIGNUM *dec_cipher_sum_2 = BN_new();
    BIGNUM *cipher_mul = BN_new();
    BIGNUM *dec_cipher_mul = BN_new();

    struct Keychain keychain;
    init_keychain(&keychain);
    err = scheme3_generate_keypair(&keychain);
    if (err != 1)
    {
        printf("\t * Generate keychain failed (scheme 3, homomorphy)!\n");
        goto end;
    }

    BN_dec2bn(&zero1, "0");
    BN_dec2bn(&zero2, "0");
    BN_dec2bn(&message_1, "100");
    BN_dec2bn(&message_2, "50");

    err = BN_add(message_sum, message_1, message_2);
    if (err != 1)
    {
        printf("\t * Add plaintexts failed (scheme 3, homomorphy)!\n");
        goto end;
    }
    err = BN_mul(message_mul, message_1, message_2, ctx);
    if (err != 1)
    {
        printf("\t * Mul plaintexts falied (scheme 3, homomorphy)!\n");
        goto end;
    }

    err = scheme3_encrypt(keychain.pk, keychain.sk.l_or_a, message_1, cipher_1, zero1, zero2);
    if (err != 1)
    {
        printf("\t * Message 1 encryption failed (scheme 3, homomorphy)!\n");
        goto end;
    }

    BN_dec2bn(&zero1, "0");
    BN_dec2bn(&zero2, "0");

    err = scheme3_encrypt(keychain.pk, keychain.sk.l_or_a, message_2, cipher_2, zero1, zero2);
    if (err != 1)
    {
        printf("\t * Message 2 encryption failed (scheme 3, homomorphy)!\n");
        goto end;
    }

    err = add(keychain.pk, cipher_1, cipher_2, cipher_sum_1);
    if (err != 1)
    {
        printf("\t * Add ciphertexts failed (scheme 3, homomorphy)!\n");
        goto end;
    }
    err = scheme3_decrypt(&keychain, cipher_sum_1, dec_cipher_sum_1);
    if (err != 1)
    {
        printf("\t * Added ciphertext decryption failed (scheme 3, homomorphy)!\n");
        goto end;
    }

    err = add_const(keychain.pk, cipher_1, message_2, cipher_sum_2);
    if (err != 1)
    {
        printf("\t * Add constant failed (scheme 3, homomorphy)!\n");
        goto end;
    }
    err = scheme3_decrypt(&keychain, cipher_sum_2, dec_cipher_sum_2);
    if (err != 1)
    {
        printf("\t * Add ciphertext wih constant decryption failed (scheme 3, homomorphy)!\n");
        goto end;
    }

    err = mul_const(keychain.pk, cipher_1, message_2, cipher_mul);
    if (err != 1)
    {
        printf("\t * Mul const failed (scheme 3, homomorphy)!\n");
        goto end;
    }
    err = scheme3_decrypt(&keychain, cipher_mul, dec_cipher_mul);
    if (err != 1)
    {
        printf("\t * Mul ciphertext with const decryption failed (scheme 3, homomorphy)!\n");
        goto end;
    }

    printf("\tMESSAGE 1: %s\n\tMESSAGE 2: %s\n", BN_bn2dec(message_1), BN_bn2dec(message_2));
    printf("\tMESSAGE SUM: %s\n\tMESSAGE MUL: %s\n\n", BN_bn2dec(message_sum), BN_bn2dec(message_mul));
    printf("\tCIPHER SUM 1: %s\n\tCIPHER SUM 2: %s\n", BN_bn2dec(dec_cipher_sum_1), BN_bn2dec(dec_cipher_sum_2));
    printf("\tCIPHER MUL: %s\n", BN_bn2dec(dec_cipher_mul));

end:
    BN_free(zero1);
    BN_free(zero2);
    BN_free(message_1);
    BN_free(message_2);
    BN_free(message_sum);
    BN_free(message_mul);
    BN_free(cipher_1);
    BN_free(cipher_2);
    BN_free(cipher_sum_1);
    BN_free(cipher_sum_2);
    BN_free(cipher_mul);
    BN_free(dec_cipher_mul);
    BN_free(dec_cipher_sum_1);
    BN_free(dec_cipher_sum_2);
    BN_CTX_free(ctx);

    free_keychain(&keychain);

    return err;
}

unsigned int homomorphy_test_both()
{
    printf("\n\t========= HOMOMORPHY TEST ===========\n");
    unsigned int err = 0;
    err += test_homomorphy_scheme1();
    printf("\n\tTEST SCHEME 1\tERR: %u (if 1 → OK)\n\n\t------\n\n", err);
    err += test_homomorphy_scheme3();
    printf("\n\tTEST SCHEME 3\tERR: %u (if 2 → OK)\n\n", err);

    return err;
}

unsigned int crt_test()
{
    printf("\n\t========= CRT TEST ==================\n");
    unsigned int err = 0;
    int i;
    int size = 3;
    BIGNUM *num[size];
    BIGNUM *rem[size];
    BIGNUM *result = BN_new();
    for (i = 0; i < size; i++)
    {
        num[i] = BN_new();
        rem[i] = BN_new();
    }

    BN_dec2bn(&num[0], "3");
    BN_dec2bn(&num[1], "4");
    BN_dec2bn(&num[2], "5");

    BN_dec2bn(&rem[0], "2");
    BN_dec2bn(&rem[1], "3");
    BN_dec2bn(&rem[2], "1");
    err = chinese_remainder_theorem(num, rem, size, result);

    printf("\tCRT result: %s (shloud be 11)\n\n", BN_bn2dec(result));

    for (i = 0; i < size; i++)
    {
        BN_free(num[i]);
        BN_free(rem[i]);
    }
    BN_free(result);

    return err;
}

int bn_field_test()
{
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *r = BN_new();

    BN_dec2bn(&p, "2");
    BN_dec2bn(&q, "3");
    BN_dec2bn(&r, "9");

    BIGNUM *field[] = {p, q, r};
    int size = sizeof(field) / sizeof(field[0]);
    printf("\n\tFIELD: [ ");
    for (int i = 0; i < size; i++)
    {
        if (i == (size - 1))
        {
            printf("%s ", BN_bn2dec(field[i]));
        }
        else
        {
            printf("%s, ", BN_bn2dec(field[i]));
        }
    }
    printf("]\tSIZE: %d\n\n", size);

    BN_free(p);
    BN_free(q);

    return 1;
}

int cJSON_create_test(unsigned char *file_name)
{
    printf("\n\t========= cJSON TEST ================\n");
    FILE *file = fopen(file_name, "w");

    const unsigned int resolution_numbers[3][2] = {
        {1280, 720},
        {1920, 1080},
        {3840, 2160}};
    char *string = NULL;
    cJSON *resolutions = NULL;
    size_t index = 0;

    cJSON *monitor = cJSON_CreateObject();

    if (cJSON_AddStringToObject(monitor, "name", "Awesome 4K") == NULL)
    {
        goto end;
    }

    resolutions = cJSON_AddArrayToObject(monitor, "resolutions");
    if (resolutions == NULL)
    {
        goto end;
    }

    for (index = 0; index < (sizeof(resolution_numbers) / (2 * sizeof(int))); ++index)
    {
        cJSON *resolution = cJSON_CreateObject();

        if (cJSON_AddNumberToObject(resolution, "width", resolution_numbers[index][0]) == NULL)
        {
            goto end;
        }

        if (cJSON_AddNumberToObject(resolution, "height", resolution_numbers[index][1]) == NULL)
        {
            goto end;
        }

        cJSON_AddItemToArray(resolutions, resolution);
    }

    string = cJSON_Print(monitor);
    if (string == NULL)
    {
        printf("Failed to print monitor.\n");
    }
    else
    {
        // printf("%s\n", string);
        if (fprintf(file, string) < 0)
        {
            printf("\t * Print to file failed!\n");
            goto end;
        }
    }

end:
    cJSON_Delete(monitor);
    free(string);

    return fclose(file);
}

int cJSON_parse_test(unsigned char *file_name)
{
    int err = 0;
    cJSON *json = cJSON_CreateObject();
    json = parse_JSON(file_name);
    const cJSON *resolution = NULL;
    const cJSON *resolutions = NULL;
    const cJSON *name = NULL;
    if (json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            printf("Error before: %s\n", error_ptr);
        }
        err = 0;
        goto end;
    }
    /* unsigned char *str = NULL;
    str = cJSON_Print(json);
    printf("%s\n", str); */

    name = cJSON_GetObjectItemCaseSensitive(json, "name");
    if (cJSON_IsString(name) && (name->valuestring != NULL))
    {
        printf("\nChecking monitor \"%s\"\n", name->valuestring);
    }

    resolutions = cJSON_GetObjectItemCaseSensitive(json, "resolutions");
    cJSON_ArrayForEach(resolution, resolutions)
    {
        cJSON *width = cJSON_GetObjectItemCaseSensitive(resolution, "width");
        cJSON *height = cJSON_GetObjectItemCaseSensitive(resolution, "height");

        if (!cJSON_IsNumber(width) || !cJSON_IsNumber(height))
        {
            err = 0;
            goto end;
        }

        if ((width->valuedouble == 1920) && (height->valuedouble == 1080))
        {
            err = 1;
            goto end;
        }
    }

    char *string = NULL;
    string = cJSON_Print(json);
    printf("%s\n", string);

end:
    cJSON_Delete(json);
    return err;
}