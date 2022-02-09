#include <homomorphy_functions.h>

unsigned int add(struct PublicKey *pk, BIGNUM *a, BIGNUM *b, BIGNUM *res) {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    //Add one encrypted unsigned long longeger to another
    unsigned int err = BN_mod_mul(res, a, b, pk->n_sq, ctx);
    
    BN_CTX_free(ctx);
    return err;
}

unsigned int add_const(struct PublicKey *pk, BIGNUM *a, BIGNUM *n, BIGNUM *res) {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    //Add constant n to an encrypted unsigned long longeger
    unsigned int err = 0;
    BIGNUM *p_1 = BN_new();
    err += BN_mod_exp(p_1, pk->g, n, pk->n_sq, ctx);
    err += BN_mod_mul(res, a, p_1, pk->n_sq, ctx);
    
    BN_free(p_1);
    BN_CTX_free(ctx);
    if(err != 2)
        return 0;
    return 1;
}

unsigned int mul_const(struct PublicKey *pk, BIGNUM *a, BIGNUM *n, BIGNUM *res) {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    //Multiplies an encrypted unsigned long longeger by a constant
    unsigned int err = BN_mod_exp(res, a, n, pk->n_sq, ctx);
    
    BN_CTX_free(ctx);
    return err;
}

unsigned int test_homomorphic_scheme1() {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    struct Keychain_scheme1 keyring1 = {{""}};
    unsigned int err = 0;
    err += scheme1_generate_keypair(&keyring1);

    BIGNUM *message_1 = BN_new();
    BN_dec2bn(message_1, "100");
    BIGNUM *message_2 = BN_new();
    BN_dec2bn(message_2, "50");
    BIGNUM *message_sum = BN_new();
    err += BN_add(message_sum, message_1, message_2);
    BIGNUM *message_mul = BN_new();
    err += BN_mul(message_mul, message_1, message_2, ctx);

    printf("MESSAGE 1: %s\nMESSAGE 2: %s\n", BN_bn2dec(message_1), BN_bn2dec(message_2));
    printf("MESSAGE SUM: %s\nMESSAGE MUL: %s\n\n", BN_bn2dec(message_sum), BN_bn2dec(message_mul));

    BN_free(message_sum);
    BN_free(message_mul);

    BIGNUM *cipher_1 = BN_new();
    err += scheme1_encrypt(&keyring1.pk, message_1, cipher_1);
    BIGNUM *cipher_2 = BN_new();
    err += scheme1_encrypt(&keyring1.pk, message_2, cipher_2);

    BIGNUM *cipher_sum_1 = BN_new();
    BIGNUM *dec_cipher_sum_1 = BN_new();
    err += add(&keyring1.pk, cipher_1, cipher_2, cipher_sum_1);
    err += scheme1_decrypt(&keyring1, cipher_sum_1, dec_cipher_sum_1);

    BIGNUM *cipher_sum_2 = BN_new();
    BIGNUM *dec_cipher_sum_2 = BN_new();
    err += add_const(&keyring1.pk, cipher_1, message_2, cipher_sum_2);
    err += scheme1_decrypt(&keyring1, cipher_sum_2, dec_cipher_sum_2);

    printf("CIPHER SUM 1: %s\nCIPHER SUM 2: %s\n", BN_bn2dec(dec_cipher_sum_1), BN_bn2dec(dec_cipher_sum_2));

    BN_free(cipher_1);
    BN_free(cipher_2);
    BN_free(cipher_sum_1);
    BN_free(cipher_sum_2);
    BN_free(dec_cipher_sum_1);
    BN_free(dec_cipher_sum_2);

    BIGNUM *cipher_mul = BN_new();
    BIGNUM *dec_cipher_mul = BN_new();
    err += mul_const(&keyring1.pk, cipher_1, message_2, cipher_mul);
    err += scheme1_decrypt(&keyring1, cipher_mul, dec_cipher_mul);

    BN_free(cipher_mul);
    BN_free(dec_cipher_mul);

    printf("CIPHER MUL: %s\n", BN_bn2dec(dec_cipher_mul));

    BN_CTX_free(ctx);
    if(err != 11)
        return 0;
    return 1;
}

unsigned int test_homomorphic_scheme3() {
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
        return 0;
    
    struct Keychain_scheme3 keyring3 = {{""}};
    unsigned int err = 0;
    err += scheme3_generate_keypair(&keyring3);

    BIGNUM *message_1 = BN_new();
    BN_dec2bn(message_1, "100");
    BIGNUM *message_2 = BN_new();
    BN_dec2bn(message_2, "50");
    BIGNUM *message_sum = BN_new();
    err += BN_add(message_sum, message_1, message_2);
    BIGNUM *message_mul = BN_new();
    err += BN_mul(message_mul, message_1, message_2, ctx);

    printf("MESSAGE 1: %s\nMESSAGE 2: %s\n", BN_bn2dec(message_1), BN_bn2dec(message_2));
    printf("MESSAGE SUM: %s\nMESSAGE MUL: %s\n\n", BN_bn2dec(message_sum), BN_bn2dec(message_mul));

    BN_free(message_sum);
    BN_free(message_mul);

    BIGNUM *cipher_1 = BN_new();
    err += scheme3_encrypt(&keyring3.pk, keyring3.sk.alpha, message_1, cipher_1);
    BIGNUM *cipher_2 = BN_new();
    err += scheme3_encrypt(&keyring3.pk, keyring3.sk.alpha, message_2, cipher_2);

    BIGNUM *cipher_sum_1 = BN_new();
    BIGNUM *dec_cipher_sum_1 = BN_new();
    err += add(&keyring3.pk, cipher_1, cipher_2, cipher_sum_1);
    err += scheme3_decrypt(&keyring3, cipher_sum_1, dec_cipher_sum_1);

    BIGNUM *cipher_sum_2 = BN_new();
    BIGNUM *dec_cipher_sum_2 = BN_new();
    err += add_const(&keyring3.pk, cipher_1, message_2, cipher_sum_2);
    err += scheme3_decrypt(&keyring3, cipher_sum_2, dec_cipher_sum_2);

    printf("CIPHER SUM 1: %s\nCIPHER SUM 2: %s\n", BN_bn2dec(dec_cipher_sum_1), BN_bn2dec(dec_cipher_sum_2));

    BN_free(cipher_1);
    BN_free(cipher_2);
    BN_free(cipher_sum_1);
    BN_free(cipher_sum_2);
    BN_free(dec_cipher_sum_1);
    BN_free(dec_cipher_sum_2);

    BIGNUM *cipher_mul = BN_new();
    BIGNUM *dec_cipher_mul = BN_new();
    err += mul_const(&keyring3.pk, cipher_1, message_2, cipher_mul);
    err += scheme3_decrypt(&keyring3, cipher_mul, dec_cipher_mul);

    BN_free(cipher_mul);
    BN_free(dec_cipher_mul);

    printf("CIPHER MUL: %s\n", BN_bn2dec(dec_cipher_mul));

    BN_CTX_free(ctx);
    if(err != 11)
        return 0;
    return 1;
}