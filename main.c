#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include <paillier_scheme1.h>
#include <paillier_scheme3.h>
#include <homomorphy_functions.h>


int main() {
    clock_t start, end;
    double consumed_time;
    unsigned int err = 0;

    /*  SCHEME 1 TEST    */
        printf("\n========= SCHEME 1 =================\n");
        struct Keychain_scheme1 keyring_scheme1;
        scheme1_init_keychain(&keyring_scheme1);
        
        start = clock();
        err += scheme1_generate_keypair(&keyring_scheme1);
        end = clock();
        consumed_time = difftime(end, start);
        printf(" |--> Key Generation:\t%0.1f s\n", consumed_time);


        printf("ERR: %u\nKEYS:\n|--> LAMBDA: %s\n|--> MI: %s\n|--> N: %s\n|--> N_SQ: %s\n|--> G: %s\n",
            err, BN_bn2dec(keyring_scheme1.sk.lambda), BN_bn2dec(keyring_scheme1.sk.mi), BN_bn2dec(keyring_scheme1.pk->n),
            BN_bn2dec(keyring_scheme1.pk->n_sq), BN_bn2dec(keyring_scheme1.pk->g));


        BIGNUM *secret = BN_new();
        BN_dec2bn(&secret, "125");
        printf("SECRET: %s\n", BN_bn2dec(secret));

        BIGNUM *enc = BN_new();
        start = clock();
        err += scheme1_encrypt(keyring_scheme1.pk, secret, enc);
        end = clock();
        consumed_time = difftime(end, start);
        printf(" |--> Encryption:\t%0.1f s\n", consumed_time);


        printf("ENC: %s\n", BN_bn2dec(enc));
        

        BIGNUM *dec = BN_new();
        start = clock();
        err += scheme1_decrypt(&keyring_scheme1, enc, dec);
        end = clock();
        consumed_time = difftime(end, start);
        printf(" |--> Decryption:\t%0.1f s\n", consumed_time);


        printf("DEC: %s\n", BN_bn2dec(dec));

        
        scheme1_free_keychain(&keyring_scheme1);

    printf("\n");
    

    /*  SCHEME 3 TEST   
        printf("\n========= SCHEME 3 ==================\n");
        err = 0;
        struct Keychain_scheme3 keyring_scheme3 = {{""}};
        
        start = clock();
        err += scheme3_generate_keypair(&keyring_scheme3);
        printf("ERR: %u\nKEYS:\n|--> ALPHA: %s\n|--> MI: %s\n|--> N: %s\n|--> N_SQ: %s\n|--> G: %s\n",
            err, keyring_scheme3.sk.alpha, keyring_scheme3.sk.mi, keyring_scheme3.pk.n,
            keyring_scheme3.pk.n_sq, keyring_scheme3.pk.g);
        end = clock();
        consumed_time = difftime(end, start);
        //printf(" |--> Key Generation:\t%0.1f s\n", consumed_time);

        /*
        unsigned char *secret = "125";
        //printf("SECRET: %s\n", secret);

        unsigned char enc[BUFFER];
        start = clock();
        err += scheme3_encrypt(keyring_scheme3.pk, secret, enc);
        //printf("ENC: %s\n", enc);
        end = clock();
        consumed_time = difftime(end, start);
        printf(" |--> Encryption:\t%0.1f s\n", consumed_time);
        
        unsigned char dec[BUFFER];
        start = clock();
        err += scheme3_decrypt(&keyring_scheme3, enc, dec);
        //printf("DEC: %s\n", dec);
        end = clock();
        consumed_time = difftime(end, start);
        printf(" |--> Decryption:\t%0.1f s\n", consumed_time);
        

    printf("\n");
    */
    

    /*  HOMOMORPHY TEST
        printf("\n---HOMOMORPHIC TEST---\n");
        err = 0;
        err += test_homomorphic_scheme1();
        printf("\n\nTEST SCHEME 1\nERR: %u (if 4 → OK)\n", err);
        err += test_homomorphic_scheme2();
        printf("\n\nTEST SCHEME 3\nERR: %u (if 4 → OK)\n", err);
    */
 
    return 0;
}