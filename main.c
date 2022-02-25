#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include <paillier_scheme1.h>
#include <paillier_scheme3.h>
#include <speed_functions.h>
#include <homomorphy_functions.h>

// definition of globals
pthread_t threads[NUM_THREADS];

struct Keychain keychain_1;
struct Keychain keychain_3;

clock_t start, end;
double consumed_time = 0;
double enc_consumed_time = 0;
double dec_consumed_time = 0;

unsigned int err = 0;
unsigned int counter = 0;
unsigned int iter = 0;
unsigned int run = 1;

BIGNUM *enc;
BIGNUM *dec;
BIGNUM *secret;

// definition of functions
void *thread_creation(void *threadid);
int scheme1_test();
int scheme3_test();
int homomorphy_test();
int crt_test();
int bn_field_test();

int main()
{
    printf("-+-+ EEICT PAILLIER -+-+-+-+-+-+-+-+-\n\n");
    char command;
    int command_int;
    enc = BN_new();
    dec = BN_new();
    secret = BN_new();
    BN_dec2bn(&secret, "1234567");

    scheme1_init_keychain(&keychain_1);
    if (!scheme1_generate_keypair(&keychain_1))
    {
        printf("KEYCHAIN Scheme 1 GENERATION FAILED!\n");
        return 0;
    }

    scheme3_init_keychain(&keychain_3);
    if (!scheme3_generate_keypair(&keychain_3))
    {
        printf("KEYCHAIN Scheme 3 GENERATION FAILED!\n");
        return 0;
    }

    /* int rc;
    for (int i = 0; i < NUM_THREADS; i++)
    {
        rc = pthread_create(&threads[i], NULL, thread_creation, (void *)i);
        if (rc)
        {
            printf("Error:unable to create thread, %d\n", rc);
            exit(-1);
        }
    } */

    while (run)
    {
        if (system('CLS') != -1)
        {
            printf("\n* Clearing the terminal FAILED!\n");
        }

        printf("~~~~ MENU ~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
               "| 1 ... Scheme 1 test                |\n"
               "| 2 ... Scheme 3 test                |\n"
               "| 3 ... Homomorphy test              |\n"
               "| 4 ... CRT test                     |\n"
               "| 5 ... BIGNUM field creation test   |\n"
               "| 6 ... Precomputation test          |\n"
               "| 7 ... Exit program                 |\n");
        printf("--------------------------------------\n\n");
        printf(" >>> ");
        if (scanf("%s", &command) == EOF)
        {
            printf("Command could not be scanned!\n");
            break;
        }

        command_int = atoi(&command);

        switch (command_int)
        {
        case 1:
            err = scheme1_test();
            break;
        case 2:
            err = scheme3_test();
            break;
        case 3:
            err = homomorphy_test();
            break;
        case 4:
            err = crt_test();
            break;
        case 5:
            err = bn_field_test();
            break;
        case 6:
            precomputation("test.json", &keychain_1);
            break;
        case 7:
            run = 0;
            break;
        default:
            printf("No such command!\n");
            break;
        }
    }

    printf("\n* Clearing memory...\t");
    scheme1_free_keychain(&keychain_1);
    scheme3_free_keychain(&keychain_3);

    BN_free(dec);
    BN_free(enc);
    BN_free(secret);

    printf("DONE!\n* Thank You! Bye! :)\n");
    pthread_exit(NULL);

    return 1;
}

// FUNCTIONS

void *thread_creation(void *threadid)
{
    long tid = (long)threadid;
    BIGNUM *min = BN_new();
    BN_dec2bn(&min, BITS_STR);

    printf("Thread ID, %ld\n", tid);
    unsigned char *file_name;
    if (tid == 0)
    {
        file_name = "gn_file.json";
        precomputation(file_name, &keychain_1);
    }
    else
    {
        file_name = "gm_file.json";
        precomputation(file_name, &keychain_1);
    }

    pthread_exit(NULL);
    BN_free(min);
}

int scheme1_test()
{
    printf("\n========= SCHEME 1 =================\n");
    err = 0;
    // counter = 0;
    // iter = 0;

    start = clock();
    err += scheme1_generate_keypair(&keychain_1);
    end = clock();
    consumed_time = difftime(end, start);
    printf(" |--> Key Generation:\t%0.1f s\n", consumed_time);
    // printf("ERR: %u\nKEYS:\n|--> LAMBDA: %s\n|--> MI: %s\n|--> N: %s\n|--> N_SQ: %s\n|--> G: %s\n",
    //     err, BN_bn2dec(keychain_1.sk.lambda), BN_bn2dec(keychain_1.sk.mi), BN_bn2dec(keychain_1.pk->n),
    //     BN_bn2dec(keychain_1.pk->n_sq), BN_bn2dec(keychain_1.pk->g));

    while (iter < 100)
    {
        // printf("iter %d", iter);

        start = clock();
        err += scheme1_encrypt(keychain_1.pk, secret, enc);
        end = clock();
        enc_consumed_time += difftime(end, start);
        // printf(" |--> Encryption:\t%0.1f s\n", consumed_time);
        // printf("ENC: %s\n", BN_bn2dec(enc));

        start = clock();
        err += scheme1_decrypt(&keychain_1, enc, dec);
        end = clock();
        dec_consumed_time += difftime(end, start);
        // printf(" |--> Decryption:\t%0.1f s\n", consumed_time);
        // printf(" |----> SECRET: %s\n", BN_bn2dec(secret));
        // printf(" |----> DEC: %s\n", BN_bn2dec(dec));

        //    printf("\t\t%s ?= %s", BN_bn2dec(secret), BN_bn2dec(dec));
        //    if(BN_is_zero(dec) == 1) {
        //        printf("\t>>>\tfail");
        //        counter++;
        //    }
        iter++;
        //    printf("\n");
    }
    printf(" |--> Encryption:\t%0.1f s\n", enc_consumed_time / iter);
    printf(" |--> Decryption:\t%0.1f s\n", dec_consumed_time / iter);

    // printf("COUNTER: %d\n", counter);
    printf("\n\n");
    return err;
}

int scheme3_test()
{
    printf("\n========= SCHEME 3 ==================\n");
    err = 0;

    // counter = 0;
    iter = 0;
    enc_consumed_time = 0;
    dec_consumed_time = 0;
    while (iter < 100)
    {
        scheme3_init_keychain(&keychain_3);
        start = clock();
        err += scheme3_generate_keypair(&keychain_3);
        end = clock();
        consumed_time = difftime(end, start);
        // printf(" |--> Key Generation:\t%0.1f s\n", consumed_time);
        // printf("ERR: %u\nKEYS:\n|--> ALPHA: %s\n|--> MI: %s\n|--> N: %s\n|--> N_SQ: %s\n|--> G: %s\n",
        //     err, BN_bn2dec(keychain_3.sk.alpha), BN_bn2dec(keychain_3.sk.mi), BN_bn2dec(keychain_3.pk->n),
        //     BN_bn2dec(keychain_3.pk->n_sq), BN_bn2dec(keychain_3.pk->g));

        // printf("iter %d", iter);
        start = clock();
        err += scheme3_encrypt(keychain_3.pk, keychain_3.sk.l_or_a, secret, enc);
        end = clock();
        enc_consumed_time += difftime(end, start);
        // printf(" |--> Encryption:\t%0.1f s\n", consumed_time);
        // printf("ENC: %s\n", BN_bn2dec(enc));

        start = clock();
        err += scheme3_decrypt(&keychain_3, enc, dec);
        end = clock();
        dec_consumed_time += difftime(end, start);
        // printf(" |--> Decryption:\t%0.1f s\n", consumed_time);
        // printf(" |----> SECRET: %s\n", BN_bn2dec(secret));
        // printf(" |----> DEC: %s\n", BN_bn2dec(dec));

        if (BN_is_zero(dec) == 1)
        {
            printf("\t>>>\tfail");
            counter++;
        }
        iter++;
        printf("\n");
        scheme3_free_keychain(&keychain_3);
    }
    printf(" |--> Encryption:\t%0.1f s\n", enc_consumed_time / iter);
    printf(" |--> Decryption:\t%0.1f s\n", dec_consumed_time / iter);
    // printf("COUNTER %d", counter);

    printf("\n\n");
    return err;
}

int homomorphy_test()
{
    printf("\n========= HOMOMORPHY TEST ===========\n");
    err = 0;
    err += test_homomorphic_scheme1();
    printf("\nTEST SCHEME 1\tERR: %u (if 1 → OK)\n\n\t------\n\n", err);
    err += test_homomorphic_scheme3();
    printf("\nTEST SCHEME 3\tERR: %u (if 2 → OK)\n\n", err);

    return err;
}

int crt_test()
{
    printf("\n========= CRT TEST ==================\n");
    err = 0;
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

    printf("CRT result: %s\n\n", BN_bn2dec(result)); // shloud be 11

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
    printf("\nFIELD: [ ");
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