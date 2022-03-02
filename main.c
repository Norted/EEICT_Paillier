#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include <paillier_scheme1.h>
#include <paillier_scheme3.h>
#include <speed_functions.h>
#include <homomorphy_functions.h>
#include <tests.h>

// definition of globals
pthread_t threads[NUM_THREADS];

struct Keychain keychain_1;
struct Keychain keychain_3;

clock_t start, end;
double consumed_time;

unsigned int err = 0;
unsigned int run = 1;

const char *restrict file_name_scheme1_noise = "precomputation_1_noise.json";
const char *restrict file_name_scheme1_message = "precomputation_1_message.json";
const char *restrict file_name_scheme3_noise = "precomputation_3_noise.json";
const char *restrict file_name_scheme3_message = "precomputation_3_message.json";

const char *restrict file_name_test = "JSON_parse_test.json";
const char *restrict file_name = "JSON_test.json";

unsigned char string[BUFFER];
BIGNUM *range;
BIGNUM *message;
BIGNUM *result;

cJSON *json_1_noise;
cJSON *json_1_message;
cJSON *json_3_noise;
cJSON *json_3_message;

// definition of functions
void *thread_creation(void *threadid);

unsigned int run_all();
int scheme1(const char *restrict result_file_name, unsigned int cheat_message, unsigned int cheat_random);
int scheme3(const char *restrict result_file_name, unsigned int cheat_message, unsigned int cheat_random);

// MAIN
int main()
{
    char command;
    int command_int;
    message = BN_new();
    BN_dec2bn(&message, "1234");
    result = BN_new();

    sprintf(string, "%d", RANGE);
    BN_dec2bn(&range, string);

    init_keychain(&keychain_1);
    read_keys(file_name_scheme1_noise, &keychain_1);
    /* if (!scheme1_generate_keypair(&keychain_1))
    {
        printf("\tKEYCHAIN Scheme 1 GENERATION FAILED!\n");
        return 0;
    } */

    init_keychain(&keychain_3);
    read_keys(file_name_scheme3_noise, &keychain_3);
    /* if (!scheme3_generate_keypair(&keychain_3))
    {
        printf("\tKEYCHAIN Scheme 3 GENERATION FAILED!\n");
        return 0;
    } */

    json_1_noise = cJSON_CreateObject();
    json_1_message = cJSON_CreateObject();
    json_3_noise = cJSON_CreateObject();
    json_3_message = cJSON_CreateObject();

    // type 1 ... message, 2 ... noise, 3 ... noise scheme 3
    /* err = precomputation(file_name_scheme1_noise, &keychain_1, RANGE, 2);
    err = precomputation(file_name_scheme1_message, &keychain_1, RANGE, 1);
    err = precomputation(file_name_scheme3_noise, &keychain_3, RANGE, 3);
    err = precomputation(file_name_scheme3_message, &keychain_3, RANGE, 1); */

    json_1_noise = parse_JSON(file_name_scheme1_noise);
    json_1_message = parse_JSON(file_name_scheme1_message);
    json_3_noise = parse_JSON(file_name_scheme3_noise);
    json_3_message = parse_JSON(file_name_scheme3_message);

    while (run)
    {
        if (system("clear") == -1)
        {
            printf("\n\t* Clearing the terminal FAILED!\n");
        }

        printf("\n\n"
               "\tEEEEE EEEEE IIIII  CCC  TTTTT       PPPP  RRRR    OOO    JJJ EEEEE  CCC  TTTTT\n"
               "\tE     E       I   C   C   T         P   P R   R  O   O     J E     C   C   T\n"
               "\tEEE   EEE     I   C       T         PPPP  RRRR   O   O     J EEE   C       T\n"
               "\tE     E       I   C       T         P     R   R  O   O J   J E     C       T\n"
               "\tEEEEE EEEEE IIIII  CCCC   T         P     R   R   OOO   JJJ  EEEEE  CCCC   T\n\n"
               "\t  ________________________________________________________________________\n"
               "\t |                                                                        |\n"
               "\t |   m mm mm   eee  n nnn  uu  u                                          |\n"
               "\t |    m  m  m eeeee  n   n  u  u                                          |\n"
               "\t |    m  m  m e      n   n  u  u                                          |\n"
               "\t |    m  m  m  eeee  n   n   uu u                                         |\n"
               "\t |                                                                        |\n"
               "\t |-----> RUN :                             -----> TESTS :                 |\n"
               "\t |   |--> 1 ... Scheme 1                     |--> 10 ... Scheme 1         |\n"
               "\t |   |--> 2 ... Scheme 3                     |--> 11 ... Scheme 3         |\n"
               "\t |   |--> 3 ... Scheme 1 precomuted g^n      |--> 12 ... Homomorphy       |\n"
               "\t |   |--> 4 ... Scheme 3 precomuted g^n      |--> 13 ... CRT              |\n"
               "\t |   |--> 5 ... Scheme 1 precomuted g^m      |--> 14 ... BIGNUM field     |\n"
               "\t |   |--> 6 ... Scheme 3 precomuted g^m      |--> 15 ... Precomputation   |\n"
               "\t |   |--> 7 ... Scheme 1 precomuted both     |--> 16 ... cJSON parser     |\n"
               "\t |   |--> 8 ... Scheme 3 precomuted both     |--> 17 ... Search test      |\n"
               "\t |   |--> 9 ... RUN ALL                                                   |\n"
               "\t |                                                                        |\n"
               "\t |-----> 18 ... Exit program                                              |\n"
               "\t |________________________________________________________________________|\n\n"
               "\t  >>> ");

        if (scanf("%s", &command) == EOF)
        {
            printf("\tCommand could not be scanned!\n");
            break;
        }

        command_int = atoi(&command);

        switch (command_int)
        {
        case 1:
            err = scheme1("scheme_1.csv", 0, 0);
            break;
        case 2:
            err = scheme3("scheme_3.csv", 0, 0);
            break;
        case 3:
            err = scheme1("scheme_1_rnd.csv", 0, 1);
            break;
        case 4:
            err = scheme3("scheme_3_rnd.csv", 0, 1);
            break;
        case 5:
            err = scheme1("scheme_1_msg.csv", 1, 0);
            break;
        case 6:
            err = scheme3("scheme_3_msg.csv", 1, 0);
            break;
        case 7:
            err = scheme1("scheme_1_both.csv", 1, 1);
            break;
        case 8:
            err = scheme3("scheme_3_both.csv", 1, 1);
            break;
        case 9:
            err = run_all();
            break;
        case 10:
            err = scheme1_test(message);
            break;
        case 11:
            err = scheme3_test(message);
            break;
        case 12:
            err = homomorphy_test_both();
            break;
        case 13:
            err = crt_test();
            break;
        case 14:
            err = bn_field_test();
            break;
        case 15:
            precomputation(file_name_test, &keychain_1, 100, 1);
            break;
        case 16:
            cJSON_create_test(file_name);
            cJSON_parse_test(file_name);
            break;
        case 17:
            json_1_noise = parse_JSON(file_name_test);
            err = find_value(json_1_noise, message, result);
            printf("\tSECRET: %s\n\tRESULT: %s\n", BN_bn2dec(message), BN_bn2dec(result));
            break;
        case 18:
            run = 0;
            break;
        default:
            printf("\tNo such command!\n");
            break;
        }

        if (command_int != 18)
        {
            getchar();
            printf("\t   ERR: %u\tPress any key to continue...", err);
            getchar();
        }
    }

    printf("\n\t* Clearing memory...\t");
    free_keychain(&keychain_1);
    free_keychain(&keychain_3);

    BN_free(message);
    BN_free(result);
    BN_free(range);

    cJSON_free(json_1_noise);
    cJSON_free(json_3_noise);

    printf("DONE!\n\t* Thank You! Bye! :)\n");
    // pthread_exit(NULL);

    return 1;
}

// FUNCTIONS
int scheme1(const char *restrict result_file_name, unsigned int cheat_message, unsigned int cheat_random)
{
    int printer = 0;
    BN_CTX *ctx = BN_secure_new();
    if (!ctx)
    {
        return 0;
    }

    BIGNUM *enc = BN_new();
    BIGNUM *dec = BN_new();
    BIGNUM *rnd = BN_new();
    BIGNUM *precomp_message = BN_new();
    BIGNUM *precomp_noise = BN_new();

    FILE *file = fopen(result_file_name, "w");
    if (file == NULL)
    {
        printf("\t * File open failed!\n");
        return 0;
    }

    printer = fprintf(file, "ITER\tENC\tDEC\tOK (=? 0)\n");
    if (printer < 0)
    {
        printf("\t * Printing to file failed!\n");
        goto end;
    }

    for (int i = 0; i < MAXITER; i++)
    {
        printer = fprintf(file, "%d\t", i);
        if (printer < 0)
        {
            printf("\t * Printing to file failed!\n");
            goto end;
        }

        err = 0;
        if (cheat_random == 1)
        {
            err = generate_rnd(range, keychain_1.pk->n, rnd, BITS / 2);
            if (err != 1)
                goto end;
            err = find_value(json_1_noise, rnd, precomp_noise);
            if (err != 1)
                goto end;
            // printf("R: %s\nP: %s\n", BN_bn2dec(rnd), BN_bn2dec(precomp_noise));
        }
        else
        {
            BN_dec2bn(&precomp_noise, "0");
        }

        if (cheat_message == 1)
        {
            err = generate_rnd(range, BN_value_one(), message, BITS / 2);
            if (err != 1)
                goto end;
            err = find_value(json_1_message, message, precomp_message);
            if (err != 1)
                goto end;
        }
        else
        {
            BN_dec2bn(&precomp_message, "0");
        }

        start = clock();
        err = scheme1_encrypt(keychain_1.pk, message, enc, precomp_message, precomp_noise);
        end = clock();
        consumed_time = difftime(end, start);
        if (err != 1)
        {
            printf("\t * Scheme 1 encryption failed (main)!\n");
            goto end;
        }
        printer = fprintf(file, "%0.1f\t", consumed_time);
        if (printer < 0)
        {
            printf("\t * Printing to file failed!\n");
            goto end;
        }

        start = clock();
        err = scheme1_decrypt(&keychain_1, enc, dec);
        end = clock();
        consumed_time = difftime(end, start);
        if (err != 1)
        {
            printf("\t * Scheme 1 decryption failed (main)!\n");
            goto end;
        }
        printer = fprintf(file, "%0.1f\t", consumed_time);
        if (printer < 0)
        {
            printf("\t * Printing to file failed!\n");
            goto end;
        }

        printer = fprintf(file, "%d\n", BN_cmp(message, dec));
        if (printer < 0)
        {
            printf("\t * Printing to file failed!\n");
            goto end;
        }

        // printf("M: %s\nD: %s\n", BN_bn2dec(message), BN_bn2dec(dec));
        if (BN_cmp(message, dec) != 0)
        {
            printf("\t * OPERATION FAILED!\n");
            break;
        }
    }

end:
    BN_free(enc);
    BN_free(dec);
    BN_free(rnd);
    BN_free(precomp_message);
    BN_free(precomp_noise);
    // BN_CTX_free(ctx);

    return fclose(file);
}

int scheme3(const char *restrict result_file_name, unsigned int cheat_message, unsigned int cheat_random)
{
    int printer = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        return 0;
    }

    FILE *file = fopen(result_file_name, "w");
    if (file == NULL)
    {
        printf("\t * File open failed!\n");
        return 0;
    }

    BIGNUM *enc = BN_new();
    BIGNUM *dec = BN_new();
    BIGNUM *rnd = BN_new();
    BIGNUM *precomp_message = BN_new();
    BIGNUM *precomp_noise = BN_new();

    printer = fprintf(file, "ITER\tENC\tDEC\tOK?\n");
    if (printer < 0)
    {
        printf("\t * Printing to file failed!\n");
        goto end;
    }

    for (int i = 0; i < MAXITER; i++) // FIX ME!
    {
        printer = fprintf(file, "%d\t", i);
        if (printer < 0)
        {
            printf("\t * Printing to file failed!\n");
            goto end;
        }

        err = 0;
        if (cheat_random == 1)
        {
            err = generate_rnd(range, keychain_1.sk.l_or_a, rnd, BITS / 2);
            if (err != 1)
                goto end;
            err = find_value(json_3_noise, rnd, precomp_noise);
            if (err != 1)
                goto end;
            // printf("R: %s\nP: %s\n", BN_bn2dec(rnd), BN_bn2dec(precomp_noise));
        }
        else
        {
            BN_dec2bn(&precomp_noise, "0");
        }

        if (cheat_message == 1)
        {
            err = generate_rnd(range, BN_value_one(), message, BITS / 2);
            if (err != 1)
                goto end;
            err = find_value(json_3_message, message, precomp_message);
            if (err != 1)
                goto end;
        }
        else
        {
            BN_dec2bn(&precomp_message, "0");
        }

        start = clock();
        err += scheme3_encrypt(keychain_3.pk, keychain_3.sk.l_or_a, message, enc, precomp_message, precomp_noise);
        end = clock();
        consumed_time = difftime(end, start);
        printer = fprintf(file, "%0.1f\t", consumed_time);
        if (printer < 0)
        {
            printf("\t * Printing to file failed!\n");
            goto end;
        }

        start = clock();
        err += scheme3_decrypt(&keychain_3, enc, dec);
        end = clock();
        consumed_time = difftime(end, start);
        printer = fprintf(file, "%0.1f\t", consumed_time);
        if (printer < 0)
        {
            printf("\t * Printing to file failed!\n");
            goto end;
        }

        printer = fprintf(file, "%d\n", BN_cmp(message, dec));
        if (printer < 0)
        {
            printf("\t * Printing to file failed!\n");
            goto end;
        }

        // printf("M: %s\nD: %s\n", BN_bn2dec(message), BN_bn2dec(dec));
        if (BN_cmp(message, dec) != 0)
        {
            printf("\t * OPERATION FAILED!\n");
            break;
        }
    }

end:
    BN_free(enc);
    BN_free(dec);
    BN_free(rnd);
    BN_free(precomp_message);
    BN_free(precomp_noise);
    BN_CTX_free(ctx);

    return fclose(file);
}

unsigned int run_all()
{
    err = 0;
    
    printf("\t * Scheme 1 started ...\t");
    err = scheme1("scheme_1.csv", 0, 0);
    if (err != 0)
    {
        printf("\t * Scheme 1 failed!\n");
        return 0;
    }
    printf("DONE!\n");

    printf("\t * Scheme 3 started ...\t");
    err = scheme3("scheme_3.csv", 0, 0);
    if (err != 0)
    {
        printf("\t * Scheme 1 failed!\n");
        return 0;
    }
    printf("DONE!\n");

    printf("\t * Scheme 1 random started ...\t");
    err = scheme1("scheme_1_rnd.csv", 0, 1);
    if (err != 0)
    {
        printf("\t * Scheme 1 random failed!\n");
        return 0;
    }
    printf("DONE!\n");

    printf("\t * Scheme 3 random started ...\t");
    err = scheme3("scheme_3_rnd.csv", 0, 1);
    if (err != 0)
    {
        printf("\t * Scheme 1 random failed!\n");
        return 0;
    }
    printf("DONE!\n");

    printf("\t * Scheme 1 message started ...\t");
    err = scheme1("scheme_1_msg.csv", 1, 0);
    if (err != 0)
    {
        printf("\t * Scheme 1 message failed!\n");
        return 0;
    }
    printf("DONE!\n");

    printf("\t * Scheme 3 message started ...\t");
    err = scheme3("scheme_3_msg.csv", 1, 0);
    if (err != 0)
    {
        printf("\t * Scheme 3 message failed!\n");
        return 0;
    }
    printf("DONE!\n");

    printf("\t * Scheme 1 both started ...\t");
    err = scheme1("scheme_1_both.csv", 1, 1);
    if (err != 0)
    {
        printf("\t * Scheme 1 both failed!\n");
        return 0;
    }
    printf("DONE!\n");

    printf("\t * Scheme 3 both started ...\t");
    err = scheme3("scheme_3_both.csv", 1, 1);
    if (err != 0)
    {
        printf("\t * Scheme 3 both failed!\n");
        return 0;
    }
    printf("DONE!\n");

    return 1;
}