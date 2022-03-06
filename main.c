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
double consumed_time, average_time;

unsigned int err = 0;
unsigned int run = 1;
char command;
int command_int;

unsigned char string[BUFFER];
BIGNUM *range;
BIGNUM *message;
BIGNUM *result;

cJSON *json_1_noise;
cJSON *json_1_message;
cJSON *json_3_noise;
cJSON *json_3_message;

// FILE NAMES
const char *restrict file_keys_scheme1 = "keys/saved_keys_scheme1.json";
const char *restrict file_keys_scheme3 = "keys/saved_keys_scheme3.json";

const char *restrict file_scheme1_precomputed_noise = "precomputed_values/precomputation_1_noise.json";
const char *restrict file_scheme1_precomputed_message = "precomputed_values/precomputation_1_message.json";
const char *restrict file_scheme3_precomputed_noise = "precomputed_values/precomputation_3_noise.json";
const char *restrict file_scheme3_precomputed_message = "precomputed_values/precomputation_3_message.json";

const char *restrict file_scheme1_results = "results/scheme_1.csv";
const char *restrict file_scheme3_results = "results/scheme_3.csv";
const char *restrict file_scheme1_noise_results = "results/scheme_1_rnd.csv";
const char *restrict file_scheme3_noise_results = "results/scheme_3_rnd.csv";
const char *restrict file_scheme1_msg_results = "results/scheme_1_msg.csv";
const char *restrict file_scheme3_msg_results = "results/scheme_3_msg.csv";
const char *restrict file_scheme1_both_results = "results/scheme_1_both.csv";
const char *restrict file_scheme3_both_results = "results/scheme_3_both.csv";

const char *restrict file_parse_test = "JSON_parse_test.json";
const char *restrict file_json_test = "JSON_test.json";

// definition of functions
void *thread_creation(void *threadid);
unsigned int threaded_precomputation();
int scheme1(const char *restrict result_file_name, const char *mode, BIGNUM *message, unsigned int cheat_message, unsigned int cheat_random);
int scheme3(const char *restrict result_file_name, const char *mode, BIGNUM *message, unsigned int cheat_message, unsigned int cheat_random);
void avg_results();
unsigned int run_all();
int run_all_tests();

// MAIN
int main()
{
    message = BN_new();
    BN_dec2bn(&message, "12");
    result = BN_new();

    sprintf(string, "%d", RANGE);
    BN_dec2bn(&range, string);

    json_1_noise = cJSON_CreateObject();
    json_1_message = cJSON_CreateObject();
    json_3_noise = cJSON_CreateObject();
    json_3_message = cJSON_CreateObject();

    init_keychain(&keychain_1);
    init_keychain(&keychain_3);

    if (access(file_keys_scheme1, F_OK))
    {

        if (!scheme1_generate_keypair(&keychain_1))
        {
            printf("\tKEYCHAIN Scheme 1 GENERATION FAILED!\n");
            return 0;
        }
        err = save_keys(file_keys_scheme1, &keychain_1);
        if(err != 0)
        {
            printf("\t * Save Keychain for Scheme 1 failed!\n");
        }
    }
    else
    {
        read_keys(file_keys_scheme1, &keychain_1);
    }

    if (access(file_keys_scheme3, F_OK))
    {
        if (!scheme3_generate_keypair(&keychain_3))
        {
            printf("\tKEYCHAIN Scheme 3 GENERATION FAILED!\n");
            return 0;
        }
        err = save_keys(file_keys_scheme3, &keychain_3);
        if(err != 0)
        {
            printf("\t * Save Keychain for Scheme 3 failed!\n");
        }
    }
    else
    {
        read_keys(file_keys_scheme3, &keychain_3);
    }

    if (access(file_scheme1_precomputed_noise, F_OK) || access(file_scheme1_precomputed_message, F_OK) ||
        access(file_scheme3_precomputed_noise, F_OK) || access(file_scheme3_precomputed_message, F_OK) )
    {
        threaded_precomputation();
        for (int i = 0; i < NUM_THREADS; i++)
        {
            pthread_join(threads[i], NULL);
        }

        printf("\a\tPress any key to continue ...");
        getchar();
    }
    
    json_1_noise = parse_JSON(file_scheme1_precomputed_noise);
    json_1_message = parse_JSON(file_scheme1_precomputed_message);
    json_3_noise = parse_JSON(file_scheme3_precomputed_noise);
    json_3_message = parse_JSON(file_scheme3_precomputed_message);

    /* MENU     */
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
               "\t  _________________________________________________________________________\n"
               "\t |                                                                         |\n"
               "\t |   m mm mm   eee  n nnn  uu  u                                           |\n"
               "\t |    m  m  m eeeee  n   n  u  u                                           |\n"
               "\t |    m  m  m e      n   n  u  u                                           |\n"
               "\t |    m  m  m  eeee  n   n   uu u                                          |\n"
               "\t |                                                                         |\n"
               "\t |-----> RUN :                             -----> TESTS :                  |\n"
               "\t |   |--> 1 .... Scheme 1                     |--> 11 ... Scheme 1         |\n"
               "\t |   |--> 2 .... Scheme 3                     |--> 12 ... Scheme 3         |\n"
               "\t |   |--> 3 .... Scheme 1 precomuted g^n      |--> 13 ... Homomorphy       |\n"
               "\t |   |--> 4 .... Scheme 3 precomuted g^n      |--> 14 ... CRT              |\n"
               "\t |   |--> 5 .... Scheme 1 precomuted g^m      |--> 15 ... BIGNUM field     |\n"
               "\t |   |--> 6 .... Scheme 3 precomuted g^m      |--> 16 ... Precomputation   |\n"
               "\t |   |--> 7 .... Scheme 1 precomuted both     |--> 17 ... cJSON parser     |\n"
               "\t |   |--> 8 .... Scheme 3 precomuted both     |--> 18 ... Search           |\n"
               "\t |   |--> 9 .... RUN ALL                      |--> 19 ... RUN ALL tests    |\n"
               "\t |   |--> 10 ... RUN ALL Average                                           |\n"
               "\t |                                                                         |\n"
               "\t |-----> 20 ... Exit program                                               |\n"
               "\t |_________________________________________________________________________|\n\n"
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
            err = scheme1(file_scheme1_results, "w", message, 0, 0);
            break;
        case 2:
            err = scheme3(file_scheme3_results, "w", message, 0, 0);
            break;
        case 3:
            err = scheme1(file_scheme1_noise_results, "w", message, 0, 1);
            break;
        case 4:
            err = scheme3(file_scheme3_noise_results, "w", message, 0, 1);
            break;
        case 5:
            err = scheme1(file_scheme1_msg_results, "w", message, 1, 0);
            break;
        case 6:
            err = scheme3(file_scheme3_msg_results, "w", message, 1, 0);
            break;
        case 7:
            err = scheme1(file_scheme1_both_results, "w", message, 1, 1);
            break;
        case 8:
            err = scheme3(file_scheme3_both_results, "w", message, 1, 1);
            break;
        case 9:
            err = run_all();
            break;
        case 10:
            avg_results();
            break;
        case 11:
            err = scheme1_test(message);
            break;
        case 12:
            err = scheme3_test(message);
            break;
        case 13:
            err = homomorphy_test_both();
            break;
        case 14:
            err = crt_test();
            break;
        case 15:
            err = bn_field_test();
            break;
        case 16:
            err = precomputation(file_parse_test, &keychain_1, 100, 1);
            break;
        case 17:
            err = cJSON_create_test(file_json_test);
            err = cJSON_parse_test(file_json_test);
            break;
        case 18:
            json_1_noise = parse_JSON(file_parse_test);
            err = find_value(json_1_noise, message, result);
            printf("\tSECRET: %s\n\tRESULT: %s\n", BN_bn2dec(message), BN_bn2dec(result));
            break;
        case 19:
            err = run_all_tests();
            break;
        case 20:
            run = 0;
            break;
        default:
            printf("\tNo such command!\n");
            break;
        }

        if (command_int != 20)
        {
            getchar();
            printf("\a\t   ERR: %u\tPress any key to continue...", err);
            getchar();
        }
    }
    //*/

    printf("\n\t* Clearing memory...\t");
    free_keychain(&keychain_1);
    free_keychain(&keychain_3);

    BN_free(message);
    BN_free(result);
    BN_free(range);

    cJSON_free(json_1_noise);
    cJSON_free(json_3_noise);
    cJSON_free(json_1_message);
    cJSON_free(json_3_message);

    printf("DONE!\n\t* Thank You! Bye! :)\n");
    pthread_exit(NULL);

    return 1;
}

void *thread_creation(void *threadid)
{ // precomputation type: 1 ... message, 2 ... noise, 3 ... noise scheme 3
    long tid;
    tid = (long)threadid;
    if (tid == 0)
    {
        err = precomputation(file_scheme1_precomputed_noise, &keychain_1, RANGE, 2);
        if (err != 0)
        {
            printf("\t * Scheme 1 noise precomputation failed!\n");
            pthread_exit(NULL);
        }
    }
    else if (tid == 1)
    {
        err = precomputation(file_scheme1_precomputed_message, &keychain_1, RANGE, 1);
        if (err != 0)
        {
            printf("\t * Scheme 1 message precomputation failed!\n");
            pthread_exit(NULL);
        }
    }
    else if (tid == 2)
    {
        err = precomputation(file_scheme3_precomputed_noise, &keychain_3, RANGE, 3);
        if (err != 0)
        {
            printf("\t * Scheme 3 noise precomputation failed!\n");
            pthread_exit(NULL);
        }
    }
    else if (tid == 3)
    {
        err = precomputation(file_scheme3_precomputed_message, &keychain_3, RANGE, 1);
        if (err != 0)
        {
            printf("\t * Scheme 3 message precomputation failed!\n");
            pthread_exit(NULL);
        }
    }
    else
    {
        printf("\t * No other thread needed! (thread no. %ld)\n", tid);
        return;
    }
    pthread_exit(NULL);
    return;
}

unsigned int threaded_precomputation()
{
    int rc;
    for (int i = 0; i < NUM_THREADS; i++)
    {
        printf("\t  main() : Creating thread, %d\n", i);
        rc = pthread_create(&threads[i], NULL, thread_creation, (void *)i);
        if (rc)
        {
            printf("\t  Error : Unable to create thread, %d\n", rc);
            exit(-1);
        }
    }
    //pthread_exit(NULL);

    return 0;
}

// FUNCTIONS
int scheme1(const char *restrict result_file_name, const char *mode, BIGNUM *message, unsigned int cheat_message, unsigned int cheat_random)
{
    int printer = 0;

    BIGNUM *enc = BN_new();
    BIGNUM *dec = BN_new();
    BIGNUM *rnd = BN_new();
    BIGNUM *precomp_message = BN_new();
    BIGNUM *precomp_noise = BN_new();

    FILE *file = fopen(result_file_name, mode);
    if (file == NULL)
    {
        printf("\t * File open failed!\n");
        return 0;
    }

    printer = fprintf(file, "ITER\tMSG\tENC\tDEC\tOK (=? 0)\n");
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

        printer = fprintf(file, "%s\t", BN_bn2dec(message));
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
            if (command_int != 10)
            {
                err = generate_rnd(range, BN_value_one(), message, BITS / 2);
                if (err != 1)
                    goto end;
            }

            err = find_value(json_1_message, message, precomp_message);
            if (err != 1)
                goto end;
            // printf("M: %s\nP: %s\n", BN_bn2dec(message), BN_bn2dec(precomp_message));
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

    return fclose(file);
}

int scheme3(const char *restrict result_file_name, const char *mode, BIGNUM *message, unsigned int cheat_message, unsigned int cheat_random)
{
    int printer = 0;

    FILE *file = fopen(result_file_name, mode);
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

    printer = fprintf(file, "ITER\tMSG\tENC\tDEC\tOK (=? 0)\n");
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

        printer = fprintf(file, "%s\t", BN_bn2dec(message));
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
            if (command_int != 10)
            {
                err = generate_rnd(range, BN_value_one(), message, BITS / 2);
                if (err != 1)
                    goto end;
            }

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

    return fclose(file);
}

void avg_results()
{
    err = 0;
    BIGNUM * bn_message = BN_new();
    char value_str[BUFFER];
    const char *mode = "w";
    for (int value = 1; value <= 10; value++)
    {
        sprintf(value_str, "%d", value);
        BN_dec2bn(&bn_message, value_str);
        
        if(value == 2)
            mode = "a";
        
        printf("\t * Starting SCHEME 1 with %d!\n", value);
        err = scheme1(file_scheme1_results, mode, bn_message, 0, 0);
        printf("\t *** SCHEME 1 ERR: %d\n", err);
        err = scheme1(file_scheme1_noise_results, mode, bn_message, 0, 1);
        printf("\t *** SCHEME 1 NOISE ERR: %d\n", err);
        err = scheme1(file_scheme1_msg_results, mode, bn_message, 1, 0);
        printf("\t *** SCHEME 1 MSG ERR: %d\n", err);
        err = scheme1(file_scheme1_both_results, mode, bn_message, 1, 1);
        printf("\t *** SCHEME 1 BOTH ERR: %d\n"
               "\t * SCHEME 1 with %d DONE!\n\n"
               "\t * Starting SCHEME 3 with %d!\n",err, value, value);

        err = scheme3(file_scheme3_results, mode, bn_message, 0, 0);
        printf("\t *** SCHEME 3 ERR: %d\n", err);
        err = scheme3(file_scheme3_noise_results, mode, bn_message, 0, 1);
        printf("\t *** SCHEME 3 NOISE ERR: %d\n", err);
        err = scheme3(file_scheme3_msg_results, mode, bn_message, 1, 0);
        printf("\t *** SCHEME 3 MSG ERR: %d\n", err);
        err = scheme3(file_scheme3_both_results, mode, bn_message, 1, 1);
        printf("\t *** SCHEME 3 BOTH ERR: %d\n"
               "\t * SCHEME 3 with %d DONE!\n\n", err, value);

        printf("\t -------------------\n");
    }

    BN_free(bn_message);

    return;
}

unsigned int run_all()
{
    err = 0;

    printf("\t * Scheme 1 started ...\t");
    err = scheme1(file_scheme1_results, "w", message, 0, 0);
    if (err != 0)
    {
        printf("\t * Scheme 1 failed!\n");
        return 0;
    }
    printf("DONE!\n");

    printf("\t * Scheme 3 started ...\t");
    err = scheme3(file_scheme3_results, "w", message, 0, 0);
    if (err != 0)
    {
        printf("\t * Scheme 1 failed!\n");
        return 0;
    }
    printf("DONE!\n");

    printf("\t * Scheme 1 random started ...\t");
    err = scheme1(file_scheme1_noise_results, "w", message, 0, 1);
    if (err != 0)
    {
        printf("\t * Scheme 1 random failed!\n");
        return 0;
    }
    printf("DONE!\n");

    printf("\t * Scheme 3 random started ...\t");
    err = scheme3(file_scheme3_noise_results, "w", message, 0, 1);
    if (err != 0)
    {
        printf("\t * Scheme 1 random failed!\n");
        return 0;
    }
    printf("DONE!\n");

    printf("\t * Scheme 1 message started ...\t");
    err = scheme1(file_scheme1_msg_results, "w", message, 1, 0);
    if (err != 0)
    {
        printf("\t * Scheme 1 message failed!\n");
        return 0;
    }
    printf("DONE!\n");

    printf("\t * Scheme 3 message started ...\t");
    err = scheme3(file_scheme3_msg_results, "w", message, 1, 0);
    if (err != 0)
    {
        printf("\t * Scheme 3 message failed!\n");
        return 0;
    }
    printf("DONE!\n");

    printf("\t * Scheme 1 both started ...\t");
    err = scheme1(file_scheme1_both_results, "w", message, 1, 1);
    if (err != 0)
    {
        printf("\t * Scheme 1 both failed!\n");
        return 0;
    }
    printf("DONE!\n");

    printf("\t * Scheme 3 both started ...\t");
    err = scheme3(file_scheme3_both_results, "w", message, 1, 1);
    if (err != 0)
    {
        printf("\t * Scheme 3 both failed!\n");
        return 0;
    }
    printf("DONE!\n");

    return err;
}

int run_all_tests()
{
    err = 0;

    err = scheme1_test(message);
    if (err == 0)
    {
        printf("\t * Scheme 1 test failed!\n");
        return -1;
    }

    err = scheme3_test(message);
    if (err == 0)
    {
        printf("\t * Scheme 3 test failed!\n");
        return -1;
    }

    err = homomorphy_test_both();
    if (err != 1)
    {
        printf("\t * Homomorphy test failed!\n");
        return 0;
    }

    err = crt_test();
    if (err != 1)
    {
        printf("\t * CRT test failed!\n");
        return 0;
    }

    err = bn_field_test();
    if (err != 1)
    {
        printf("\t * BN field test failed!\n");
        return 0;
    }

    err = precomputation(file_parse_test, &keychain_1, 100, 1);
    if (err != 0)
    {
        printf("\t * Precomputation test failed!\n");
        return 0;
    }

    err = cJSON_create_test(file_json_test);
    if (err != 0)
    {
        printf("\t * cJSON create test failed!\n");
        return 0;
    }
    err = cJSON_parse_test(file_json_test);
    if (err != 1)
    {
        printf("\t * cJSON parse test failed!\n");
        return 0;
    }

    json_1_noise = parse_JSON(file_parse_test);
    err = find_value(json_1_noise, message, result);
    if (err != 1)
    {
        printf("\t * Find value test failed!\n");
        return 0;
    }
    else
        printf("\tSECRET: %s\n\tRESULT: %s\n", BN_bn2dec(message), BN_bn2dec(result));

    return err;
}