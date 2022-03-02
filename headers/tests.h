#ifndef __TESTS_H__
#define __TESTS_H__

#include <parameters.h>

unsigned int scheme1_test(BIGNUM *message);
unsigned int scheme3_test(BIGNUM *message);
unsigned int test_homomorphy_scheme1();
unsigned int test_homomorphy_scheme3();
unsigned int homomorphy_test_both();
unsigned int crt_test();
int bn_field_test();
int cJSON_create_test(unsigned char *file_name);
int cJSON_parse_test(unsigned char *file_name);

#endif