#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <paillier.h>

int main() {
    printf("\n---PAILLIER test---\n");
    unsigned int err = 0;
    struct paillierKeychain p_keyring = {{""}};
    
    err += generate_keypair(&p_keyring);
    printf("ERR: %u\nKEYS:\n|--> L: %s\n|--> M: %s\n|--> N: %s\n|--> N_SQ: %s\n|--> G: %s\n",
        err, p_keyring.sk.l, p_keyring.sk.m, p_keyring.pk.n, p_keyring.pk.n_sq, p_keyring.pk.g);
    
    unsigned char *secret = "125";
    printf("SECRET: %s\n", secret);
    
    unsigned char enc[BUFFER];
    err += encrypt(p_keyring.pk, secret, enc);
    printf("ENC: %s\n", enc);
    
    unsigned char dec[BUFFER];
    err += decrypt(&p_keyring, enc, dec);
    printf("DEC: %s\n", dec);
    
    
    printf("\n---HOMOMORPHIC TEST---\n");
    err += test_homomorphic();
    printf("\n\nERR: %u (if 4 → OK)\n", err);

    return 0;
}