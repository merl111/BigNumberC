#include "bigint.h"

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){
    
    BIGNUM *a = BN_create();
    BN_dec2bn(&a, "123");

    BIGNUM *b = BN_create();
    BN_dec2bn(&b, "123");

    BIGNUM *c = BN_create();
    BN_dec2bn(&c, "-123");

    BIGNUM *result  = BN_create();
    BIGNUM *rem = BN_create();

    BN_add(result, b, a);
    char *x = BN_bn2dec(result);
    printf("result: %s\n", x);

    BN_sub(b, result, a);
    x = BN_bn2dec(b);
    printf("result: %s\n", x);

    BN_add(result, b, c);
    x = BN_bn2dec(result);
    printf("result: %s\n", x);
    BN_dec2bn(&a, "3");
    BN_dec2bn(&b, "1");


    BN_dec2bn(&a, "12");
    BN_dec2bn(&b, "12");

    BN_rshift1(result, b);
    x = BN_bn2dec(result);
    printf("result rshift result: %s\n", x);

    x = BN_bn2dec(b);
    printf("result rshift b: %s\n", x);


    BN_dec2bn(&a, "1");
    BN_dec2bn(&b, "3");

    BN_lshift(result, a, 3);
    x = BN_bn2dec(result);
    printf("result lshift a: %s\n", x);
    x = BN_bn2dec(b);
    printf("result lshift b: %s\n", x);

    BN_dec2bn(&a, "3000000000000000000000000000000000000000000000000000000000");
    BN_dec2bn(&b, "-2");
    BN_mul(result, a, b);
    x = BN_bn2dec(result);
    printf("result mul a*b: %s\n", x);

    BN_dec2bn(&a, "8");
    BN_dec2bn(&b, "-3");

    BN_rshift(result, a, 3);
    x = BN_bn2dec(result);
    printf("result neg lshift a: %s\n", x);

    BN_dec2bn(&a, "80");
    BN_dec2bn(&b, "10");

    BN_div(result, rem, a, b);
    x = BN_bn2dec(result);
    printf("result division: %s\n", x);
    x = BN_bn2dec(rem);
    printf("remainder division: %s\n", x);

    BN_dec2bn(&a, "70");
    BN_dec2bn(&b, "30");

    BN_div(result, rem, a, b);
    x = BN_bn2dec(result);
    printf("2 result division: %s\n", x);
    x = BN_bn2dec(rem);
    printf("2 remainder division: %s\n", x);

    BN_dec2bn(&a, "10.5");
    BN_dec2bn(&b, "1");

    BN_div(result, rem, a, b);
    x = BN_bn2dec(result);
    printf("3 result division: %s\n", x);
    x = BN_bn2dec(rem);
    printf("3 remainder division: %s\n", x);


    BN_dec2bn(&a, "10.5");
    long res = 0;
    int ret;
    ret = BN_bn2long(a, &res);
    printf("bn2long return: %d\n", ret);
    printf("bn2long result: %ld\n", res);


    BN_dec2bn(&a, "100000000000020");
    unsigned char *bin;
    bin = malloc(sizeof(unsigned long) * a->top+10000);
    printf("num_bytes: %d\n", BN_num_bytes(a));
    ret = BN_bn2bin(a, bin);
    printf("num_bytes: %d\n", BN_num_bytes(a));

    for (int i=0; i < BN_num_bytes(a); i++) {
        printf("%02x", (unsigned int) bin[i]);
    }

    printf("\n");



    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(result);
    BN_free(rem);

    return 0;
}

