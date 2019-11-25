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

    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(result);

    return 0;
}

