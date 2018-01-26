// gcc -o test test.c target/debug/libpkauth_c.a -lssl -lcrypto -lutil -ldl -lrt -lpthread -lgcc_s -lc -lm

#include <stdio.h>

typedef void Any;

#include "target/pkauth.h"

int main() {
	printf("running\n");

	SystemRandom* r = rs_systemrandom();
	Algorithm* alg = rs_se_aesgcm256();
	Key* key = rs_se_gen( r, alg);

	char* encoded = rs_se_encode_key( key);
	printf("%s\n", encoded);

	rs_free_systemrandom( r);
	rs_free_se_algorithm( alg);
	rs_free_se_key( key);
	rs_free_cstring( encoded);

	printf("ran\n");

	return 2;
}
