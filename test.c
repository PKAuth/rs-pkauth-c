// gcc -o test test.c target/debug/libpkauth_c.a -lssl -lcrypto -lutil -ldl -lrt -lpthread -lgcc_s -lc -lm

#include <stdio.h>

typedef void Any;

#include "target/pkauth.h"

void zeroString( char* s) {
	while ( *s != 0) {
		*s = 0;
		s++;
	}
}

void printKey( Key* key) {
	char* e = rs_se_encode_key( key);
	printf("%s\n", e);
	rs_free_cstring( e);
}

int main() {
	printf("running\n");

	SystemRandom* r = rs_systemrandom();
	Algorithm* alg = rs_se_aesgcm256();
	Key* key = rs_se_gen( r, alg);

	char* encoded = rs_se_encode_key( key);
	printf("%s\n", encoded);

	Key* decoded = rs_se_decode_key( encoded);

	printKey( decoded);
	zeroString( encoded);
	printKey( decoded);
	rs_free_cstring( encoded);
	printKey( decoded);

	rs_free_systemrandom( r);
	rs_free_se_algorithm( alg);
	rs_free_se_key( key);
	rs_free_se_key( decoded);

	printf("ran\n");

	return 2;
}
