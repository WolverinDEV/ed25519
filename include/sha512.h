#ifndef SHA512_H
#define SHA512_H

#include <assert.h>

#ifdef USE_OPENSSL
	#include <openssl/sha.h>

	typedef SHA512_CTX sha512_context;
#else
	#include <stddef.h>

	#include "fixedint.h"

	/* state */
	typedef struct sha512_context_ {
		uint64_t  length, state[8];
		size_t curlen;
		unsigned char buf[128];
	} sha512_context;
#endif

typedef struct sha512_functions_ {
	int(*_ed_sha512_init)(sha512_context*);
	int(*_ed_sha512_final)(sha512_context*, unsigned char *);
	int(*_ed_sha512_update)(sha512_context*, const unsigned char *, size_t);
} sha512_functions;
extern sha512_functions _ed_sha512_functions;

void _ed_sha512_validate() {
	assert(_ed_sha512_functions._ed_sha512_init);
	assert(_ed_sha512_functions._ed_sha512_final);
	assert(_ed_sha512_functions._ed_sha512_update);
}
int _ed_sha512(const unsigned char *message, size_t message_len, unsigned char *out) {
	_ed_sha512_validate();

	int result = 1;
	sha512_context ctx;
	result &= _ed_sha512_functions._ed_sha512_init(&ctx);
	result &= _ed_sha512_functions._ed_sha512_update(&ctx, message, message_len);
	result &= _ed_sha512_functions._ed_sha512_final(&ctx, out);
	return result;
}

#endif
