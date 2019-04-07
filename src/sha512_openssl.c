#include <openssl/sha.h>
#include "../include/sha512.h"


int _ed_sha512_init(sha512_context * md) {
	return SHA512_Init(md) != 1; /* Returns 0 on success */
}

int _ed_sha512_final(sha512_context * md, unsigned char *out) {
	return SHA512_Final(out, md) != 1; /* Returns 0 on success */
}

int _ed_sha512_update(sha512_context * md, const unsigned char *in, size_t inlen) {
	return SHA512_Update(md, in, inlen) != 1; /* Returns 0 on success */
}

extern sha512_functions _ed_sha512_functions = {
		_ed_sha512_init,
		_ed_sha512_final,
		_ed_sha512_update
};