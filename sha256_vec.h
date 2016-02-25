#ifndef SHA256_VEC_H
#define SHA256_VEC_H

#include <stdint.h>
#include "sha256.h"

#define SHA256_VEC_SIZE 8
typedef uint32_t sha256_vec __attribute__ ((vector_size (sizeof(uint32_t) * SHA256_VEC_SIZE)));

struct sha256_v_state {
	sha256_vec state[SHA256_LEN_WORDS];
};
typedef struct sha256_v_state sha256_v_state;

void sha256_v_initialize(sha256_v_state *s);
void sha256_v_append(sha256_v_state *s, sha256_vec *chunk);
void sha256_v(sha256_vec *in, uint64_t len, sha256_vec *out);

#endif // SHA256_VEC_H
