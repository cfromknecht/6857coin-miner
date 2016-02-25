#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include "sha256.h"

#define SHA256_LEN_WORDS 8
#define SHA256_LEN_BYTES 32

typedef uint32_t sha256_word;

struct sha256_state {
	sha256_word state[SHA256_LEN_WORDS];
};

typedef struct sha256_state sha256_state;

extern uint64_t sha256_padded_length(uint64_t len);
extern void sha256_preprocess(uint8_t *in, uint64_t len, sha256_word *out);
extern void sha256_postprocess(sha256_word *in, uint8_t *out);

void sha256_initialize(sha256_state *s);
void sha256_append(sha256_state *s, sha256_word *chunk);
extern void sha256(sha256_word *in, uint64_t len, sha256_word *out);

#endif // SHA256_H
