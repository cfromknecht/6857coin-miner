#include <string.h>
#include <stdio.h>

#include "sha256.h"

typedef sha256_word word;

static inline void set_byte(word *a, uint8_t b, int i) {
  int shift = 24 - 8 * (i % 4);
  a[i/4] |= b << shift;
}

uint64_t sha256_padded_length(uint64_t len) {
  int chunks = (len * 8 + 1 + 64 + 511) / 512;
  return chunks * 512 / 32;
}

void sha256_preprocess(uint8_t *in, uint64_t len, word *out) {
  memset(out, 0, sha256_padded_length(len) * sizeof(*out));
  int i = 0;
  // copy bytes
  for (i = 0; i < len; i++) {
    set_byte(out, in[i], i);
  }

  // padding
  set_byte(out, 0x80, i++);
  while ((i + 8) % 64) {
    set_byte(out, 0, i++);
  }

  // length
  uint64_t len_bits = len * 8;
  for (int j = 0; j < 8; j++) {
    set_byte(out, len_bits >> (56 - j * 8), i++);
  }
}

void sha256_postprocess(word *in, uint8_t *out) {
  for (int i = 0; i < 8; i++) {
    for (int j = 0; j < 4; j++) {
      out[4*i + j] = (in[i] >> (24 - j * 8)) & 0xff;
    }
  }
}

static inline word rotate(word x, int y) {
  return x << y | x >> (32-y);
}

static inline word ch(word a, word b, word c) {
  return (a & b) ^ ((~a) & c);
}

static inline word maj(word a, word b, word c) {
  return (a & b) ^ (a & c) ^ (b & c);
}

static inline word S(word a, int r1, int r2, int r3) {
  return rotate(a, r1) ^ rotate(a, r2) ^ rotate(a, r3);
}

static inline word schedule(word a, word b, word c, word d) {
  word s0 = rotate(a, 25) ^ rotate(a, 14) ^ (a >> 3);
  word s1 = rotate(b, 15) ^ rotate(b, 13) ^ (b >> 10);
  return s0 + s1 + c + d;
}

#define iter1(v, w, chunk, i, k) { \
  w[i] = chunk[i]; \
  compress(v, w, i, k); \
}

#define iter2(v, w, i, k) { \
  w[i] = schedule(w[i-15], w[i-2], w[i-16], w[i-7]); \
  compress(v, w, i, k); \
}

#define compress(v, w, i, k) { \
  int j = 7*i; \
  word a = v[j%8], b = v[(j+1)%8], c = v[(j+2)%8]; \
  word e = v[(j+4)%8], f = v[(j+5)%8], g = v[(j+6)%8], h = v[(j+7)%8]; \
  word t1 = h + S(e, 26, 21, 7) + ch(e, f, g) + k + w[i]; \
  word t2 = S(a, 30, 19, 10) + maj(a, b, c); \
  v[(j+3)%8] += t1; \
  v[(j+7)%8] = t1 + t2; \
}

void sha256_initialize(sha256_state *s) {
  s->state[0] = 0x6a09e667U;
  s->state[1] = 0xbb67ae85U;
  s->state[2] = 0x3c6ef372U;
  s->state[3] = 0xa54ff53aU;
  s->state[4] = 0x510e527fU;
  s->state[5] = 0x9b05688cU;
  s->state[6] = 0x1f83d9abU;
  s->state[7] = 0x5be0cd19U;
}

void sha256_append(sha256_state *s, word *chunk) {
  word v[8], w[64];
  memcpy(v, s->state, sizeof(v));

  iter1(v, w, chunk, 0, 0x428a2f98U);
  iter1(v, w, chunk, 1, 0x71374491U);
  iter1(v, w, chunk, 2, 0xb5c0fbcfU);
  iter1(v, w, chunk, 3, 0xe9b5dba5U);
  iter1(v, w, chunk, 4, 0x3956c25bU);
  iter1(v, w, chunk, 5, 0x59f111f1U);
  iter1(v, w, chunk, 6, 0x923f82a4U);
  iter1(v, w, chunk, 7, 0xab1c5ed5U);
  iter1(v, w, chunk, 8, 0xd807aa98U);
  iter1(v, w, chunk, 9, 0x12835b01U);
  iter1(v, w, chunk, 10, 0x243185beU);
  iter1(v, w, chunk, 11, 0x550c7dc3U);
  iter1(v, w, chunk, 12, 0x72be5d74U);
  iter1(v, w, chunk, 13, 0x80deb1feU);
  iter1(v, w, chunk, 14, 0x9bdc06a7U);
  iter1(v, w, chunk, 15, 0xc19bf174U);

  iter2(v, w, 16, 0xe49b69c1U);
  iter2(v, w, 17, 0xefbe4786U);
  iter2(v, w, 18, 0x0fc19dc6U);
  iter2(v, w, 19, 0x240ca1ccU);
  iter2(v, w, 20, 0x2de92c6fU);
  iter2(v, w, 21, 0x4a7484aaU);
  iter2(v, w, 22, 0x5cb0a9dcU);
  iter2(v, w, 23, 0x76f988daU);
  iter2(v, w, 24, 0x983e5152U);
  iter2(v, w, 25, 0xa831c66dU);
  iter2(v, w, 26, 0xb00327c8U);
  iter2(v, w, 27, 0xbf597fc7U);
  iter2(v, w, 28, 0xc6e00bf3U);
  iter2(v, w, 29, 0xd5a79147U);
  iter2(v, w, 30, 0x06ca6351U);
  iter2(v, w, 31, 0x14292967U);
  iter2(v, w, 32, 0x27b70a85U);
  iter2(v, w, 33, 0x2e1b2138U);
  iter2(v, w, 34, 0x4d2c6dfcU);
  iter2(v, w, 35, 0x53380d13U);
  iter2(v, w, 36, 0x650a7354U);
  iter2(v, w, 37, 0x766a0abbU);
  iter2(v, w, 38, 0x81c2c92eU);
  iter2(v, w, 39, 0x92722c85U);
  iter2(v, w, 40, 0xa2bfe8a1U);
  iter2(v, w, 41, 0xa81a664bU);
  iter2(v, w, 42, 0xc24b8b70U);
  iter2(v, w, 43, 0xc76c51a3U);
  iter2(v, w, 44, 0xd192e819U);
  iter2(v, w, 45, 0xd6990624U);
  iter2(v, w, 46, 0xf40e3585U);
  iter2(v, w, 47, 0x106aa070U);
  iter2(v, w, 48, 0x19a4c116U);
  iter2(v, w, 49, 0x1e376c08U);
  iter2(v, w, 50, 0x2748774cU);
  iter2(v, w, 51, 0x34b0bcb5U);
  iter2(v, w, 52, 0x391c0cb3U);
  iter2(v, w, 53, 0x4ed8aa4aU);
  iter2(v, w, 54, 0x5b9cca4fU);
  iter2(v, w, 55, 0x682e6ff3U);
  iter2(v, w, 56, 0x748f82eeU);
  iter2(v, w, 57, 0x78a5636fU);
  iter2(v, w, 58, 0x84c87814U);
  iter2(v, w, 59, 0x8cc70208U);
  iter2(v, w, 60, 0x90befffaU);
  iter2(v, w, 61, 0xa4506cebU);
  iter2(v, w, 62, 0xbef9a3f7U);
  iter2(v, w, 63, 0xc67178f2U);

  for (int i = 0; i < 8; i++) {
    s->state[i] += v[i];
  }
}

void sha256(word *in, uint64_t len, word *out) {
  sha256_state s;
  sha256_initialize(&s);

  // loop through chunks
  word *end = in + len;
  for (word *chunk = in; chunk < end; chunk += 16) {
    sha256_append(&s, chunk);
  }

  for (int i = 0; i < SHA256_LEN_WORDS; i++) {
    out[i] = s.state[i];
  }
}
