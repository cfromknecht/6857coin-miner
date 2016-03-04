#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "sha256.h"
#include "sha256_vec.h"

uint8_t hex_to_nibble(char *str) {
  if (*str >= 'a' && *str <= 'f') {
    return *str - 'a' + 10;
  }
  if (*str >= '0' && *str <= '9') {
    return *str - '0';
  }
  assert(0);
}

uint8_t hex_to_byte(char *str) {
  return (hex_to_nibble(str) << 4) | hex_to_nibble(str+1);
}

void check(uint8_t *hash, char *expected, int suppress) {
  if (!suppress)
    printf("expected: %s\n", expected);
  if (!suppress)
    printf("got: ");
  for (int i = 0; i < SHA256_LEN_BYTES; i++) {
    if (!suppress)
      printf("%02x", hash[i]);
  }

  if (!suppress)
    printf("\n");
  for (int i = 0; i < SHA256_LEN_BYTES; i++) {
    if (hash[i] != hex_to_byte(&expected[2*i])) {
      printf("...mismatch\n");
      return;
    }
  }
  if (!suppress)
    printf("...pass\n");
}

void test_scalar(char *in, char *expected) {
  printf("testing scalar...\n");
  int inlen = strlen(in);
  int wlen = sha256_padded_length(inlen);
  sha256_word *win = malloc(wlen * sizeof(*win));
  sha256_preprocess((uint8_t *) in, inlen, win);

  sha256_word tmp_hash[SHA256_LEN_WORDS];
  sha256(win, wlen, tmp_hash);

  uint8_t hash[SHA256_LEN_BYTES];
  sha256_postprocess(tmp_hash, hash);

  check(hash, expected, 0);
  free(win);
}

void test_vector(char *in, char *expected) {
  printf("testing vector...\n");
  int inlen = strlen(in);
  int wlen = sha256_padded_length(inlen);
  sha256_word *win = malloc(wlen * sizeof(*win));
  sha256_preprocess((uint8_t *) in, inlen, win);

  sha256_vec *vin = malloc(wlen * sizeof(*vin));
  for (int i = 0; i < wlen; i++) {
    for (int j = 0; j < SHA256_VEC_SIZE; j++) {
      vin[i][j] = win[i];
    }
  }

  sha256_vec tmp_hashes[SHA256_LEN_WORDS];
  sha256_v(vin, wlen, tmp_hashes);

  for (int i = 0; i < SHA256_VEC_SIZE; i++) {
    sha256_word tmp_hash[SHA256_LEN_WORDS];
    for (int j = 0; j < SHA256_LEN_WORDS; j++) {
      tmp_hash[j] = tmp_hashes[j][i];
    }

    uint8_t hash[SHA256_LEN_BYTES];
    sha256_postprocess(tmp_hash, hash);

    check(hash, expected, i != 0);
  }

  free(win);
  free(vin);
}

void test(char *in, char *expected) {
  test_scalar(in, expected);
  test_vector(in, expected);
}

void print_rate(struct timespec start, struct timespec end, int size) {
  double msecs = (end.tv_nsec - start.tv_nsec)/1000000.0 + (end.tv_sec - start.tv_sec) * 1000;
  double rate = size / msecs / 1000;
  printf("... %.6f msec, %.6f MB/s\n", msecs, rate);
}

void benchmark_scalar(int size) {
  printf("scalar benchmark");

  sha256_word *input = malloc(sizeof(*input) * size);
  for (int i = 0; i < size; i++) {
    input[i] = rand();
  }

  struct timespec start, end;
  clock_gettime(CLOCK_MONOTONIC, &start);

  sha256_word hash[SHA256_LEN_WORDS];
  sha256(input, size, hash);

  clock_gettime(CLOCK_MONOTONIC, &end);
  print_rate(start, end, size * sizeof(*input));
  free(input);
}

void benchmark_vector(int size) {
  printf("vector benchmark");

  int vsize = size / SHA256_VEC_SIZE;
  sha256_vec *input;
  if (posix_memalign((void **) &input, 32, sizeof(*input) * vsize)) {
    return;
  }
  for (int i = 0; i < vsize; i++) {
    for (int j = 0; j < SHA256_VEC_SIZE; j++) {
      input[i][j] = rand();
    }
  }

  struct timespec start, end;
  clock_gettime(CLOCK_MONOTONIC, &start);

  sha256_vec hash[SHA256_LEN_WORDS];
  sha256_v(input, vsize, hash);

  clock_gettime(CLOCK_MONOTONIC, &end);
  print_rate(start, end, vsize * sizeof(*input));
  free(input);
}

#ifdef SHA256_TEST
int main() {
  test("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  test("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  test("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  test("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
      "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");

  int size = 25000000; // 100 MB
  benchmark_scalar(size);
  benchmark_vector(size);
}
#endif
