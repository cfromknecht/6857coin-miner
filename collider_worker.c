#include <stdio.h>

#include "collider_worker.h"
#include "sha256_vec.h"

static void lock(volatile mutex *m) {
  // volatile actually required to make test-and-test-and-set optimization work
  while (1)
    if (*m == 0 && __sync_bool_compare_and_swap(m, 0, 1))
      return;
}

static void unlock(mutex *m) {
  __sync_lock_release(m);
}

uint64_t insertL1(table1_entry *table1, int log_table1_size, mutex *locks, int
    difficulty, uint64_t sum, uint64_t nonce) {

  uint64_t ret = 0;

  int lockidx = sum & 65535;
  lock(&locks[lockidx]);

  int bucket = sum & ((1ULL << log_table1_size) - 1);
  table1_entry *e = &table1[bucket];

  int partial = sum >> log_table1_size;

  if (!e->nonceA) {
    e->nonceA = nonce;
    e->partial = partial;
    goto cleanup;
  }

  if (e->partial != partial)
    goto cleanup;

  ret = e->nonceA;

cleanup:
  unlock(&locks[lockidx]);
  return ret;
}

uint64_t insertL2(table2_entry *table2, int log_table2_size, mutex *locks,
    uint64_t sum, uint64_t nonce) {

  uint64_t ret = 0;

  int lockidx = sum & 65535;
  lock(&locks[lockidx]);

  int bucket = sum & ((1ULL << log_table2_size) - 1);
  table2_entry *e = &table2[bucket];

  if (!e->nonceB) {
    e->nonceB = nonce;
    e->sum = sum;
    goto cleanup;
  }

  if (e->sum != sum)
    goto cleanup;

  ret = e->nonceB;

cleanup:
  unlock(&locks[lockidx]);
  return ret;
}

int find_collisions(table1_entry *table1, int log_table1_size, table2_entry
		*table2, int log_table2_size, mutex *locks, int difficulty,
		uint64_t nonce, uint8_t *header, int iters, uint64_t *result) {
  sha256_word buf[32]; // 128 bytes
  sha256_preprocess(header, 89, buf);

  sha256_vec vbuf[32]; // 8x 128 bytes
  for (int i = 0; i < 32; i++) {
    for (int j = 0; j < SHA256_VEC_SIZE; j++) {
      vbuf[i][j] = buf[i];
    }
  }

  sha256_v_state prefix_state;
  sha256_v_initialize(&prefix_state);
  sha256_v_append(&prefix_state, vbuf);

  sha256_vec *suffix = &vbuf[16];
  for (int i = 0; i < iters / SHA256_VEC_SIZE; i++) {
    sha256_v_state s = prefix_state;

    for (int j = 0; j < SHA256_VEC_SIZE; j++) {
      suffix[4][j] = nonce >> 32;
      suffix[5][j] = nonce + j;
    }

    sha256_v_append(&s, suffix);

    for (int j = 0; j < SHA256_VEC_SIZE; j++) {
      uint64_t sum = ((uint64_t) s.state[6][j] << 32) | s.state[7][j];
      sum &= (1ULL << difficulty) - 1;
      if (result[0] = insertL1(table1, log_table1_size, locks, difficulty, sum, nonce+j)) {
        if (result[1] = insertL2(table2, log_table2_size, locks, sum, nonce+j)) {
          result[2] = nonce+j;
          return 1;
        }
      }
    }

    nonce += SHA256_VEC_SIZE;
  }
  return 0;
}
