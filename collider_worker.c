#include <stdint.h>
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

int insert(entry *entries, mutex *locks, int entry_mask,
    uint64_t sum, uint64_t nonce, uint64_t *result) {
  int ret = 0;

  int lockidx = sum & 65535;
  lock(&locks[lockidx]);

  int bucket = sum & entry_mask;
  entry *entry = &entries[bucket];

  if (!entry->nonceA) {
    entry->nonceA = nonce;
    entry->sum = sum;
    goto cleanup;
  }

  if (entry->sum != sum)
    goto cleanup;

  if (!entry->nonceB) {
    entry->nonceB = nonce;
    goto cleanup;
  }

  result[0] = entry->nonceA;
  result[1] = entry->nonceB;
  result[2] = nonce;
  ret = 1;

cleanup:
  unlock(&locks[lockidx]);
  return ret;
}

int find_collisions(entry *entries, mutex *locks, uint64_t entry_mask,
                     uint64_t difficulty_mask, uint64_t nonce,
                     uint8_t *header, int iters, uint64_t *result) {
  int orig_nonce = nonce % 256;
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
      sum &= difficulty_mask;
      if (insert(entries, locks, entry_mask, sum, nonce+j, result)) {
        return 1;
      }
    }

    nonce += SHA256_VEC_SIZE;
  }
  return 0;
}
