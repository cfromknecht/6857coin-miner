#ifndef COLLIDER_WORKER_H
#define COLLIDER_WORKER_H

#include <stdint.h>

struct entry {
	uint64_t nonceA;
	uint64_t nonceB;
	uint64_t sum;
};
typedef struct entry entry;
typedef int mutex;
int find_collisions(entry *entries, mutex *locks, uint64_t entry_mask,
                     uint64_t difficulty_mask, uint64_t nonce,
                     uint8_t *header, int iters, uint64_t *result);

#endif // COLLIDER_WORKER_H
