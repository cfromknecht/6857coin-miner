#ifndef COLLIDER_WORKER_H
#define COLLIDER_WORKER_H

#include <stdint.h>

struct __attribute__((__packed__)) table1_entry {
	uint64_t nonceA;
	uint32_t partial;
};
typedef struct table1_entry table1_entry;

struct table2_entry {
	uint64_t nonceB;
	uint64_t sum;
};
typedef struct table2_entry table2_entry;

typedef int mutex;
int find_collisions(table1_entry *table1, int log_table1_size, table2_entry
		*table2, int log_table2_size, mutex *locks, int difficulty,
		uint64_t nonce, uint8_t *header, int iters, uint64_t *result);

#endif // COLLIDER_WORKER_H
