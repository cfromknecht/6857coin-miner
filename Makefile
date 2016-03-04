all: sha256_test

run: sha256_test
	./sha256_test

.PHONY: all run

clean:
	@rm *.o sha256_test

CFLAGS = -g -g3 -O3 -Wall -march=native -DSHA256_TEST
LDFLAGS =

sha256_test: sha256.o sha256_vec.o
