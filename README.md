6857coin Miner
==============

This is a heavily optimized CPU miner for 6857coin for Spring 2016, which
involves finding partial SHA256 3-collisions. It uses a simple algorithm of
maintaining a huge table of preimages, indexed by the lower few bits of the
hash. It is multithreaded and vectorized with AVX2 instructions. For optimal
performance, an Intel Haswell (or newer) CPU and 12 * 2^(difficulty * 2 / 3)
bytes of RAM are required, although the memory footprint can be reduced in
exchange for longer runtimes. Achieves about 140 million hashes per second on
an Intel 12-core 2.5GHz Haswell-EP CPU with 16GB of memory.
