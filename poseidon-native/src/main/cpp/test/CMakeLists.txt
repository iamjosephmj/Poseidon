cmake_minimum_required(VERSION 3.18)
project(poseidon_glob_test C)
add_executable(glob_test glob_test.c)

# ring_test: MPSC event-ring concurrency test (Task 5.1).
# Requires a host C toolchain with pthreads + C11 atomics.
# DEFERRED: not run in this build environment (Android NDK cross-compiler only,
# no host CRT/glibc-dev).  Run manually when a host toolchain is available:
#   cmake -S . -B build && cmake --build build && ./build/ring_test
project(poseidon_ring_test C)
add_executable(ring_test ring_test.c ../event_ring.c)
target_compile_options(ring_test PRIVATE -std=c11)
target_link_libraries(ring_test pthread)
