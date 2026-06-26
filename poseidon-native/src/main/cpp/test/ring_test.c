/* ring_test.c — host-toolchain test for event_ring MPSC correctness.
 *
 * DEFERRED: Requires a host C toolchain (gcc/clang with pthreads and C11
 * atomics) or an on-device NDK run.  Cannot be compiled or executed in
 * build environments where only the Android NDK cross-compiler is available
 * and no host CRT/glibc-dev is present.  See task-5.1-report.md for the
 * Checkpoint 5 on-device validation plan.
 *
 * Usage (when a host toolchain IS available):
 *   cd poseidon-native/src/main/cpp/test
 *   cmake -S . -B build && cmake --build build && ./build/ring_test
 * Expected output:
 *   pushed=2000 drained=<N> drops=<D> (N+D == 2000)
 *   OK
 *
 * What it checks:
 *   - Two producer threads each push PER_THREAD events concurrently.
 *   - The main thread drains repeatedly until no more events arrive.
 *   - Asserts that  drained + dropped == total_pushed  (no events lost or
 *     double-counted; drops are events discarded when the ring was full).
 *   - Does NOT assert ordering across producers (MPSC offers no cross-producer
 *     FIFO guarantee); does assert that count is correct.
 */
#include <stdio.h>
#include <pthread.h>
#include <stdint.h>
#include "../include/event_ring.h"

#define PER_THREAD 1000
#define N_THREADS  2

static void *producer(void *arg) {
    long id = (long)arg;
    for (int i = 0; i < PER_THREAD; i++) {
        ring_push(
            (uint64_t)(id * PER_THREAD + i),  /* ts: unique per event  */
            "test.example.com",
            443,
            0,                                  /* transport: TCP       */
            0,                                  /* tier: libc           */
            (i % 3 == 0) ? 1 : 0,              /* blocked: every 3rd   */
            (uint64_t)0xdeadbeefULL
        );
    }
    return NULL;
}

int main(void) {
    pthread_t threads[N_THREADS];
    for (long t = 0; t < N_THREADS; t++)
        pthread_create(&threads[t], NULL, producer, (void *)t);
    for (int t = 0; t < N_THREADS; t++)
        pthread_join(threads[t], NULL);

    /* Drain: loop until nothing more is available. */
    struct ring_event out[RING_CAP];
    int drained = 0, batch;
    while ((batch = ring_drain(out + drained, RING_CAP - drained)) > 0)
        drained += batch;

    uint64_t drops = ring_dropped();
    int total_pushed = N_THREADS * PER_THREAD;

    printf("pushed=%d drained=%d drops=%llu sum=%d\n",
           total_pushed, drained, (unsigned long long)drops,
           drained + (int)drops);

    if (drained + (int)drops == total_pushed) {
        printf("OK\n");
        return 0;
    } else {
        printf("FAIL: count mismatch (expected %d, got drained=%d + drops=%llu = %d)\n",
               total_pushed, drained, (unsigned long long)drops,
               drained + (int)drops);
        return 1;
    }
}
