/* event_ring.h — lock-free MPSC event ring for Poseidon native shim.
 *
 * Multiple producer threads (connect/sendto/seccomp-supervisor) push events;
 * exactly ONE consumer thread (the JVM drain, every ~250 ms) drains them.
 * No locks, no malloc, no logging anywhere in this module.
 *
 * Design (MPSC via per-slot sequence numbers + CAS on head):
 *   g_head is claimed by producers via atomic CAS (not fetch_add) so that a
 *   full ring is detected BEFORE any slot is claimed, leaving no "ghost"
 *   position that would stall the consumer.  Each claimed slot is published by
 *   storing  slot.seq = pos + 1  (release).  The consumer polls
 *   slot.seq == tail + 1  (acquire) before copying and advancing tail.  No
 *   slot reset is required: because pos is monotonically increasing, the value
 *   pos+1 is unique within the uint32 wrap-around period (4 billion events).
 *
 * Drop-on-full:
 *   If head - tail >= RING_CAP the CAS loop increments g_dropped and returns
 *   without claiming or writing any slot, so the consumer never stalls.
 *
 * RUNTIME / CONCURRENCY UNVERIFIED — deferred to Checkpoint 5.
 * No host toolchain is available to run ring_test; no device is connected.
 */
#pragma once
#include <stdint.h>

#define RING_CAP  1024              /* fixed capacity; MUST be a power of two */
#define RING_MASK ((unsigned)(RING_CAP) - 1u)

/* Plain-old-data payload carried through the ring.
 * All fields are written by the producer BEFORE the seq publish; the consumer
 * copies the struct as a unit after it sees seq == tail + 1.             */
struct ring_event {
    uint64_t ts;           /* CLOCK_MONOTONIC nanoseconds, or 0 if unavailable */
    char     host[64];     /* hostname or IP literal; NUL-terminated; truncated */
    int      port;         /* destination port (0 if unknown / DNS block)        */
    int      transport;    /* 0=TCP/unknown  1=UDP  2=DNS                        */
    int      tier;         /* 0=libc-interceptor  1=seccomp-supervisor           */
    int      blocked;      /* 1=blocked  0=allowed or monitor-violation           */
    uint64_t origin_addr;  /* dladdr()-resolvable return-address into caller .so  */
};

/* Push one event from ANY thread (multi-producer hot path).
 * NEVER allocates, NEVER logs, NEVER blocks, NEVER calls any blocking fn.
 * Drops silently (increments ring_dropped()) when the ring is full.        */
void ring_push(uint64_t ts,
               const char *host_or_ip,
               int port,
               int transport,
               int tier,
               int blocked,
               uint64_t origin_addr);

/* Drain up to `max` events into `out` (call from SINGLE consumer thread only).
 * Returns the number of events copied (0 .. max).                          */
int ring_drain(struct ring_event *out, int max);

/* Cumulative count of events dropped due to ring-full since library load.  */
uint64_t ring_dropped(void);
