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
 */
#pragma once
#include <stdint.h>

#define RING_CAP  1024              /* fixed capacity; MUST be a power of two */
#define RING_MASK ((unsigned)(RING_CAP) - 1u)

/* ---- Named wire constants ----
 * Used at ring_push call sites instead of bare integer literals.
 * The Kotlin drain thread parses the pipe-delimited wire format:
 *   ts|host|port|transport|tier|blocked|origin_addr
 * where transport and tier use the values below.
 * See NativeShimBackend.RingEventParser for the Kotlin side. */
#define POSEIDON_TRANSPORT_TCP  0   /* TCP or unknown socket type    */
#define POSEIDON_TRANSPORT_UDP  1   /* connectionless UDP            */
#define POSEIDON_TRANSPORT_DNS  2   /* DNS query/block               */

#define POSEIDON_TIER_LIBC      0   /* libc-interceptor (DT_NEEDED)  */
#define POSEIDON_TIER_SECCOMP   1   /* seccomp USER_NOTIF supervisor */

/* Plain-old-data payload carried through the ring.
 * All fields are written by the producer BEFORE the seq publish; the consumer
 * copies the struct as a unit after it sees seq == tail + 1.
 *
 * Wire format (pipe-delimited string produced by drainEvents JNI):
 *   ts|host|port|transport|tier|blocked|origin_addr
 *   ts          = CLOCK_MONOTONIC nanoseconds (uint64, or 0)
 *   host        = hostname or IP literal (≤63 chars, NUL-terminated)
 *   port        = destination port (0 if unknown)
 *   transport   = POSEIDON_TRANSPORT_TCP/UDP/DNS
 *   tier        = POSEIDON_TIER_LIBC/SECCOMP
 *   blocked     = 1 if blocked, 0 if allowed or monitor-violation
 *   origin_addr = dladdr()-resolvable return-address into calling SDK .so
 */
struct ring_event {
    uint64_t ts;
    char     host[64];
    int      port;
    int      transport;
    int      tier;
    int      blocked;
    uint64_t origin_addr;
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
