/* event_ring.c — lock-free MPSC ring implementation.
 *
 * See event_ring.h for the full design rationale.
 *
 * Correctness sketch (for a human reviewer — runtime unverified):
 *
 *   PRODUCERS (any thread, concurrent):
 *     1. Load g_head (relaxed).
 *     2. Load g_tail (acquire) and compare: if head - tail >= RING_CAP the
 *        ring is full; increment g_dropped and return.
 *     3. CAS g_head: head -> head+1.  On failure the loaded head is refreshed
 *        and we loop from step 2.  On success we own slot pos = head (old).
 *     4. Write event fields into g_ring[pos & RING_MASK].data.
 *     5. Publish: atomic_store(&slot->seq, pos + 1, release).
 *
 *   CONSUMER (single thread, JVM drain):
 *     1. Read tail (relaxed — only this thread writes tail).
 *     2. Acquire-load slot->seq.  If seq != tail+1 the producer hasn't
 *        published yet (or the slot is genuinely empty): stop draining.
 *     3. Copy slot->data into the caller's buffer.
 *     4. Advance tail by 1.  (No seq reset needed; the producer at position
 *        tail+RING_CAP will write seq = tail+RING_CAP+1, which is a different
 *        value from the current tail+1.)
 *     5. Repeat up to `max` times, then release-store the new tail.
 *
 *   Memory ordering:
 *     - Producer: all data writes happen-before the release-store of seq.
 *     - Consumer: the acquire-load of seq synchronises-with the release-store,
 *       so the consumer sees all data written by that producer.
 *     - Tail is only touched by the consumer; its release-store at the end of
 *       ring_drain makes the new tail visible to producers' acquire-load of
 *       g_tail in their full-check.
 *
 */
#include "event_ring.h"
#include <string.h>
#include <stdatomic.h>

/* Per-slot: data payload + a monotonic sequence number. */
typedef struct {
    struct ring_event data;
    _Atomic unsigned  seq;  /* 0 = initial/never-written; producer sets pos+1 */
} ring_slot;

/* All in BSS; zero-initialised by the dynamic linker.
 * seq == 0 for every slot at startup, which is correct: the consumer starts
 * at tail == 0 and expects slot[0].seq == 1 before reading slot 0.        */
static ring_slot     g_ring[RING_CAP];
static _Atomic unsigned g_head    = 0;  /* next position to claim (producers)  */
static _Atomic unsigned g_tail    = 0;  /* consumer cursor (ring_drain only)    */
static _Atomic uint64_t g_dropped = 0;  /* cumulative drop counter              */

void ring_push(uint64_t ts,
               const char *host_or_ip,
               int port,
               int transport,
               int tier,
               int blocked,
               uint64_t origin_addr)
{
    /* ---- claim a slot via CAS (drop-on-full without claiming) ---- */
    unsigned head, tail;
    head = atomic_load_explicit(&g_head, memory_order_relaxed);
    do {
        /* Reload tail on every iteration so a draining consumer can open up
         * space while we're spinning under contention.                    */
        tail = atomic_load_explicit(&g_tail, memory_order_acquire);
        if (head - tail >= (unsigned)RING_CAP) {
            /* Ring full: drop this event; do NOT claim any slot. */
            atomic_fetch_add_explicit(&g_dropped, 1u, memory_order_relaxed);
            return;
        }
        /* CAS: try to advance head from `head` to `head+1`.
         * On failure, `head` is updated to the current g_head value and we
         * retry the full-check with the refreshed head.                   */
    } while (!atomic_compare_exchange_weak_explicit(
                 &g_head, &head, head + 1u,
                 memory_order_relaxed,   /* success: head write visible to other producers via their CAS */
                 memory_order_relaxed)); /* failure: no fence needed, just a retry */

    /* `head` now holds our claimed position (the CAS returned the old value). */
    unsigned pos = head;
    ring_slot *slot = &g_ring[pos & RING_MASK];

    /* ---- write event data (before the publish release-store below) ---- */
    struct ring_event *e = &slot->data;
    e->ts          = ts;
    e->port        = port;
    e->transport   = transport;
    e->tier        = tier;
    e->blocked     = blocked;
    e->origin_addr = origin_addr;
    if (host_or_ip) {
        strncpy(e->host, host_or_ip, sizeof(e->host) - 1u);
        e->host[sizeof(e->host) - 1u] = '\0';
    } else {
        e->host[0] = '\0';
    }

    /* ---- publish: release-store makes data visible to consumer ---- */
    atomic_store_explicit(&slot->seq, pos + 1u, memory_order_release);
}

int ring_drain(struct ring_event *out, int max)
{
    /* Single consumer: load tail without an atomic (only we write it).
     * Use relaxed; we issue an acquire-load per slot before reading data. */
    unsigned tail = atomic_load_explicit(&g_tail, memory_order_relaxed);
    int count = 0;

    while (count < max) {
        ring_slot *slot = &g_ring[tail & RING_MASK];
        /* Acquire-load synchronises with the producer's release-store.   */
        unsigned seq = atomic_load_explicit(&slot->seq, memory_order_acquire);
        if (seq != tail + 1u) break;  /* producer hasn't published yet    */

        out[count++] = slot->data;    /* copy the event                   */
        tail++;                       /* advance consumer cursor          */
        /* No seq reset: next producer at (tail - 1 + RING_CAP) will write
         * a distinct seq value ((tail - 1 + RING_CAP) + 1).             */
    }

    if (count > 0)
        /* Release-store makes the new tail visible to producers' full-check. */
        atomic_store_explicit(&g_tail, tail, memory_order_release);

    return count;
}

uint64_t ring_dropped(void)
{
    return (uint64_t)atomic_load_explicit(&g_dropped, memory_order_relaxed);
}
