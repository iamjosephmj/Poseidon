# Task 5.1 Report: Lock-free native event ring + drain JNI

## Status
**DONE_WITH_CONCERNS** — native code compiles and symbols export correctly for all 4 ABIs.
Runtime / concurrency correctness UNVERIFIED (deferred to Checkpoint 5 — no host toolchain, no device).

---

## Ring Design (MPSC-safe, drop-on-full)

File: `poseidon-native/src/main/cpp/event_ring.{h,c}`

**Fixed capacity**: `RING_CAP = 1024` slots (power of two; `RING_MASK = 1023`).

**Per-slot state**: `struct ring_event data` + `_Atomic unsigned seq`.
All slots are zero-initialised in BSS at load time (seq = 0 for all slots).

**Producers (any thread, concurrent)**:
1. Load `g_head` (relaxed).
2. Load `g_tail` (acquire) and check `head - tail >= RING_CAP`; if so, increment `g_dropped` (relaxed) and return — no slot is claimed, so the consumer never stalls.
3. `atomic_compare_exchange_weak` `g_head`: head → head+1. On failure `head` is refreshed to the current value and we loop from step 2. On success `pos = head` (old value) is the claimed slot.
4. Write `ring_event` fields into `g_ring[pos & RING_MASK].data`.
5. `atomic_store_explicit(&slot->seq, pos + 1, release)` — publishes the event.

**Consumer (single thread, JVM drain)**:
1. `tail = atomic_load_explicit(&g_tail, relaxed)` (only this thread writes tail).
2. Acquire-load `slot->seq`. If `seq != tail + 1`: producer hasn't published yet — stop.
3. Copy `slot->data` into caller buffer.
4. `tail++`. No seq reset needed: the next producer at `pos + RING_CAP` writes `seq = pos + RING_CAP + 1`, which is distinct.
5. After `count > 0`: `atomic_store_explicit(&g_tail, tail, release)` to make the new tail visible to the producers' full-check.

**Memory ordering**:
- Producer release-store of `seq` synchronises-with consumer acquire-load → consumer sees all data writes from that producer.
- Consumer release-store of `g_tail` synchronises-with producer acquire-load of `g_tail` in the full-check → producer sees consumed slots.

---

## Hot-path LOG calls replaced (shim.c)

Total: **11 synchronous `__android_log_print` calls** replaced on the hot path.

| Location (before) | Replacement |
|---|---|
| `act()` — P_BLOCK verdict (line ~179) | `ring_push(...)` |
| `act()` — P_MONITOR_VIOL verdict (line ~180) | `ring_push(...)` |
| `act()` — P_ALLOW verdict (line ~181) | `ring_push(...)` |
| `getaddrinfo()` — BLOCK path (line ~282) | `ring_push(...)` |
| `android_getaddrinfofornet()` — BLOCK path (line ~308) | `ring_push(...)` |
| `seccomp_supervisor` — connect BLOCK (line ~545) | `ring_push(...)` |
| `seccomp_supervisor` — connect MONITOR_VIOL (line ~548) | `ring_push(...)` |
| `seccomp_supervisor` — DNS BLOCK (line ~567) | `ring_push(...)` |
| `seccomp_supervisor` — DNS allowed query (line ~571) | `ring_push(...)` |
| `seccomp_supervisor` — sendto BLOCK (line ~580) | `ring_push(...)` |
| `seccomp_supervisor` — sendmsg/sendmmsg BLOCK (line ~597) | `ring_push(...)` |

Kept `LOG()` (off hot path): `installSeccomp()` init/error messages, `seccompProbe()`, `configure()`.

The `act()` function was refactored from `act(fn, verdict, desc, caller)` to
`act(verdict, desc, port, transport, tier, origin)` — the caller `.so` attribution
is now captured as `origin_addr` (a `uint64_t` return address symbolised off-path by `symbolize()`).

Three new hot-path helpers added (all inline, no allocations):
- `mono_ns()` — CLOCK_MONOTONIC via vDSO (very cheap on Android)
- `get_port(sa)` — port from sockaddr without locking
- `desc_host(desc, out, sz)` — extracts hostname from `"hostname (ipstr)"` desc format

---

## :poseidon-native:assembleDebug result

```
BUILD SUCCESSFUL in 849ms
42 actionable tasks: 15 executed, 27 up-to-date
```
All 4 ABIs built: arm64-v8a, armeabi-v7a, x86_64, x86.

---

## nm symbol check (arm64-v8a)

```
000000000000563c T Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_drainEvents@@LIBC
00000000000058c8 T Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_symbolize@@LIBC
```
Both exported at version node `LIBC` as required by `poseidon.ver`.

---

## ring_test.c (deferred)

`poseidon-native/src/main/cpp/test/ring_test.c` is written and wired into
`test/CMakeLists.txt` as target `ring_test`. It pushes 2000 events from 2 threads,
drains, and asserts `drained + drops == 2000`.

**Not run**: no host C toolchain (gcc/clang/cmake absent from this environment).
See the DEFERRED notice at the top of `ring_test.c`.

---

## UNVERIFIED AT RUNTIME — deferred to Checkpoint 5

The following correctness properties have NOT been verified because:
1. No host C toolchain is available to compile and run `ring_test` with TSan.
2. No physical Android device is connected for on-device ART validation.

Items deferred to Checkpoint 5 on-device / host validation:
- **MPSC correctness under real concurrency**: two-thread push + single-thread drain
  with the exact C11 atomic memory model on arm64 hardware.
- **No stall when ring is full**: the CAS-based drop-on-full path must never leave
  a "ghost" slot that blocks the consumer.
- **ring_drain sees all events eventually**: slow producers (preempted between claiming
  and publishing) are correctly waited for across drain cycles.
- **No double-free / corruption**: the consumer reads each slot exactly once (no seq reset,
  relies on monotonically increasing pos).
- **TSan clean**: run `ring_test` with `-fsanitize=thread` once a host toolchain is available.
- **Drain thread JNI wiring**: `drainEvents()` returns correct events on a real device;
  `Observer.record()` receives events with correct `Tier.NATIVE`/`Tier.SECCOMP` attribution.
- **No hot-path regression**: all enforced blocks/allows still fire correctly
  (enforcement semantics unchanged — only the observability channel changed).
