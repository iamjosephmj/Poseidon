package tech.ssemaj.poseidon.seccomp

/**
 * Marker object for the poseidon-seccomp opt-in tier.
 *
 * This module is a thin facade over [:poseidon-native][tech.ssemaj.poseidon.runtime.NativeShimBackend].
 * It does NOT introduce a separate native library — the seccomp supervisor and DNS-correlation
 * logic already live inside `libposeidon_shim.so` (compiled in `shim.c`).
 *
 * **What this tier enables:**
 * When a consumer depends on `:poseidon-seccomp` (or the `:poseidon-all` umbrella), the
 * in-process seccomp gate is available to intercept Go runtime / raw-syscall `connect()` and
 * `sendto()` calls that bypass the libc shim interposition layer.  Activation is controlled by
 * the `nativeDnsCorrelation` flag in the Poseidon Gradle DSL — no code changes are required in
 * the consuming app.
 *
 * **Dependency tiers:**
 * - `:poseidon-core` — JVM policy pipeline + [tech.ssemaj.poseidon.runtime.NativeBridge] SEAM (no .so)
 * - `:poseidon-native` — libc shim interposition (libposeidon_shim.so)
 * - `:poseidon-seccomp` *(this module)* — Go/raw-syscall coverage via seccomp gate (same .so)
 * - `:poseidon-all` — umbrella aggregating all three tiers
 */
object PoseidonSeccomp
