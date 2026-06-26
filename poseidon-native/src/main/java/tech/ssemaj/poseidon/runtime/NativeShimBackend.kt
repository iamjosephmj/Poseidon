package tech.ssemaj.poseidon.runtime

import android.util.Log
import tech.ssemaj.poseidon.runtime.internal.NativeBridge
import tech.ssemaj.poseidon.runtime.pipeline.Observer

/**
 * Pattern: **Adapter** — adapts the native `libposeidon_shim.so` (JNI) to the core's
 * [NativeBridge.Backend] abstraction (the shim itself is a **Proxy** that interposes
 * libc network calls). Real [NativeBridge.Backend] backed by libposeidon_shim.so. Registers itself
 * with [NativeBridge] on first use (triggered via reflective Class.forName from
 * [PoseidonInitializer] before policy is pushed, so the backend is ready).
 *
 * Package intentionally matches :poseidon-core's package so JNI symbol names
 * (Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_*) bind correctly.
 *
 * The daemon drain thread polls [drainEvents] every ~250 ms and forwards each
 * drained native event to [Observer.record] via [RingEventParser], keeping the
 * native hot path (connect/sendto/getaddrinfo) free of synchronous logging or
 * JNI calls.
 */
object NativeShimBackend : NativeBridge.Backend {

    private val available: Boolean =
        runCatching { System.loadLibrary("poseidon_shim") }
            .onFailure { Log.w("Poseidon", "native shim not loadable: ${it.message}") }
            .isSuccess

    init {
        if (available) {
            NativeBridge.register(this)
            startDrainThread()
        }
    }

    // ---- JNI externals (10 symbols) ----
    // configureCidrs is included in this count.  All names are pinned by the
    // version script (poseidon.ver) and the FQN Java_tech_ssemaj_poseidon_runtime_
    // NativeShimBackend_* prefix required by the JNI spec.

    /** Pushes the host allow-list + mode into native. */
    private external fun configure(allowedHosts: Array<String>, enforce: Int)

    /** Pushes the opt-in CIDR allow-list into native (closes the bare-IP raw-connect residual). */
    private external fun configureCidrs(cidrs: Array<String>)

    /** Feasibility probe for in-process seccomp. */
    private external fun seccompProbe()

    /** Install the seccomp connect() gate (covers Go/raw-syscall). */
    private external fun installSeccomp(dnsCorrelation: Int): Int

    /** Raw-syscall connect (bypasses libc), for verifying the seccomp gate. */
    private external fun rawConnect(ip: String, port: Int): Int

    /** Raw DNS resolve (sendto/recvfrom :53, like Go's pure resolver). */
    private external fun rawResolve(host: String): String?

    /** Raw-syscall connectionless UDP sendto (no connect), for verifying the gate. */
    private external fun rawSendto(ip: String, port: Int): Int

    /** Seeds the native IP->host cache for an allowed host from the JVM layer. */
    private external fun cacheHost(host: String, ips: Array<String>)

    /**
     * Drains up to 64 pending events from the native lock-free ring.
     * Each element is a compact string: "ts|host|port|transport|tier|blocked|origin_addr"
     * Parsed by [RingEventParser]. See event_ring.h for field encodings.
     */
    private external fun drainEvents(): Array<String>

    /**
     * Returns the .so path containing [addr] via dladdr, or null.
     * Used off the hot path to attribute events to their source SDK.
     */
    private external fun symbolize(addr: Long): String?

    // ---- NativeBridge.Backend implementation ----

    override fun apply(allowedHosts: List<String>, enforce: Boolean) {
        if (!available) return
        runCatching { configure(allowedHosts.toTypedArray(), if (enforce) 1 else 0) }
            .onFailure { Log.w("Poseidon", "native configure failed: ${it.message}") }
    }

    override fun cacheHostIps(host: String, ips: Array<String>) {
        if (!available) return
        runCatching { cacheHost(host, ips) }
    }

    override fun setAllowedCidrs(cidrs: List<String>) {
        if (!available) return
        runCatching { configureCidrs(cidrs.toTypedArray()) }
            .onFailure { Log.w("Poseidon", "native configureCidrs failed: ${it.message}") }
    }

    override fun installSeccompGate(dnsCorrelation: Boolean) {
        if (!available) return
        runCatching { installSeccomp(if (dnsCorrelation) 1 else 0) }
            .onFailure { Log.w("Poseidon", "seccomp gate install failed: ${it.message}") }
    }

    // ---- Public test/probe helpers (used by RawSyscallProbe / RawDnsProbe in :app) ----

    /** Test helper: raw-syscall connectionless UDP sendto — verifies the seccomp gate. */
    fun rawSendtoTest(ip: String, port: Int): Int = if (available) rawSendto(ip, port) else -1

    /** Test helper: raw-syscall connect (bypasses libc), to verify the seccomp gate. */
    fun rawConnectTest(ip: String, port: Int): Int = if (available) rawConnect(ip, port) else -1

    /** Test helper: raw DNS resolve (sendto/recvfrom :53), to verify DNS correlation. */
    fun rawResolveTest(host: String): String? = if (available) rawResolve(host) else null

    /** Feasibility probe: can this app process install a seccomp filter (to cover Go)? */
    fun probeSeccomp() {
        if (!available) return
        runCatching { seccompProbe() }
            .onFailure { Log.w("Poseidon", "seccomp probe failed: ${it.message}") }
    }

    // ---- Daemon drain thread ----

    /**
     * Starts a single daemon thread that polls [drainEvents] every ~250 ms
     * and forwards each event to [Observer.record] via [RingEventParser].
     *
     * The thread is a daemon so it never prevents JVM shutdown.
     * All exceptions inside the loop are swallowed to prevent crashing the app.
     */
    private fun startDrainThread() {
        Thread({
            while (true) {
                try {
                    Thread.sleep(250L)
                    for (raw in drainEvents()) {
                        try {
                            val event = RingEventParser.parse(raw) { symbolize(it) } ?: continue
                            Observer.record(event)
                        } catch (_: Throwable) {
                            // Never let a single bad event crash the drain loop.
                        }
                    }
                } catch (ie: InterruptedException) {
                    Thread.currentThread().interrupt()
                    break
                } catch (_: Throwable) {
                    // Never crash the drain thread on unexpected errors.
                }
            }
        }, "poseidon-native-drain").apply {
            isDaemon = true
            start()
        }
    }
}
