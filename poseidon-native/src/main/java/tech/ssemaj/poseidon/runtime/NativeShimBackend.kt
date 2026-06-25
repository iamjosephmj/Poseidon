package tech.ssemaj.poseidon.runtime

import android.util.Log

/**
 * Real [NativeBridge.Backend] backed by libposeidon_shim.so. Registers itself
 * with [NativeBridge] on first use (triggered via reflective Class.forName from
 * [PoseidonInitializer] before policy is pushed, so the backend is ready).
 *
 * Package intentionally matches :poseidon-core's package so JNI symbol names
 * (Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_*) bind correctly.
 *
 * Task 5.1 adds a daemon drain thread that polls [drainEvents] every ~250 ms
 * and forwards each drained native event to [Observer.record], keeping the
 * native hot path (connect/sendto/getaddrinfo) completely free of synchronous
 * logging or JNI calls.
 */
object NativeShimBackend : NativeBridge.Backend {

    private val available: Boolean = try {
        System.loadLibrary("poseidon_shim")
        true
    } catch (t: Throwable) {
        Log.w("Poseidon", "native shim not loadable: ${t.message}")
        false
    }

    init {
        if (available) {
            NativeBridge.register(this)
            startDrainThread()
        }
    }

    // ---- JNI externals (9 symbols) ----

    /** Pushes the host allow-list + mode into native. */
    private external fun configure(allowedHosts: Array<String>, enforce: Int)

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
     * where:
     *   ts          = CLOCK_MONOTONIC nanoseconds (or 0)
     *   host        = hostname or IP (up to 63 chars)
     *   port        = destination port
     *   transport   = 0 (TCP/unknown), 1 (UDP), 2 (DNS)
     *   tier        = 0 (libc-interceptor), 1 (seccomp-supervisor)
     *   blocked     = 0 (allowed/monitor) or 1 (blocked)
     *   origin_addr = return-address into the calling SDK .so
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
        try {
            configure(allowedHosts.toTypedArray(), if (enforce) 1 else 0)
        } catch (t: Throwable) {
            Log.w("Poseidon", "native configure failed: ${t.message}")
        }
    }

    override fun cacheHostIps(host: String, ips: Array<String>) {
        if (!available) return
        try { cacheHost(host, ips) } catch (_: Throwable) {}
    }

    override fun installSeccompGate(dnsCorrelation: Boolean) {
        if (!available) return
        try {
            installSeccomp(if (dnsCorrelation) 1 else 0)
        } catch (t: Throwable) {
            Log.w("Poseidon", "seccomp gate install failed: ${t.message}")
        }
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
        try {
            seccompProbe()
        } catch (t: Throwable) {
            Log.w("Poseidon", "seccomp probe failed: ${t.message}")
        }
    }

    // ---- Task 5.1: daemon drain thread ----

    /**
     * Starts a single daemon thread that polls [drainEvents] every ~250 ms
     * and forwards each event to [Observer.record].
     *
     * The thread is a daemon so it never prevents JVM shutdown.
     * All exceptions inside the loop are swallowed to prevent crashing the app.
     *
     * RUNTIME CORRECTNESS UNVERIFIED — deferred to Checkpoint 5 (no device).
     */
    private fun startDrainThread() {
        val thread = Thread({
            while (true) {
                try {
                    Thread.sleep(250L)
                    val events = drainEvents()
                    for (raw in events) {
                        try {
                            val event = parseRingEvent(raw) ?: continue
                            Observer.record(event)
                        } catch (t: Throwable) {
                            // Never let a single bad event crash the drain loop.
                        }
                    }
                } catch (ie: InterruptedException) {
                    Thread.currentThread().interrupt()
                    break
                } catch (t: Throwable) {
                    // Never crash the drain thread on unexpected errors.
                }
            }
        }, "poseidon-native-drain")
        thread.isDaemon = true
        thread.start()
    }

    /**
     * Parses a compact ring-event string into an [EgressEvent].
     *
     * Format: "ts|host|port|transport|tier|blocked|origin_addr"
     *   transport: 0=TCP/unknown, 1=UDP, 2=DNS
     *   tier:      0=libc (Tier.NATIVE), 1=seccomp (Tier.SECCOMP)
     *   blocked:   0=ALLOW, 1=BLOCK
     *
     * Returns null if the string cannot be parsed.
     */
    private fun parseRingEvent(raw: String): EgressEvent? {
        val parts = raw.split('|')
        if (parts.size != 7) return null
        val ts        = parts[0].toLongOrNull() ?: return null
        val host      = parts[1].ifEmpty { null }
        val port      = parts[2].toIntOrNull() ?: 0
        val transport = parts[3].toIntOrNull() ?: 0
        val tierInt   = parts[4].toIntOrNull() ?: 0
        val blocked   = (parts[5].toIntOrNull() ?: 0) != 0
        val originAddr = parts[6].toULongOrNull()?.toLong() ?: 0L

        val transportEnum = when (transport) {
            1    -> Transport.UDP
            2    -> Transport.DNS
            else -> Transport.TCP
        }
        val tierEnum = if (tierInt == 1) Tier.SECCOMP else Tier.NATIVE
        val action = if (blocked) Action.BLOCK else Action.ALLOW
        val decision = Decision(action = action, reason = if (blocked) "native-block" else "")

        // Symbolize the origin address off the hot path (dladdr, safe to call here).
        val originSymbol: String? = if (originAddr != 0L) {
            try { symbolize(originAddr) } catch (_: Throwable) { null }
        } else null

        return EgressEvent(
            ts          = ts,
            tid         = 0,   // native thread id not captured; use 0
            host        = host,
            ip          = null, // IP is embedded in host field from native side
            port        = port,
            transport   = transportEnum,
            tier        = tierEnum,
            originToken = originSymbol ?: originAddr,
            decision    = decision,
        )
    }
}
