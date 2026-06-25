package tech.ssemaj.poseidon.runtime

import android.util.Log

/**
 * Real [NativeBridge.Backend] backed by libposeidon_shim.so. Registers itself
 * with [NativeBridge] on first use (triggered via reflective Class.forName from
 * [PoseidonInitializer] before policy is pushed, so the backend is ready).
 *
 * Package intentionally matches :poseidon-core's package so JNI symbol names
 * (Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_*) bind correctly.
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
        if (available) NativeBridge.register(this)
    }

    // ---- JNI externals (7 symbols) ----

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
}
