package tech.ssemaj.poseidon.runtime

import android.util.Log

/**
 * Bridge to the native shim (libposeidon_shim.so). Pushes the compiled host
 * allow-list + mode into native so connect()/sendto() enforce it. The shim is the
 * same .so instance already loaded as a DT_NEEDED of guarded native libs, so the
 * configured policy is visible to those interceptors.
 */
object NativeBridge {
    private val available: Boolean = try {
        System.loadLibrary("poseidon_shim")
        true
    } catch (t: Throwable) {
        Log.w("Poseidon", "native shim not loadable: ${t.message}")
        false
    }

    /** @param enforce 1 = ENFORCE (block), 0 = MONITOR (log only). */
    private external fun configure(allowedHosts: Array<String>, enforce: Int)

    private external fun seccompProbe()
    private external fun installSeccomp(dnsCorrelation: Int): Int
    private external fun rawConnect(ip: String, port: Int): Int
    private external fun rawResolve(host: String): String?
    private external fun rawSendto(ip: String, port: Int): Int
    private external fun cacheHost(host: String, ips: Array<String>)

    /** Test helper: raw-syscall connectionless UDP sendto (no connect) — verifies the gate. */
    fun rawSendtoTest(ip: String, port: Int): Int = if (available) rawSendto(ip, port) else -1

    /** Seed the native IP->host cache for an allowed host (called from the JVM layer). */
    fun cacheHostIps(host: String, ips: Array<String>) {
        if (available) try { cacheHost(host, ips) } catch (_: Throwable) {}
    }

    /** Feasibility probe: can this app process install a seccomp filter (to cover Go)? */
    fun probeSeccomp() {
        if (!available) return
        try {
            seccompProbe()
        } catch (t: Throwable) {
            Log.w("Poseidon", "seccomp probe failed: ${t.message}")
        }
    }

    /**
     * Install the seccomp connect() gate (covers Go/raw-syscall host enforcement).
     * @param dnsCorrelation also trap sendto/recvfrom for Go-DNS correlation (costly).
     */
    fun installSeccompGate(dnsCorrelation: Boolean) {
        if (!available) return
        try {
            installSeccomp(if (dnsCorrelation) 1 else 0)
        } catch (t: Throwable) {
            Log.w("Poseidon", "seccomp gate install failed: ${t.message}")
        }
    }

    /** Test helper: raw-syscall connect (bypasses libc), to verify the seccomp gate. */
    fun rawConnectTest(ip: String, port: Int): Int = if (available) rawConnect(ip, port) else -1

    /** Test helper: raw DNS resolve (sendto/recvfrom :53), to verify DNS correlation. */
    fun rawResolveTest(host: String): String? = if (available) rawResolve(host) else null

    fun apply(allowedHosts: List<String>, enforce: Boolean) {
        if (!available) return
        try {
            configure(allowedHosts.toTypedArray(), if (enforce) 1 else 0)
        } catch (t: Throwable) {
            Log.w("Poseidon", "native configure failed: ${t.message}")
        }
    }
}
