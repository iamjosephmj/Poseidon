package tech.ssemaj.poseidon.probes.seccomp

import android.util.Log
import tech.ssemaj.poseidon.runtime.NativeShimBackend
import java.util.concurrent.Executors

/**
 * Tier: seccomp Go-raw gate (DNS correlation).
 *
 * Resolves a host via RAW DNS (sendto/recvfrom — like Go's pure resolver), then raw-connects
 * to the resolved IP.  If in-process DNS correlation is active, the seccomp supervisor's connect
 * log shows the HOSTNAME for that raw connect instead of a bare IP — enabling host-based policy
 * enforcement even for raw-syscall callers.
 */
object RawDnsProbe {
    private const val TAG = "PoseidonDemo"

    /** Denied hostname used to exercise DNS correlation via raw sendto/recvfrom. */
    private const val DENIED_HOSTNAME = "www.google.com"

    /** HTTPS port used for the raw connect() after DNS resolution. */
    private const val HTTPS_PORT = 443

    /** Milliseconds to wait for the seccomp gate + DNS correlation cache to settle. */
    private const val GATE_SETTLE_MS = 1200L

    fun run() {
        Executors.newSingleThreadExecutor().execute {
            Thread.sleep(GATE_SETTLE_MS)
            val ip = NativeShimBackend.rawResolveTest(DENIED_HOSTNAME) // denied host
            Log.i(TAG, "raw-dns $DENIED_HOSTNAME -> $ip")
            ip?.let { resolvedIp ->
                val e = NativeShimBackend.rawConnectTest(resolvedIp, HTTPS_PORT)
                Log.i(TAG, "raw-connect $resolvedIp (resolved from $DENIED_HOSTNAME) -> errno=$e")
            }
        }
    }
}
