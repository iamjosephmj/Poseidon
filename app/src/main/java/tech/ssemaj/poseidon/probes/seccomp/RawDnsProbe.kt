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

    fun run() {
        Executors.newSingleThreadExecutor().execute {
            Thread.sleep(1200)
            val ip = NativeShimBackend.rawResolveTest("www.google.com") // denied host
            Log.i(TAG, "raw-dns www.google.com -> $ip")
            if (ip != null) {
                val e = NativeShimBackend.rawConnectTest(ip, 443)
                Log.i(TAG, "raw-connect $ip (resolved from www.google.com) -> errno=$e")
            }
        }
    }
}
