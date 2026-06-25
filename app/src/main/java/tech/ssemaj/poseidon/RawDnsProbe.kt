package tech.ssemaj.poseidon

import android.util.Log
import tech.ssemaj.poseidon.runtime.NativeShimBackend
import java.util.concurrent.Executors

// Resolves a host via RAW DNS (sendto/recvfrom — like Go's pure resolver), then
// raw-connects to the resolved IP. If in-process DNS correlation works, the seccomp
// supervisor's connect log shows the HOSTNAME for that raw connect (not a bare IP).
object RawDnsProbe {
    fun run() {
        Executors.newSingleThreadExecutor().execute {
            Thread.sleep(1200)
            val ip = NativeShimBackend.rawResolveTest("www.google.com") // denied host
            Log.i("PoseidonDemo", "raw-dns www.google.com -> $ip")
            if (ip != null) {
                val e = NativeShimBackend.rawConnectTest(ip, 443)
                Log.i("PoseidonDemo", "raw-connect $ip (resolved from www.google.com) -> errno=$e")
            }
        }
    }
}
