package tech.ssemaj.poseidon.probes.seccomp

import android.util.Log
import tech.ssemaj.poseidon.runtime.NativeShimBackend
import java.util.concurrent.Executors

/**
 * Tier: seccomp Go-raw gate.
 *
 * Issues [connect] and [sendto] as RAW syscalls — bypassing the libc connect symbol entirely,
 * exactly like Go's runtime net stack.  Only the seccomp supervisor can intercept these.
 *
 * errno 13 (EACCES) = the seccomp supervisor blocked the call.
 * errno 111 (ECONNREFUSED) = allowed through but nothing listening.
 */
object RawSyscallProbe {
    private const val TAG = "PoseidonDemo"

    fun run() {
        Executors.newSingleThreadExecutor().execute {
            Thread.sleep(700) // let policy + gate settle
            val lo = NativeShimBackend.rawConnectTest("127.0.0.1", 80)
            Log.i(TAG, "raw-syscall 127.0.0.1:80 -> errno=$lo (13=seccomp-blocked)")
            val g = NativeShimBackend.rawConnectTest("142.250.190.78", 443) // google, not allow-listed
            Log.i(TAG, "raw-syscall google:443 -> errno=$g (13=seccomp-blocked)")
            // Connectionless UDP via raw sendto (no connect) — like Go's WriteToUDP.
            val u = NativeShimBackend.rawSendtoTest("8.8.8.8", 443) // not allow-listed, non-53
            Log.i(TAG, "raw-sendto(udp) 8.8.8.8:443 -> errno=$u (13=seccomp-blocked)")
        }
    }
}
