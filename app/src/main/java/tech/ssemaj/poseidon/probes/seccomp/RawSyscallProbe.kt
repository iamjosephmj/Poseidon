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
 * errno [SECCOMP_EACCES] = the seccomp supervisor blocked the call.
 * errno 111 (ECONNREFUSED) = allowed through but nothing listening.
 */
object RawSyscallProbe {
    private const val TAG = "PoseidonDemo"

    /** Loopback address — passes the allow-gate (localhost is always permitted). */
    private const val LOOPBACK_IP = "127.0.0.1"

    /** A google.com A record — NOT allow-listed; expect seccomp block. */
    private const val GOOGLE_IP = "142.250.190.78"

    /** Google's public DNS resolver — not allow-listed; expect seccomp block. */
    private const val GOOGLE_DNS_IP = "8.8.8.8"

    /** Standard HTTPS port. */
    private const val HTTPS_PORT = 443

    /** Standard HTTP port. */
    private const val HTTP_PORT = 80

    /** Milliseconds to wait for the seccomp policy + gate to settle before issuing raw syscalls. */
    private const val GATE_SETTLE_MS = 700L

    /** EACCES (13) — the errno the seccomp gate returns when it blocks a call. */
    private const val SECCOMP_EACCES = 13

    fun run() {
        Executors.newSingleThreadExecutor().execute {
            Thread.sleep(GATE_SETTLE_MS) // let policy + gate settle
            val lo = NativeShimBackend.rawConnectTest(LOOPBACK_IP, HTTP_PORT)
            Log.i(TAG, "raw-syscall $LOOPBACK_IP:$HTTP_PORT -> errno=$lo ($SECCOMP_EACCES=seccomp-blocked)")
            val g = NativeShimBackend.rawConnectTest(GOOGLE_IP, HTTPS_PORT) // google, not allow-listed
            Log.i(TAG, "raw-syscall google:$HTTPS_PORT -> errno=$g ($SECCOMP_EACCES=seccomp-blocked)")
            // Connectionless UDP via raw sendto (no connect) — like Go's WriteToUDP.
            val u = NativeShimBackend.rawSendtoTest(GOOGLE_DNS_IP, HTTPS_PORT) // not allow-listed, non-53
            Log.i(TAG, "raw-sendto(udp) $GOOGLE_DNS_IP:$HTTPS_PORT -> errno=$u ($SECCOMP_EACCES=seccomp-blocked)")
        }
    }
}
