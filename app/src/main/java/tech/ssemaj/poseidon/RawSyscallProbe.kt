package tech.ssemaj.poseidon

import android.util.Log
import tech.ssemaj.poseidon.runtime.NativeBridge
import java.util.concurrent.Executors

// Issues connect() as a RAW syscall (bypasses the libc connect symbol, exactly like
// Go's runtime). Only the seccomp gate can catch this. errno 13 (EACCES) == the
// seccomp supervisor blocked it; a natural failure (ECONNREFUSED 111) means it was
// allowed through.
object RawSyscallProbe {
    fun run() {
        Executors.newSingleThreadExecutor().execute {
            Thread.sleep(700) // let policy + gate settle
            val lo = NativeBridge.rawConnectTest("127.0.0.1", 80)
            Log.i("PoseidonDemo", "raw-syscall 127.0.0.1:80 -> errno=$lo (13=seccomp-blocked)")
            val g = NativeBridge.rawConnectTest("142.250.190.78", 443) // google, not allow-listed
            Log.i("PoseidonDemo", "raw-syscall google:443 -> errno=$g (13=seccomp-blocked)")
            // Connectionless UDP via raw sendto (no connect) — like Go's WriteToUDP.
            val u = NativeBridge.rawSendtoTest("8.8.8.8", 443) // not allow-listed, non-53
            Log.i("PoseidonDemo", "raw-sendto(udp) 8.8.8.8:443 -> errno=$u (13=seccomp-blocked)")
        }
    }
}
