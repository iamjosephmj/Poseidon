package tech.ssemaj.poseidon.runtime

import android.util.Log

/**
 * Observability sink for policy decisions. Default logs; apps can swap in a callback.
 * NOTE: the JVM path here is fine to log on; the NATIVE shim must NOT log on its hot
 * path (see shim.c) — it will feed events through a lock-free async ring instead.
 */
object Observer {
    @JvmStatic
    fun record(host: String, path: String?, decision: Decision, mode: Mode) {
        val verdict = if (decision.block) "BLOCK (${decision.reason})" else "ALLOW"
        Log.i("Poseidon", "[$mode] $host${path ?: ""} -> $verdict")
    }
}
