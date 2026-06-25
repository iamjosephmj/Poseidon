package tech.ssemaj.poseidon.runtime

import android.util.Log

/**
 * The only audit output. Records every decision in BOTH modes (monitor = enforce minus
 * the block). Default sink logs off the JVM path; apps can swap a callback. The NATIVE
 * shim must NOT log on its hot path — native events arrive here via the async ring
 * (Phase 5), already off-thread.
 */
object Observer {
    @Volatile private var sink: (EgressEvent) -> Unit = ::logSink

    @JvmStatic fun record(event: EgressEvent) = sink(event)

    @JvmStatic fun setSink(sink: (EgressEvent) -> Unit) { this.sink = sink }
    @JvmStatic fun resetSink() { this.sink = ::logSink }

    private fun logSink(e: EgressEvent) {
        val d = e.decision
        val verdict = if (d?.block == true) "BLOCK (${d.reason})" else "ALLOW"
        Log.i("Poseidon", "[${Mode.current}/${e.tier}] ${e.host ?: e.ip}${e.path ?: ""} -> $verdict")
    }
}
