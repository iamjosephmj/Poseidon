package tech.ssemaj.poseidon.runtime.pipeline

import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.runtime.model.Mode
import tech.ssemaj.poseidon.runtime.internal.PoseidonConstants.LOG_TAG

import android.util.Log
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Pattern: **Observer** — the audit subject. Every policy decision is published here in
 * BOTH modes (monitor = enforce minus the block); registered observers (sinks) receive
 * a normalized [EgressEvent]. Native events arrive via the async ring drain (already
 * off the shim's hot path), JVM events inline.
 *
 * Supports multiple observers: the default logs to Logcat; apps can [addSink] their own
 * (metrics, a UI, a file) without removing others, [setSink] to replace all with one, or
 * [resetSink] to restore just the default. A misbehaving observer can never break
 * enforcement — each is dispatched under its own try/catch, and the list is copy-on-write
 * so [record] never blocks on registration.
 */
object Observer {
    private val sinks = CopyOnWriteArrayList<(EgressEvent) -> Unit>().apply { add(::logSink) }

    /** Publish [event] to every registered observer. Never throws. */
    @JvmStatic fun record(event: EgressEvent) {
        // An observer must never break the audit fan-out (or, in enforce, a block).
        sinks.forEach { sink -> runCatching { sink(event) } }
    }

    /** Register an additional observer without removing existing ones. */
    @JvmStatic fun addSink(sink: (EgressEvent) -> Unit) { sinks.add(sink) }

    /** Remove a previously-registered observer (by identity — pass the same reference). */
    @JvmStatic fun removeSink(sink: (EgressEvent) -> Unit) { sinks.remove(sink) }

    /** Replace ALL observers with [sink] (single-sink convenience / back-compat). */
    @JvmStatic fun setSink(sink: (EgressEvent) -> Unit) {
        sinks.clear()
        sinks.add(sink)
    }

    /** Restore the default Logcat observer (drops any app-registered sinks). */
    @JvmStatic fun resetSink() {
        sinks.clear()
        sinks.add(::logSink)
    }

    private fun logSink(e: EgressEvent) {
        val verdict = e.decision?.takeIf { it.block }?.let { "BLOCK (${it.reason})" } ?: "ALLOW"
        Log.i(LOG_TAG, "[${Mode.current}/${e.tier}] ${e.host ?: e.ip}${e.path ?: ""} -> $verdict")
    }
}
