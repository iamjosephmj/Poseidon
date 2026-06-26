package tech.ssemaj.poseidon.probes

import android.content.Context
import tech.ssemaj.poseidon.probes.interposition.CronetProbe
import tech.ssemaj.poseidon.probes.interposition.HttpUrlConnectionProbe
import tech.ssemaj.poseidon.probes.interposition.OkHttpProbe
import tech.ssemaj.poseidon.probes.interposition.VolleyProbe
import tech.ssemaj.poseidon.probes.seccomp.RawDnsProbe
import tech.ssemaj.poseidon.probes.seccomp.RawSyscallProbe

/**
 * Orchestrator for all Poseidon demo probes.
 *
 * Probes are grouped by the tier they exercise:
 *
 * **Tier 1 — JVM adapters** (bytecode / call-site interposition):
 * - [OkHttpProbe]              — OkHttp interceptor auto-injected by the Poseidon plugin
 * - [HttpUrlConnectionProbe]   — [java.net.URL.openConnection] call-site rewrite
 * - [VolleyProbe]              — [com.android.volley.RequestQueue.add] gate
 * - [CronetProbe]              — Cronet Java API observed via native libc shim
 *
 * **Tier 2 — native libc shim** (ELF DT_NEEDED interposition):
 * covered by [CronetProbe] above (Cronet's native stack goes through libposeidon_shim.so).
 *
 * **Tier 3 — seccomp Go-raw gate**:
 * - [RawSyscallProbe]  — raw connect() / sendto() syscalls (Go-runtime style)
 * - [RawDnsProbe]      — raw DNS resolution + connect with in-process hostname correlation
 *
 * All probes are fire-and-forget on their own executor threads; ordering here is
 * chosen so the seccomp gate has time to settle before raw probes execute.
 */
object DemoProbes {

    /**
     * Launch all probes.  Call from [android.app.Activity.onCreate] after
     * [android.app.Activity.setContent] so the UI thread is not blocked.
     */
    fun runAll(context: Context) {
        // Seccomp-tier probes first: they sleep internally to let the gate settle.
        RawSyscallProbe.run()
        RawDnsProbe.run()

        // JVM-adapter tier probes.
        OkHttpProbe.run()
        HttpUrlConnectionProbe.run()
        VolleyProbe.run(context)
        CronetProbe.run(context)
    }
}
