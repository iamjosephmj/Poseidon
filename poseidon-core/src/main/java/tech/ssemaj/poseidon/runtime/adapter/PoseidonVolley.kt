@file:OptIn(InternalPoseidonApi::class)

package tech.ssemaj.poseidon.runtime.adapter

import tech.ssemaj.poseidon.runtime.internal.InternalPoseidonApi
import tech.ssemaj.poseidon.runtime.pipeline.PoseidonGate
import tech.ssemaj.poseidon.runtime.pipeline.normalizePath

import com.android.volley.Request
import java.net.URL

/**
 * Pattern: **Adapter** — bridges Volley to the Poseidon gate. The plugin injects
 * `PoseidonVolley.onAdd(request)` at the top of `RequestQueue.add(Request)`; a denied
 * request is cancelled before it dispatches.
 */
@InternalPoseidonApi
object PoseidonVolley {
    @JvmStatic
    fun onAdd(request: Request<*>) {
        try {
            val u = URL(request.url)
            if (PoseidonGate.shouldBlock(u.host, normalizePath(u.path))) request.cancel()
        } catch (_: Throwable) {
            // malformed URL or non-HTTP request: leave it alone
        }
    }
}
