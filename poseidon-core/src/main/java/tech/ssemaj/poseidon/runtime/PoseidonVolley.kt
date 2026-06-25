package tech.ssemaj.poseidon.runtime

import com.android.volley.Request
import java.net.URL

/**
 * Volley adapter. The plugin injects PoseidonVolley.onAdd(request) at the top of
 * RequestQueue.add(Request); a denied request is cancelled before it dispatches.
 */
object PoseidonVolley {
    @JvmStatic
    fun onAdd(request: Request<*>) {
        try {
            val u = URL(request.url)
            val path = u.path?.ifEmpty { "/" } ?: "/"
            if (PoseidonGate.shouldBlock(u.host, path)) request.cancel()
        } catch (_: Throwable) {
            // malformed URL or non-HTTP request: leave it alone
        }
    }
}
