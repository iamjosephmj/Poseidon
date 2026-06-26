package tech.ssemaj.poseidon.probes.interposition

import android.content.Context
import android.util.Log
import com.android.volley.Request
import com.android.volley.toolbox.StringRequest
import com.android.volley.toolbox.Volley
import tech.ssemaj.poseidon.probes.DemoUrls

/**
 * Tier: JVM adapters (RequestQueue.add gate).
 *
 * Raw Volley usage — no Poseidon code in the app.  The plugin injects a gate at
 * [com.android.volley.RequestQueue.add]; a request whose URL is denied is cancelled
 * before it is dispatched to the network thread.
 */
object VolleyProbe {
    private const val TAG = "PoseidonDemo"

    fun run(ctx: Context) {
        val queue = Volley.newRequestQueue(ctx)
        for (url in listOf(
            DemoUrls.ALLOWED,      // allowed
            DemoUrls.DENIED_PATH,  // denied path
            DemoUrls.DENIED_HOST,  // denied host
        )) {
            val req = StringRequest(
                Request.Method.GET, url,
                { Log.i(TAG, "volley $url -> OK") },
                { e -> Log.i(TAG, "volley $url -> err ${e.message}") },
            )
            queue.add(req)
            Log.i(TAG, "volley $url -> canceled=${req.isCanceled}")
        }
    }
}
