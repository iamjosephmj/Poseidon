package tech.ssemaj.poseidon

import android.content.Context
import android.util.Log
import com.android.volley.Request
import com.android.volley.toolbox.StringRequest
import com.android.volley.toolbox.Volley

// Raw Volley usage (no Poseidon code). The plugin injects a gate at
// RequestQueue.add(Request); a denied request is cancelled before dispatch.
object VolleyProbe {
    fun run(ctx: Context) {
        val queue = Volley.newRequestQueue(ctx)
        for (url in listOf(
            "https://example.com/demo/path?x=1",  // allowed
            "https://example.com/blocked/secret", // denied path
            "https://www.google.com/",            // denied host
        )) {
            val req = StringRequest(
                Request.Method.GET, url,
                { Log.i("PoseidonDemo", "volley $url -> OK") },
                { e -> Log.i("PoseidonDemo", "volley $url -> err ${e.message}") },
            )
            queue.add(req)
            Log.i("PoseidonDemo", "volley $url -> canceled=${req.isCanceled}")
        }
    }
}
