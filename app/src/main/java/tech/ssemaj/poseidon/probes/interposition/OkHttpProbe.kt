package tech.ssemaj.poseidon.probes.interposition

import android.util.Log
import okhttp3.OkHttpClient
import okhttp3.Request
import tech.ssemaj.poseidon.probes.DemoUrls
import java.util.concurrent.Executors

/**
 * Tier: JVM adapters (bytecode interposition).
 *
 * The Poseidon plugin auto-injects [PoseidonInterceptor] into every [OkHttpClient] built
 * in the APK — no app-side configuration needed.  Requests to denied hosts/paths are
 * short-circuited with a synthetic HTTP 403 before any socket is opened.
 */
object OkHttpProbe {
    private const val TAG = "PoseidonDemo"

    fun run() {
        Executors.newSingleThreadExecutor().execute {
            val client = OkHttpClient.Builder().build() // interceptor auto-injected by Poseidon
            Log.i(TAG, "interceptors = ${client.interceptors.map { it.javaClass.simpleName }}")
            call(client, DemoUrls.ALLOWED)      // allowed host, allowed path -> proceeds
            call(client, DemoUrls.DENIED_PATH)  // allowed host, DENIED path -> 403
            call(client, DemoUrls.DENIED_HOST)  // host NOT allow-listed -> 403
        }
    }

    private fun call(client: OkHttpClient, url: String) {
        try {
            client.newCall(Request.Builder().url(url).build()).execute().use { r ->
                Log.i(TAG, "$url -> ${r.code} ${r.message}")
            }
        } catch (t: Throwable) {
            Log.e(TAG, "$url -> error ${t.message}")
        }
    }
}
