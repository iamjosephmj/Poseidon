package tech.ssemaj.poseidon

import android.util.Log
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.Executors

// Policy now comes entirely from the build config (poseidon { } DSL + YAML),
// loaded at startup by PoseidonInitializer. No policy is set in app code.
object OkHttpProbe {
    fun run() {
        Executors.newSingleThreadExecutor().execute {
            val client = OkHttpClient.Builder().build() // interceptor auto-injected by Poseidon
            Log.i("PoseidonDemo", "interceptors = ${client.interceptors.map { it.javaClass.simpleName }}")
            call(client, "https://example.com/demo/path?x=1")     // allowed host, allowed path -> proceeds
            call(client, "https://example.com/blocked/secret")    // allowed host, DENIED path -> 403
            call(client, "https://www.google.com/")               // host NOT allow-listed -> 403
        }
    }

    private fun call(client: OkHttpClient, url: String) {
        try {
            client.newCall(Request.Builder().url(url).build()).execute().use { r ->
                Log.i("PoseidonDemo", "$url -> ${r.code} ${r.message}")
            }
        } catch (t: Throwable) {
            Log.e("PoseidonDemo", "$url -> error ${t.message}")
        }
    }
}
