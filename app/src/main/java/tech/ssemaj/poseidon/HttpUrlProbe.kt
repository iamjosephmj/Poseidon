package tech.ssemaj.poseidon

import android.util.Log
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors

// Uses raw HttpURLConnection (no app-side Poseidon code). The plugin rewrites the
// url.openConnection() call site below to route through PoseidonHttpUrl.
object HttpUrlProbe {
    fun run() {
        Executors.newSingleThreadExecutor().execute {
            for (spec in listOf(
                "https://example.com/demo/path?x=1",  // allowed host + allowed path
                "https://example.com/blocked/secret", // allowed host, DENIED path
                "https://www.google.com/",            // host NOT allow-listed
            )) {
                try {
                    val c = URL(spec).openConnection() as HttpURLConnection
                    c.connectTimeout = 4000
                    val code = c.responseCode
                    Log.i("PoseidonDemo", "huc $spec -> $code")
                    c.disconnect()
                } catch (t: Throwable) {
                    Log.i("PoseidonDemo", "huc $spec -> blocked/err: ${t.message}")
                }
            }
        }
    }
}
