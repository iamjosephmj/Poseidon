package tech.ssemaj.poseidon.probes.interposition

import android.util.Log
import tech.ssemaj.poseidon.probes.DemoUrls
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors

/**
 * Tier: JVM adapters (call-site rewrite).
 *
 * Uses raw [HttpURLConnection] — no Poseidon code in the app.  The plugin rewrites every
 * [URL.openConnection] call site at build time to route through the Poseidon HTTP-URL
 * adapter, enforcing the same allow-list as the OkHttp interceptor path.
 */
object HttpUrlConnectionProbe {
    private const val TAG = "PoseidonDemo"

    fun run() {
        Executors.newSingleThreadExecutor().execute {
            for (spec in listOf(
                DemoUrls.ALLOWED,      // allowed host + allowed path
                DemoUrls.DENIED_PATH,  // allowed host, DENIED path
                DemoUrls.DENIED_HOST,  // host NOT allow-listed
            )) {
                try {
                    val c = URL(spec).openConnection() as HttpURLConnection
                    c.connectTimeout = 4000
                    val code = c.responseCode
                    Log.i(TAG, "huc $spec -> $code")
                    c.disconnect()
                } catch (t: Throwable) {
                    Log.i(TAG, "huc $spec -> blocked/err: ${t.message}")
                }
            }
        }
    }
}
