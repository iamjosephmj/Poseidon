package tech.ssemaj.poseidon

import android.content.Context
import android.util.Log
import org.chromium.net.CronetEngine
import org.chromium.net.CronetException
import org.chromium.net.UrlRequest
import org.chromium.net.UrlResponseInfo
import java.nio.ByteBuffer
import java.util.concurrent.Executors

// Drives Cronet's NATIVE stack. If the plugin's APK transform injected the shim
// into libcronet, the native connect() shows up / gets blocked under tag POSEIDON
// (controlled by `setprop debug.poseidon.block`).
object CronetProbe {
    fun run(ctx: Context) {
        val engine = CronetEngine.Builder(ctx).build()
        val exec = Executors.newSingleThreadExecutor()
        fun cb(url: String) = object : UrlRequest.Callback() {
            override fun onRedirectReceived(r: UrlRequest, i: UrlResponseInfo, u: String) = r.followRedirect()
            override fun onResponseStarted(r: UrlRequest, i: UrlResponseInfo) {
                r.read(ByteBuffer.allocateDirect(8192))
            }
            override fun onReadCompleted(r: UrlRequest, i: UrlResponseInfo, b: ByteBuffer) { b.clear(); r.read(b) }
            override fun onSucceeded(r: UrlRequest, i: UrlResponseInfo) {
                Log.i("PoseidonDemo", "cronet(native) $url -> SUCCESS http=${i.httpStatusCode}")
            }
            override fun onFailed(r: UrlRequest, i: UrlResponseInfo?, e: CronetException) {
                Log.i("PoseidonDemo", "cronet(native) $url -> FAILED ${e.message}")
            }
        }
        // example.com is in the allow-list -> native allows; google is not -> native blocks.
        for (url in listOf("https://example.com/", "https://www.google.com/")) {
            engine.newUrlRequestBuilder(url, cb(url), exec).build().start()
        }
    }
}
