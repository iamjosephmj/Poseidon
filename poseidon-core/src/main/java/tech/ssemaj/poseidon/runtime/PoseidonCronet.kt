@file:OptIn(InternalPoseidonApi::class)

package tech.ssemaj.poseidon.runtime

import org.chromium.net.CronetEngine
import org.chromium.net.UrlRequest
import java.net.URL
import java.util.concurrent.Executor

/**
 * Cronet adapter. The plugin rewrites `engine.newUrlRequestBuilder(url, cb, exec)`
 * call sites to this static, giving PATH visibility at Cronet's Java API. Host
 * BLOCK for Cronet is enforced by the native shim (Cronet's TLS is native, so the
 * path can't be blocked below the Java layer); here we record/observe the path.
 */
@InternalPoseidonApi
object PoseidonCronet {
    @JvmStatic
    fun newUrlRequestBuilder(
        engine: CronetEngine,
        url: String,
        callback: UrlRequest.Callback,
        executor: Executor,
    ): UrlRequest.Builder {
        try {
            val u = URL(url)
            PoseidonGate.shouldBlock(u.host, normalizePath(u.path))
        } catch (_: Throwable) {
        }
        return engine.newUrlRequestBuilder(url, callback, executor)
    }
}
