package tech.ssemaj.poseidon

import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import com.android.volley.Request as VolleyRequest
import com.android.volley.toolbox.RequestFuture
import com.android.volley.toolbox.StringRequest
import com.android.volley.toolbox.Volley
import okhttp3.OkHttpClient
import okhttp3.Request
import org.chromium.net.CronetEngine
import org.chromium.net.CronetException
import org.chromium.net.UrlRequest
import org.chromium.net.UrlResponseInfo
import tech.ssemaj.poseidon.runtime.NativeShimBackend
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** The "Android ways of making a network call" the verifier can fire a URL through. */
enum class ClientStyle(val label: String) {
    OKHTTP("OkHttp"),
    HTTP_URL("HttpURLConnection"),
    VOLLEY("Volley"),
    CRONET("Cronet"),
    RAW("Raw syscall"),
}

/** One verifier result: which client, the URL, the concrete outcome, and whether Poseidon blocked it. */
data class QueryResult(
    val id: Long,
    val client: String,
    val url: String,
    val outcome: String,
    val blocked: Boolean,
)

private const val MAX_RESULTS = 30
private const val HTTPS_PORT = 443
private const val CONNECT_TIMEOUT_MS = 5000
private const val AWAIT_SECONDS = 10L

/**
 * State for the interactive verifier: an editable URL plus the result of firing it through
 * each Android client style. Queries run on a background pool; results are marshalled to the
 * main thread. Every query also flows into the live egress log via the audit Observer.
 */
class VerifyState {

    val url = mutableStateOf("https://example.com/demo/path?x=1")
    val results = mutableStateListOf<QueryResult>()

    private val main = Handler(Looper.getMainLooper())
    private val pool = Executors.newCachedThreadPool()
    private var counter = 0L

    /** Fire the current [url] through [style] and record the outcome. */
    fun run(style: ClientStyle, context: Context) {
        val target = url.value.trim()
        if (target.isEmpty()) return
        pool.execute {
            val (outcome, blocked) = runCatching { query(style, target, context) }
                .getOrElse { "error: ${it.message}" to false }
            main.post {
                results.add(0, QueryResult(counter++, style.label, target, outcome, blocked))
                while (results.size > MAX_RESULTS) results.removeAt(results.lastIndex)
            }
        }
    }

    private fun query(style: ClientStyle, url: String, ctx: Context): Pair<String, Boolean> =
        when (style) {
            ClientStyle.OKHTTP   -> okhttp(url)
            ClientStyle.HTTP_URL -> httpUrl(url)
            ClientStyle.VOLLEY   -> volley(url, ctx)
            ClientStyle.CRONET   -> cronet(url, ctx)
            ClientStyle.RAW      -> raw(url)
        }

    private fun okhttp(url: String): Pair<String, Boolean> = runCatching {
        OkHttpClient.Builder().build()                       // interceptor auto-injected
            .newCall(Request.Builder().url(url).build())
            .execute().use { r ->
                val blocked = r.code == 403 && r.message.contains("Poseidon", ignoreCase = true)
                (if (blocked) "403 Blocked by Poseidon" else "${r.code} ${r.message}") to blocked
            }
    }.getOrElse { "error: ${it.message}" to false }

    private fun httpUrl(url: String): Pair<String, Boolean> = runCatching {
        val c = (URL(url).openConnection() as HttpURLConnection)  // call-site rewritten by the plugin
            .apply { connectTimeout = CONNECT_TIMEOUT_MS }
        val code = c.responseCode
        c.disconnect()
        "$code" to false
    }.getOrElse {
        val blocked = it.message?.contains("Poseidon", ignoreCase = true) == true
        (if (blocked) "IOException: Blocked by Poseidon" else "error: ${it.message}") to blocked
    }

    private fun volley(url: String, ctx: Context): Pair<String, Boolean> {
        val queue = Volley.newRequestQueue(ctx)
        val future = RequestFuture.newFuture<String>()
        val req = StringRequest(VolleyRequest.Method.GET, url, future, future)
        queue.add(req)                                        // RequestQueue.add gate cancels denied
        if (req.isCanceled) return "canceled (blocked by Poseidon)" to true
        return runCatching { future.get(AWAIT_SECONDS, TimeUnit.SECONDS); "OK" to false }
            .getOrElse {
                if (req.isCanceled) "canceled (blocked by Poseidon)" to true
                else "err: ${it.message}" to false
            }
    }

    private fun cronet(url: String, ctx: Context): Pair<String, Boolean> {
        val engine = CronetEngine.Builder(ctx).build()
        val exec = Executors.newSingleThreadExecutor()
        val latch = CountDownLatch(1)
        var outcome = "no response"
        var blocked = false
        val cb = object : UrlRequest.Callback() {
            override fun onRedirectReceived(r: UrlRequest, i: UrlResponseInfo, u: String) = r.followRedirect()
            override fun onResponseStarted(r: UrlRequest, i: UrlResponseInfo) { r.read(ByteBuffer.allocateDirect(8192)) }
            override fun onReadCompleted(r: UrlRequest, i: UrlResponseInfo, b: ByteBuffer) { b.clear(); r.read(b) }
            override fun onSucceeded(r: UrlRequest, i: UrlResponseInfo) {
                // Reached the origin (host allowed). The HTTP status is the SERVER's answer —
                // e.g. 404 just means that path doesn't exist, NOT a Poseidon block.
                outcome = "HTTP ${i.httpStatusCode} (allowed)"; latch.countDown()
            }
            override fun onFailed(r: UrlRequest, i: UrlResponseInfo?, e: CronetException) {
                outcome = e.message ?: "failed"; blocked = true; latch.countDown()
            }
        }
        engine.newUrlRequestBuilder(url, cb, exec).build().start()  // call-site rewritten; native shim gates the host
        latch.await(AWAIT_SECONDS, TimeUnit.SECONDS)
        return outcome to blocked
    }

    private fun raw(url: String): Pair<String, Boolean> {
        val host = runCatching { URL(url).host }.getOrDefault(url).ifEmpty { url }
        val ip = runCatching { InetAddress.getByName(host).hostAddress }.getOrNull()
            ?: return "can't resolve $host" to false
        return when (val errno = NativeShimBackend.rawConnectTest(ip, HTTPS_PORT)) {
            13   -> "errno=13 — seccomp blocked ($ip)" to true
            0    -> "errno=0 — allowed ($ip)" to false
            else -> "errno=$errno ($ip)" to false
        }
    }
}
