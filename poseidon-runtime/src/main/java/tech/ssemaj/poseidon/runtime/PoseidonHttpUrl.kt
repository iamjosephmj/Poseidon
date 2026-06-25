package tech.ssemaj.poseidon.runtime

import java.io.IOException
import java.io.InputStream
import java.net.Proxy
import java.net.URL
import java.net.URLConnection

/**
 * HttpURLConnection adapter. The plugin rewrites `URL.openConnection()/openStream()`
 * call sites to these statics (java.net.URL is a platform class, so call-site
 * rewriting is used instead of instrumenting the class). Covers raw
 * HttpURLConnection, Volley's HurlStack, and Ktor's Android engine.
 */
object PoseidonHttpUrl {
    @JvmStatic
    @Throws(IOException::class)
    fun open(url: URL): URLConnection {
        guard(url)
        return url.openConnection()
    }

    @JvmStatic
    @Throws(IOException::class)
    fun open(url: URL, proxy: Proxy): URLConnection {
        guard(url)
        return url.openConnection(proxy)
    }

    @JvmStatic
    @Throws(IOException::class)
    fun openStream(url: URL): InputStream {
        guard(url)
        return url.openStream()
    }

    private fun guard(url: URL) {
        val path = url.path?.ifEmpty { "/" } ?: "/"
        if (PoseidonGate.shouldBlock(url.host, path)) {
            throw IOException("Blocked by Poseidon: ${url.host}$path")
        }
    }
}
