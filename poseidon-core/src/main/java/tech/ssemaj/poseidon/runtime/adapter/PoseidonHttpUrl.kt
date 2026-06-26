@file:OptIn(InternalPoseidonApi::class)

package tech.ssemaj.poseidon.runtime.adapter

import tech.ssemaj.poseidon.runtime.internal.InternalPoseidonApi
import tech.ssemaj.poseidon.runtime.pipeline.PoseidonGate
import tech.ssemaj.poseidon.runtime.pipeline.normalizePath

import java.io.IOException
import java.io.InputStream
import java.net.Proxy
import java.net.URL
import java.net.URLConnection

/**
 * Pattern: **Adapter** + **Proxy** — adapts HttpURLConnection to the Poseidon gate and
 * acts as a protection proxy over `URL.openConnection()/openStream()` (guard, then
 * forward). The plugin rewrites those call sites to these statics (java.net.URL is a
 * platform class, so call-site rewriting is used instead of instrumenting the class).
 * Covers raw HttpURLConnection, Volley's HurlStack, and Ktor's Android engine.
 */
@InternalPoseidonApi
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
        if (PoseidonGate.shouldBlock(url.host, normalizePath(url.path))) {
            throw IOException("Blocked by Poseidon: ${url.host}${url.path ?: ""}")
        }
    }
}
