@file:OptIn(InternalPoseidonApi::class)

package tech.ssemaj.poseidon.runtime.pipeline

import tech.ssemaj.poseidon.runtime.internal.InternalPoseidonApi
import tech.ssemaj.poseidon.runtime.internal.NativeBridge

import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Seeds the native IP cache the first time a JVM-layer allowed host is resolved.
 * This lets the seccomp connect() gate recognize platform-resolved IPs without a
 * host-name lookup in the kernel path.
 */
internal object HostIpCacheSeeder {
    private val seeded: MutableSet<String> = ConcurrentHashMap.newKeySet()

    fun seed(host: String) {
        if (host.isEmpty() || !seeded.add(host)) return
        try {
            InetAddress.getAllByName(host)
                .mapNotNull { it.hostAddress }
                .takeIf { it.isNotEmpty() }
                ?.let { NativeBridge.cacheHostIps(host, it.toTypedArray()) }
        } catch (_: Throwable) {}
    }

    /**
     * TEST-ONLY: clears the seeded host set so each test starts from a clean slate.
     * Must not be called from production code.
     */
    fun resetForTest() { seeded.clear() }
}
