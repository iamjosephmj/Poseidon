package tech.ssemaj.poseidon.runtime

/**
 * Shared policy gate used by every JVM HTTP-client adapter (OkHttp, HttpURLConnection,
 * …). Host allow-list first, then path deny-list; records the decision; returns
 * whether the request must be blocked (ENFORCE + violation).
 */
object PoseidonGate {
    private val seeded = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    @JvmStatic
    fun shouldBlock(host: String, path: String): Boolean {
        val hostDecision = PolicyEngine.evaluateHost(host, -1)
        val decision = if (hostDecision.block) hostDecision
        else PolicyEngine.evaluatePath(host, path)
        Observer.record(host, path, decision, Mode.current)
        val block = Mode.current == Mode.ENFORCE && decision.block
        // Allowed host: seed the native cache with its IPs (once) so the seccomp
        // connect gate recognizes them — fixes strict-mode over-block for JVM clients
        // whose platform resolution our libc hook never sees.
        if (!block && host.isNotEmpty() && seeded.add(host)) {
            try {
                val ips = java.net.InetAddress.getAllByName(host).mapNotNull { it.hostAddress }
                if (ips.isNotEmpty()) NativeBridge.cacheHostIps(host, ips.toTypedArray())
            } catch (_: Throwable) {
            }
        }
        return block
    }
}
