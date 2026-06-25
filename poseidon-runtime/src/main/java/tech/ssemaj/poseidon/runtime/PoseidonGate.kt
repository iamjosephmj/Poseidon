package tech.ssemaj.poseidon.runtime

/**
 * Thin JVM-tier producer: builds an EgressEvent, runs it through the one PolicyEngine,
 * records via the one Observer, and returns the Enforcer's gate. The seccomp IP-cache
 * seed for allowed hosts (so the connect gate recognizes platform-resolved IPs) stays
 * here — it is a JVM-tier side effect, not a policy decision.
 */
object PoseidonGate {
    private val seeded = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    /**
     * TEST-ONLY: clears the seeded host set so each test starts from a clean slate.
     * Must not be called from production code.
     */
    @JvmStatic fun resetForTest() { seeded.clear() }

    @JvmStatic
    fun shouldBlock(host: String, path: String): Boolean {
        val event = EgressEvent(
            ts = System.currentTimeMillis(),
            tid = android.os.Process.myTid(),
            host = host, ip = null, port = -1,
            transport = Transport.TCP, path = path, tier = Tier.JVM,
        )
        val decision = PolicyEngine.evaluate(event)
        event.decision = decision
        Observer.record(event)
        val block = Enforcer.shouldBlock(decision)
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
