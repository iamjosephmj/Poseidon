package tech.ssemaj.poseidon.runtime

import android.os.Process

/**
 * Thin JVM-tier producer: builds an EgressEvent, runs it through the one PolicyEngine,
 * records via the one Observer, and returns the ModeGate decision. The seccomp IP-cache
 * seed for allowed hosts (so the connect gate recognizes platform-resolved IPs) stays
 * here — it is a JVM-tier side effect, not a policy decision.
 */
@InternalPoseidonApi
object PoseidonGate {
    /**
     * TEST-ONLY: clears the seeded host set so each test starts from a clean slate.
     * Must not be called from production code.
     */
    @JvmStatic fun resetForTest() { HostIpCacheSeeder.resetForTest() }

    @JvmStatic
    fun shouldBlock(host: String, path: String): Boolean {
        val event = EgressEvent(
            ts = System.currentTimeMillis(),
            tid = Process.myTid(),
            host = host, ip = null, port = -1,
            transport = Transport.TCP, path = path, tier = Tier.JVM,
        )
        val decision = PolicyEngine.evaluate(event)
        event.decision = decision
        Observer.record(event)
        val block = ModeGate.shouldBlock(decision)
        if (!block) HostIpCacheSeeder.seed(host)
        return block
    }
}
