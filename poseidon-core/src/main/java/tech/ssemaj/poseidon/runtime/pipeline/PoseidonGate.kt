package tech.ssemaj.poseidon.runtime.pipeline

import tech.ssemaj.poseidon.runtime.internal.InternalPoseidonApi
import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.runtime.model.EgressEvent.Companion.UNKNOWN_PORT
import tech.ssemaj.poseidon.runtime.model.Tier
import tech.ssemaj.poseidon.runtime.model.Transport
import tech.ssemaj.poseidon.runtime.policy.PolicyEngine

import android.os.Process

/**
 * Pattern: **Facade** — one JVM-tier entry point (`shouldBlock`) over the policy
 * pipeline. Builds an [EgressEvent], runs it through the one [PolicyEngine], records via
 * the one [Observer], and returns the [ModeGate] decision; the seccomp IP-cache seed for
 * allowed hosts (via [HostIpCacheSeeder]) is a JVM-tier side effect, not a policy
 * decision. Every HTTP-client adapter calls only this, so the subsystem stays hidden.
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
            host = host, ip = null, port = UNKNOWN_PORT,
            transport = Transport.TCP, path = path, tier = Tier.JVM,
        )
        val decision = PolicyEngine.evaluate(event).also { event.decision = it }
        Observer.record(event)
        return ModeGate.shouldBlock(decision).also { if (!it) HostIpCacheSeeder.seed(host) }
    }
}
