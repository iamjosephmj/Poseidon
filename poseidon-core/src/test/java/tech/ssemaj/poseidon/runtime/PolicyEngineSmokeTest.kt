package tech.ssemaj.poseidon.runtime

import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.runtime.model.Tier
import tech.ssemaj.poseidon.runtime.model.Transport
import tech.ssemaj.poseidon.runtime.policy.PolicyEngine

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PolicyEngineSmokeTest {
    @Test fun allowListBlocksUnlistedHost() {
        PolicyEngine.configure(allowedHosts = listOf("example.com"), deniedPaths = emptyList())
        val blocked = EgressEvent(ts = 0, tid = 0, host = "evil.test", ip = null, port = -1, transport = Transport.TCP, tier = Tier.JVM)
        val allowed = EgressEvent(ts = 0, tid = 0, host = "example.com", ip = null, port = -1, transport = Transport.TCP, tier = Tier.JVM)
        assertTrue(PolicyEngine.evaluate(blocked).block)
        assertFalse(PolicyEngine.evaluate(allowed).block)
    }
}
