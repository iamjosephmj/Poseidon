package tech.ssemaj.poseidon.runtime

import tech.ssemaj.poseidon.runtime.model.Action
import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.runtime.model.Tier
import tech.ssemaj.poseidon.runtime.model.Transport
import tech.ssemaj.poseidon.runtime.policy.PolicyEngine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class PolicyEngineEvaluateTest {
    private fun ev(host: String?, path: String? = null, tier: Tier = Tier.JVM) =
        EgressEvent(0L, 0, host, ip = null, port = 443, transport = Transport.TCP, path = path, tier = tier)

    @Before fun setup() = PolicyEngine.configure(listOf("example.com", "*.api.foo.com"), listOf("/internal/*"))

    @Test fun unlistedHostBlocked() = assertTrue(PolicyEngine.evaluate(ev("evil.test")).block)
    @Test fun allowedHostAllowed() = assertFalse(PolicyEngine.evaluate(ev("example.com")).block)
    @Test fun wildcardHostAllowed() = assertFalse(PolicyEngine.evaluate(ev("v2.api.foo.com")).block)

    @Test fun deniedPathBlockedOnAllowedHost() {
        val d = PolicyEngine.evaluate(ev("example.com", "/internal/secrets"))
        assertTrue(d.block); assertEquals("deny-path:/internal/*", d.matchedRule)
    }

    @Test fun pathIgnoredForNativeTier() =
        assertFalse(PolicyEngine.evaluate(ev("example.com", "/internal/secrets", Tier.NATIVE)).block)

    @Test fun emptyAllowListAllowsAll() {
        PolicyEngine.configure(emptyList(), emptyList())
        assertFalse(PolicyEngine.evaluate(ev("anything.test")).block)
    }
}
