package tech.ssemaj.poseidon.runtime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class EgressEventTest {
    @Test fun defaultsAreRawAndUndecided() {
        val e = EgressEvent(ts = 1L, tid = 2, host = "example.com", ip = null, port = 443,
            transport = Transport.TCP, path = "/v1", tier = Tier.JVM, originToken = 0L)
        assertNull(e.decision)
        assertEquals("example.com", e.host)
        assertEquals(Transport.TCP, e.transport)
    }

    @Test fun decisionCarriesRuleAndReason() {
        val d = Decision(Action.BLOCK, matchedRule = "allow:example.com", reason = "host not in allow-list")
        assertEquals(Action.BLOCK, d.action)
        assertEquals("allow:example.com", d.matchedRule)
    }
}
