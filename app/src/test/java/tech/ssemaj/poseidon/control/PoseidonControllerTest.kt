package tech.ssemaj.poseidon.control

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import tech.ssemaj.poseidon.runtime.model.Action
import tech.ssemaj.poseidon.runtime.model.Decision
import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.runtime.model.Mode
import tech.ssemaj.poseidon.runtime.model.Tier
import tech.ssemaj.poseidon.runtime.model.Transport

private class FakeGate : EnforcementGate {
    var lastEnforce: Boolean? = null
    override fun setEnforcing(enforce: Boolean) { lastEnforce = enforce }
}

// Real EgressEvent constructor: (ts, tid, host, ip, port, transport, path, tier, originToken, decision)
// transport is non-nullable; Tier enum: JVM, NATIVE, SECCOMP (no LIBC).
private fun event(tier: Tier, host: String, block: Boolean) = EgressEvent(
    ts = 0L,
    tid = 0,
    host = host,
    ip = null,
    port = 443,
    transport = Transport.TCP,
    path = null,
    tier = tier,
    decision = Decision(if (block) Action.BLOCK else Action.ALLOW),
)

class PoseidonControllerTest {

    @Test
    fun onEvent_updatesTotalsAndPerTierTallies() {
        val c = PoseidonController(Mode.ENFORCE, FakeGate())
        c.onEvent(event(Tier.JVM, "a.com", block = true))
        c.onEvent(event(Tier.JVM, "example.com", block = false))
        c.onEvent(event(Tier.NATIVE, "b.com", block = true))

        val s = c.state.value
        assertEquals(1, s.allowedTotal)
        assertEquals(2, s.blockedTotal)
        val jvm = s.tierTallies.first { it.tier == Tier.JVM }
        assertEquals(1, jvm.allowed)
        assertEquals(1, jvm.blocked)
        // newest-first
        assertEquals("b.com", s.events.first().host)
    }

    @Test
    fun events_areCappedAtMaxEvents() {
        val c = PoseidonController(Mode.ENFORCE, FakeGate(), maxEvents = 2)
        repeat(5) { c.onEvent(event(Tier.JVM, "h$it.com", block = true)) }
        assertEquals(2, c.state.value.events.size)
        assertEquals("h4.com", c.state.value.events.first().host)
    }

    @Test
    fun setMode_flipsGateAndState() {
        val gate = FakeGate()
        val c = PoseidonController(Mode.ENFORCE, gate)
        c.setMode(Mode.MONITOR)
        assertEquals(Mode.MONITOR, c.state.value.mode)
        assertEquals(false, gate.lastEnforce)
        c.toggleMode()
        assertEquals(Mode.ENFORCE, c.state.value.mode)
        assertTrue(gate.lastEnforce == true)
    }
}
