package tech.ssemaj.poseidon.runtime

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EnforcerTest {
    @Test fun monitorNeverBlocks() {
        Mode.current = Mode.MONITOR
        assertFalse(Enforcer.shouldBlock(Decision(Action.BLOCK, reason = "x")))
    }
    @Test fun enforceBlocksOnBlockDecision() {
        Mode.current = Mode.ENFORCE
        assertTrue(Enforcer.shouldBlock(Decision(Action.BLOCK, reason = "x")))
        assertFalse(Enforcer.shouldBlock(Decision(Action.ALLOW)))
    }
}
