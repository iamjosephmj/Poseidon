package tech.ssemaj.poseidon.runtime

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ModeGateTest {
    @Test fun monitorNeverBlocks() {
        Mode.current = Mode.MONITOR
        assertFalse(ModeGate.shouldBlock(Decision(Action.BLOCK, reason = "x")))
    }
    @Test fun enforceBlocksOnBlockDecision() {
        Mode.current = Mode.ENFORCE
        assertTrue(ModeGate.shouldBlock(Decision(Action.BLOCK, reason = "x")))
        assertFalse(ModeGate.shouldBlock(Decision(Action.ALLOW)))
    }
}
