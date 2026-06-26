package tech.ssemaj.poseidon.runtime

import tech.ssemaj.poseidon.runtime.model.Action
import tech.ssemaj.poseidon.runtime.model.Decision
import tech.ssemaj.poseidon.runtime.model.Mode
import tech.ssemaj.poseidon.runtime.pipeline.ModeGate

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
