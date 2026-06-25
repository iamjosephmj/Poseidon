package tech.ssemaj.poseidon.runtime

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList

class PoseidonGateTest {
    private val seen = CopyOnWriteArrayList<EgressEvent>()

    @Before fun setup() {
        PoseidonGate.resetForTest()          // clear seeded host cache between tests
        seen.clear()                          // clear accumulated events from prior tests
        PolicyEngine.configure(listOf("example.com"), listOf("/blocked/*"))
        Observer.setSink { seen.add(it) }
    }

    @Test fun enforceBlocksUnlistedHostAndRecords() {
        Mode.current = Mode.ENFORCE
        assertTrue(PoseidonGate.shouldBlock("evil.test", "/"))
        assertTrue(seen.single().decision!!.block)
    }

    @Test fun monitorRecordsButNeverBlocks() {
        Mode.current = Mode.MONITOR
        assertFalse(PoseidonGate.shouldBlock("evil.test", "/"))
        assertTrue(seen.single().decision!!.block) // recorded as would-block
    }

    @Test fun allowedHostPathDenyBlocksInEnforce() {
        Mode.current = Mode.ENFORCE
        assertTrue(PoseidonGate.shouldBlock("example.com", "/blocked/x"))
        assertFalse(PoseidonGate.shouldBlock("example.com", "/ok"))
    }
}
