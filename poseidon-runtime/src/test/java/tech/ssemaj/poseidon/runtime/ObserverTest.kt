package tech.ssemaj.poseidon.runtime

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList

class ObserverTest {
    @After fun tearDown() = Observer.resetSink()

    @Test fun recordsInBothModes() {
        val seen = CopyOnWriteArrayList<EgressEvent>()
        Observer.setSink { seen.add(it) }
        val allow = EgressEvent(0L, 0, "example.com", null, 443, Transport.TCP, "/", Tier.JVM,
            decision = Decision(Action.ALLOW))
        val block = allow.copy(host = "evil.test", decision = Decision(Action.BLOCK, reason = "x"))
        Mode.current = Mode.MONITOR; Observer.record(allow)
        Mode.current = Mode.ENFORCE; Observer.record(block)
        assertEquals(2, seen.size)
    }
}
