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

    @Test fun fansOutToMultipleObservers() {
        val a = CopyOnWriteArrayList<EgressEvent>()
        val b = CopyOnWriteArrayList<EgressEvent>()
        Observer.setSink { a.add(it) }   // replaces the default
        Observer.addSink { b.add(it) }   // adds a second observer
        val e = EgressEvent(0L, 0, "example.com", null, 443, Transport.TCP, "/", Tier.JVM,
            decision = Decision(Action.ALLOW))
        Observer.record(e)
        assertEquals(1, a.size)
        assertEquals(1, b.size)
    }

    @Test fun aThrowingObserverDoesNotBreakOthers() {
        val ok = CopyOnWriteArrayList<EgressEvent>()
        Observer.setSink { throw RuntimeException("bad observer") }
        Observer.addSink { ok.add(it) }
        val e = EgressEvent(0L, 0, "example.com", null, 443, Transport.TCP, "/", Tier.JVM,
            decision = Decision(Action.ALLOW))
        Observer.record(e)               // must not throw
        assertEquals(1, ok.size)         // the healthy observer still received it
    }
}
