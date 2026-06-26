package tech.ssemaj.poseidon.runtime

import tech.ssemaj.poseidon.runtime.model.Action
import tech.ssemaj.poseidon.runtime.model.Decision
import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.runtime.model.Tier
import tech.ssemaj.poseidon.runtime.model.Transport

/**
 * Parses compact ring-event strings produced by the native drainEvents JNI call
 * into [EgressEvent] instances.
 *
 * Wire format: `ts|host|port|transport|tier|blocked|origin_addr`
 *   - ts:          CLOCK_MONOTONIC nanoseconds (uint64, or 0 if unavailable)
 *   - host:        hostname or IP literal (up to 63 chars)
 *   - port:        destination port (0 if unknown)
 *   - transport:   0=TCP/unknown, 1=UDP, 2=DNS  (POSEIDON_TRANSPORT_* in event_ring.h)
 *   - tier:        0=libc-interceptor, 1=seccomp-supervisor  (POSEIDON_TIER_* in event_ring.h)
 *   - blocked:     0=allowed or monitor-violation, 1=blocked
 *   - origin_addr: return-address into the calling SDK .so (resolved by [NativeShimBackend.symbolize])
 *
 * This class is pure (no JNI, no I/O) and is therefore JVM-unit-testable in isolation.
 */
internal object RingEventParser {

    /**
     * Parse a single wire-format string into an [EgressEvent].
     * Returns null if the string is malformed or any required field is missing.
     */
    fun parse(raw: String, symbolize: (Long) -> String?): EgressEvent? {
        val parts = raw.split('|')
        if (parts.size != 7) return null

        val ts         = parts[0].toLongOrNull() ?: return null
        val host       = parts[1].ifEmpty { null }
        val port       = parts[2].toIntOrNull() ?: 0
        val transport  = parts[3].toIntOrNull() ?: 0
        val tierInt    = parts[4].toIntOrNull() ?: 0
        val blocked    = (parts[5].toIntOrNull() ?: 0) != 0
        val originAddr = parts[6].toULongOrNull()?.toLong() ?: 0L

        val transportEnum = when (transport) {
            1    -> Transport.UDP
            2    -> Transport.DNS
            else -> Transport.TCP
        }
        val tierEnum = if (tierInt == 1) Tier.SECCOMP else Tier.NATIVE
        val action   = if (blocked) Action.BLOCK else Action.ALLOW
        val decision = Decision(action = action, reason = if (blocked) "native-block" else "")

        val originSymbol: String? = originAddr.takeIf { it != 0L }
            ?.let { runCatching { symbolize(it) }.getOrNull() }

        return EgressEvent(
            ts          = ts,
            tid         = 0,   // native thread id not captured; use 0
            host        = host,
            ip          = null, // IP is embedded in the host field from the native side
            port        = port,
            transport   = transportEnum,
            tier        = tierEnum,
            originToken = originSymbol ?: originAddr,
            decision    = decision,
        )
    }
}
