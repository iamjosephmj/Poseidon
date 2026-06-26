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

    // ---- Wire-format constants ----
    // The field order and delimiter below are the Kotlin side of the contract with
    // jni_bridge.c / drainEvents, which formats each event as:
    //   "%llu|%s|%d|%d|%d|%d|%llu"
    // i.e.  ts | host | port | transport | tier | blocked | origin_addr

    /** Delimiter character separating fields in the native ring wire format. */
    private const val RING_FIELD_DELIMITER = '|'

    /** Expected number of pipe-delimited fields per ring event string. */
    private const val RING_FIELD_COUNT = 7

    // Field indices within the split array (matches the drainEvents wire format above)
    private const val FIELD_IDX_TS           = 0
    private const val FIELD_IDX_HOST         = 1
    private const val FIELD_IDX_PORT         = 2
    private const val FIELD_IDX_TRANSPORT    = 3
    private const val FIELD_IDX_TIER         = 4
    private const val FIELD_IDX_BLOCKED      = 5
    private const val FIELD_IDX_ORIGIN_ADDR  = 6

    // Transport encoding — mirrors POSEIDON_TRANSPORT_* in event_ring.h
    private const val TRANSPORT_TCP = 0  // TCP or unknown socket type
    private const val TRANSPORT_UDP = 1  // connectionless UDP
    private const val TRANSPORT_DNS = 2  // DNS query/block

    // Tier encoding — mirrors POSEIDON_TIER_* in event_ring.h
    private const val TIER_LIBC    = 0  // libc-interceptor (DT_NEEDED interposition)
    private const val TIER_SECCOMP = 1  // seccomp USER_NOTIF supervisor

    /**
     * Parse a single wire-format string into an [EgressEvent].
     * Returns null if the string is malformed or any required field is missing.
     */
    fun parse(raw: String, symbolize: (Long) -> String?): EgressEvent? {
        val parts = raw.split(RING_FIELD_DELIMITER)
        if (parts.size != RING_FIELD_COUNT) return null

        val ts         = parts[FIELD_IDX_TS].toLongOrNull() ?: return null
        val host       = parts[FIELD_IDX_HOST].ifEmpty { null }
        val port       = parts[FIELD_IDX_PORT].toIntOrNull() ?: 0
        val transport  = parts[FIELD_IDX_TRANSPORT].toIntOrNull() ?: TRANSPORT_TCP
        val tierInt    = parts[FIELD_IDX_TIER].toIntOrNull() ?: TIER_LIBC
        val blocked    = (parts[FIELD_IDX_BLOCKED].toIntOrNull() ?: 0) != 0
        val originAddr = parts[FIELD_IDX_ORIGIN_ADDR].toULongOrNull()?.toLong() ?: 0L

        val transportEnum = when (transport) {
            TRANSPORT_UDP -> Transport.UDP
            TRANSPORT_DNS -> Transport.DNS
            else          -> Transport.TCP
        }
        val tierEnum = if (tierInt == TIER_SECCOMP) Tier.SECCOMP else Tier.NATIVE
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
