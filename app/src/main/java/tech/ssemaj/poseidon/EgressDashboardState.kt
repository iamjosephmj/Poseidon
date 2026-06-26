package tech.ssemaj.poseidon

import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.mutableStateListOf
import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.runtime.model.Tier
import tech.ssemaj.poseidon.runtime.pipeline.Observer

private const val MAX_LOG_ENTRIES = 100

/** Wraps an [EgressEvent] with a monotonically-increasing [id] for stable LazyColumn keys. */
data class LoggedEvent(val id: Long, val event: EgressEvent)

/**
 * Observable state holder for the Poseidon live-egress dashboard.
 *
 * Registers an [Observer] sink that marshals every audit event to the main thread before
 * prepending it to [events] — a Compose-snapshot-safe list that drives recomposition.
 * The sink captures [EgressEvent] references and never blocks the caller thread.
 *
 * Lifecycle: call [start] once the UI is ready, [stop] in [android.app.Activity.onDestroy].
 */
class EgressDashboardState {

    /** Live audit log, newest entry at index 0, capped at [MAX_LOG_ENTRIES]. */
    val events = mutableStateListOf<LoggedEvent>()

    private val mainHandler = Handler(Looper.getMainLooper())
    private var counter = 0L

    private val sink: (EgressEvent) -> Unit = { event ->
        mainHandler.post {
            events.add(0, LoggedEvent(id = counter++, event = event))
            while (events.size > MAX_LOG_ENTRIES) events.removeAt(events.lastIndex)
        }
    }

    /** Register our sink with the audit Observer. */
    fun start() = Observer.addSink(sink)

    /** Deregister our sink (called in onDestroy to prevent leaks). */
    fun stop() = Observer.removeSink(sink)

    /** Events on [tier] that were allowed (decision is null = not blocked, or block == false). */
    fun allowCount(tier: Tier): Int =
        events.count { it.event.tier == tier && it.event.decision?.block != true }

    /** Events on [tier] that were explicitly blocked. */
    fun blockCount(tier: Tier): Int =
        events.count { it.event.tier == tier && it.event.decision?.block == true }
}
