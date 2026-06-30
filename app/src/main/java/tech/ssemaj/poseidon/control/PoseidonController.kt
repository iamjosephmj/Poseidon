package tech.ssemaj.poseidon.control

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.runtime.model.Mode
import tech.ssemaj.poseidon.runtime.model.Tier

/**
 * Single seam to the Poseidon runtime for the demo UI. Aggregates audit events into a
 * render-ready [UiState] and flips enforcement through an [EnforcementGate]. Pure logic —
 * no Android or native types beyond the public runtime model — so it is unit-testable.
 */
class PoseidonController(
    initialMode: Mode,
    private val gate: EnforcementGate,
    private val maxEvents: Int = 100,
) {
    private val _state = MutableStateFlow(UiState.EMPTY.copy(mode = initialMode))
    val state: StateFlow<UiState> = _state.asStateFlow()

    /** Called for every EgressEvent (from the Observer sink). Thread: arbitrary. */
    @Synchronized
    fun onEvent(event: EgressEvent) {
        val events = (listOf(event) + _state.value.events).take(maxEvents)
        _state.value = _state.value.copy(
            events = events,
            allowedTotal = events.count { it.decision?.block != true }, // null decision = no block decision = pass-through, counts as allowed
            blockedTotal = events.count { it.decision?.block == true },
            tierTallies = tally(events),
        )
    }

    @Synchronized
    fun setMode(mode: Mode) {
        gate.setEnforcing(mode == Mode.ENFORCE)
        _state.value = _state.value.copy(mode = mode)
    }

    @Synchronized
    fun toggleMode() =
        setMode(if (_state.value.mode == Mode.ENFORCE) Mode.MONITOR else Mode.ENFORCE)

    private fun tally(events: List<EgressEvent>): List<TierTally> =
        Tier.entries.map { tier ->
            val forTier = events.filter { it.tier == tier }
            TierTally(
                tier = tier,
                allowed = forTier.count { it.decision?.block != true },
                blocked = forTier.count { it.decision?.block == true },
            )
        }
}
