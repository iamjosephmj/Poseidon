package tech.ssemaj.poseidon.control

import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.runtime.model.Mode
import tech.ssemaj.poseidon.runtime.model.Tier

/** Allow/block counts for a single enforcement tier. */
data class TierTally(val tier: Tier, val allowed: Int, val blocked: Int)

/** Immutable snapshot the UI renders. Produced only by [PoseidonController]. */
data class UiState(
    val mode: Mode,
    val allowedTotal: Int,
    val blockedTotal: Int,
    val tierTallies: List<TierTally>,
    val events: List<EgressEvent>,
) {
    companion object {
        val EMPTY = UiState(Mode.MONITOR, 0, 0, emptyList(), emptyList())
    }
}
