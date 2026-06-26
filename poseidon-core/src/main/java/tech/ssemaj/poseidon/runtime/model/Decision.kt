package tech.ssemaj.poseidon.runtime

/** Result of a policy lookup. matchedRule is the glob/rule that decided it (for audit). */
data class Decision(
    val action: Action,
    val matchedRule: String? = null,
    val reason: String = "",
) {
    val block: Boolean get() = action == Action.BLOCK
}
