package tech.ssemaj.poseidon.runtime

enum class Transport { TCP, UDP, DNS }
enum class Tier { JVM, NATIVE, SECCOMP }
enum class Action { ALLOW, BLOCK }

/** Result of a policy lookup. matchedRule is the glob/rule that decided it (for audit). */
data class Decision(
    val action: Action,
    val matchedRule: String? = null,
    val reason: String = "",
) {
    val block: Boolean get() = action == Action.BLOCK
}

/**
 * Source-agnostic egress record. Interceptors fill everything except [decision];
 * PolicyEngine fills [decision]. The engine, sink, and enforcer never branch on [tier].
 * [originToken] is captured cheaply (native return-address or a JVM stack ref) and
 * symbolized OFF the hot path by the Observer drain.
 */
data class EgressEvent(
    val ts: Long,
    val tid: Int,
    val host: String?,
    val ip: String?,
    val port: Int,
    val transport: Transport,
    val path: String? = null,
    val tier: Tier = Tier.JVM,
    val originToken: Any? = null,
    var decision: Decision? = null,
)
