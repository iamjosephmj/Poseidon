package tech.ssemaj.poseidon.runtime.model

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
