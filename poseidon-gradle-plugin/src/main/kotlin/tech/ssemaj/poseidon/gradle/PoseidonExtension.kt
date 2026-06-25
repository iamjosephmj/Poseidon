package tech.ssemaj.poseidon.gradle

/**
 * Build-script config. Host = allow-list (default-deny), Path = deny-list.
 * An optional YAML file is merged on top (lists unioned, mode overridden if set).
 *
 * poseidon {
 *     allowedHosts.add("example.com")
 *     deniedPaths.add("/track")
 *     mode = "enforce"            // or "monitor"
 *     policyFile = "poseidon-policy.yml"
 * }
 */
open class PoseidonExtension {
    val allowedHosts: MutableList<String> = mutableListOf()
    val deniedPaths: MutableList<String> = mutableListOf()
    var mode: String = "monitor"
    var policyFile: String? = null

    /**
     * Opt-in: trap sendto/recvfrom to correlate Go/raw-syscall DNS (IP->host) so the
     * native gate can enforce Go traffic by hostname. Costs ~160µs per datagram op —
     * brutal for UDP/QUIC-heavy apps — so default OFF. The connect-gate (host enforce)
     * runs regardless; this only adds Go *DNS* correlation.
     */
    var nativeDnsCorrelation: Boolean = false
}
