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
     * Trap sendto/recvfrom to correlate Go/raw-syscall DNS (IP->host) so the native gate
     * can enforce Go traffic by hostname. Default ON for full coverage. The connect-gate
     * (host enforce) runs regardless; this only adds Go *DNS* correlation, which costs
     * ~160µs per datagram op — set false for UDP/QUIC-heavy apps where that hurts.
     */
    var nativeDnsCorrelation: Boolean = true

    /** App-authoritative manifest policy XML (relative to the module). Canonical source. */
    var policyXml: String? = "src/main/res/xml/poseidon_policy.xml"

    /**
     * Opt-in IP/CIDR allow-list. When non-empty, closes the un-correlated bare-IP residual
     * in the seccomp gate: any raw/Go connect() to an IP not covered by a declared CIDR
     * (and not already allowed-by-host via the DNS-correlation cache) is blocked.
     *
     * Must include the CDN/cloud IP ranges of your allow-listed hosts (e.g. Cloudflare
     * ranges for example.com). Default empty = unchanged behavior (positive-identity only).
     */
    val allowedCidrs: MutableList<String> = mutableListOf()

    /** Grant every library proposal without explicit <approve> (default: only approved are granted). */
    var acceptProposals: Boolean = false

    /** Unapproved proposals: "warn" (default) logs them; "error" fails the build (CI gate). */
    var proposalsAction: String = "warn"

    /**
     * Inject the libposeidon_shim.so DT_NEEDED into the app's native libraries at build time
     * so native-SDK (libc) traffic is host-enforced. Default ON for full coverage; it safely
     * no-ops when the shim isn't packaged (a :poseidon-core-only build), so it never produces
     * a dangling dependency. Set false for a strictly Play-clean build with no binary
     * modification even when :poseidon-native/:poseidon-all is on the classpath.
     */
    var injectNative: Boolean = true
}
