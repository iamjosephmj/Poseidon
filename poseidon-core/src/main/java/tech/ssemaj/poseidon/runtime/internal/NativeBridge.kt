package tech.ssemaj.poseidon.runtime

/**
 * Pattern: **Bridge** (internal seam — NOT a consumer API) — decouples the abstraction
 * (core's policy push) from its implementation: poseidon-native registers a real
 * [Backend]; the default is no-op so the core AAR is
 * Play-policy clean without native code. (Not marked @InternalPoseidonApi because it is
 * implemented across the module boundary by poseidon-native's NativeShimBackend, which
 * would otherwise need an opt-in; the doc here states the intent.)
 */
object NativeBridge {
    interface Backend {
        fun apply(allowedHosts: List<String>, enforce: Boolean)
        fun cacheHostIps(host: String, ips: Array<String>)
        fun setAllowedCidrs(cidrs: List<String>)
        fun installSeccompGate(dnsCorrelation: Boolean)
    }
    @Volatile private var backend: Backend? = null
    @JvmStatic fun register(b: Backend) { backend = b }
    fun apply(allowedHosts: List<String>, enforce: Boolean) { backend?.apply(allowedHosts, enforce) }
    fun cacheHostIps(host: String, ips: Array<String>) { backend?.cacheHostIps(host, ips) }
    fun setAllowedCidrs(cidrs: List<String>) { backend?.setAllowedCidrs(cidrs) }
    fun installSeccompGate(dnsCorrelation: Boolean) { backend?.installSeccompGate(dnsCorrelation) }
}
