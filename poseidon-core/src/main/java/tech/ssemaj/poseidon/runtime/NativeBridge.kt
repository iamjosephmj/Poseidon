package tech.ssemaj.poseidon.runtime

/**
 * Core-side seam for the native backend. poseidon-native registers a real [Backend];
 * the default is no-op so the core AAR is Play-policy clean without native code.
 */
@InternalPoseidonApi
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
