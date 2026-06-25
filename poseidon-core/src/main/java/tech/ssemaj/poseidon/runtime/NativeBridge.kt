package tech.ssemaj.poseidon.runtime

/** Core-side seam. poseidon-native registers a real backend; default is no-op (Play-clean core). */
object NativeBridge {
    interface Backend {
        fun apply(allowedHosts: List<String>, enforce: Boolean)
        fun cacheHostIps(host: String, ips: Array<String>)
        fun installSeccompGate(dnsCorrelation: Boolean)
    }
    @Volatile private var backend: Backend? = null
    @JvmStatic fun register(b: Backend) { backend = b }
    fun apply(allowedHosts: List<String>, enforce: Boolean) { backend?.apply(allowedHosts, enforce) }
    fun cacheHostIps(host: String, ips: Array<String>) { backend?.cacheHostIps(host, ips) }
    fun installSeccompGate(dnsCorrelation: Boolean) { backend?.installSeccompGate(dnsCorrelation) }
}
