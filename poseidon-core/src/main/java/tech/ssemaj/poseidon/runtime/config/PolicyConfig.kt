package tech.ssemaj.poseidon.runtime.config

import tech.ssemaj.poseidon.runtime.model.Mode

/** Parsed value object from poseidon/policy.json. */
internal data class PolicyConfig(
    val mode: Mode,
    val allowedHosts: List<String>,
    val deniedPaths: List<String>,
    val allowedCidrs: List<String>,
    val dnsCorrelation: Boolean,
)
