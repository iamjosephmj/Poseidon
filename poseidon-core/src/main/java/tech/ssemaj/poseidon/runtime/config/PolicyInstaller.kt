@file:OptIn(InternalPoseidonApi::class)

package tech.ssemaj.poseidon.runtime.config

import tech.ssemaj.poseidon.runtime.internal.InternalPoseidonApi
import tech.ssemaj.poseidon.runtime.internal.NativeBridge
import tech.ssemaj.poseidon.runtime.model.Mode
import tech.ssemaj.poseidon.runtime.policy.PolicyEngine

/**
 * Wires a parsed [PolicyConfig] into the running process in the prescribed order:
 * PolicyEngine → Mode → NativeBridge host list → NativeBridge CIDRs → seccomp gate.
 */
internal object PolicyInstaller {
    fun install(config: PolicyConfig) {
        PolicyEngine.configure(config.allowedHosts, config.deniedPaths)
        Mode.current = config.mode
        NativeBridge.apply(config.allowedHosts, config.mode == Mode.ENFORCE)
        NativeBridge.setAllowedCidrs(config.allowedCidrs)
        NativeBridge.installSeccompGate(config.mode == Mode.ENFORCE || config.dnsCorrelation)
    }
}
