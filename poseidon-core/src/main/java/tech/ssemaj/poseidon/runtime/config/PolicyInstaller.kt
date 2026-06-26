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
    fun install(config: PolicyConfig) = with(config) {
        PolicyEngine.configure(allowedHosts, deniedPaths)
        Mode.current = mode
        NativeBridge.apply(allowedHosts, mode == Mode.ENFORCE)
        NativeBridge.setAllowedCidrs(allowedCidrs)
        NativeBridge.installSeccompGate(mode == Mode.ENFORCE || dnsCorrelation)
    }
}
