package tech.ssemaj.poseidon.control

import tech.ssemaj.poseidon.runtime.internal.NativeBridge
import tech.ssemaj.poseidon.runtime.model.Mode

/**
 * Real enforcement seam against the published Poseidon runtime (public APIs only):
 * flips the JVM gate (Mode.current) and re-pushes the native allow-list with the new
 * enforce flag. The host list comes from the compiled policy so native re-config keeps
 * the same allow-list, only toggling block-vs-observe.
 */
class RuntimeEnforcementGate(private val allowedHosts: List<String>) : EnforcementGate {
    override fun setEnforcing(enforce: Boolean) {
        Mode.current = if (enforce) Mode.ENFORCE else Mode.MONITOR
        NativeBridge.apply(allowedHosts, enforce)
    }
}
