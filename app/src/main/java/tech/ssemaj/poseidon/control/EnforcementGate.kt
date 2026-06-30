package tech.ssemaj.poseidon.control

/**
 * Seam over Poseidon's runtime enforcement switch so the controller is unit-testable
 * without loading native code. The real implementation flips the public
 * Mode.current + NativeBridge APIs; tests use a fake.
 */
interface EnforcementGate {
    /** true = ENFORCE (block), false = MONITOR (log-only). */
    fun setEnforcing(enforce: Boolean)
}
