package tech.ssemaj.poseidon.runtime

/** The only unit that decides whether a BLOCK decision becomes an actual block. */
object ModeGate {
    @JvmStatic
    fun shouldBlock(decision: Decision): Boolean =
        Mode.current == Mode.ENFORCE && decision.block
}
