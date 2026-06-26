package tech.ssemaj.poseidon.runtime.internal

/**
 * Shared constants for the Poseidon runtime library.
 *
 * Centralising the log tag here prevents the "Poseidon" string literal from
 * scattering across every file that calls Log.i/w, and ensures that any
 * future rename only needs to change one place.
 */
internal object PoseidonConstants {
    /** Logcat tag used across all Poseidon runtime log calls. */
    const val LOG_TAG = "Poseidon"
}
