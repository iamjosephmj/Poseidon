package tech.ssemaj.poseidon.runtime

/**
 * Marks a declaration as a Poseidon internal seam — not a stable consumer API.
 * Usage outside poseidon-core requires explicit opt-in.
 */
@RequiresOptIn(
    message = "Poseidon internal seam — not a consumer API",
    level = RequiresOptIn.Level.ERROR,
)
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY,
    AnnotationTarget.CONSTRUCTOR,
)
annotation class InternalPoseidonApi
