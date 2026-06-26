package tech.ssemaj.poseidon.runtime

/** MONITOR logs what would happen; ENFORCE acts on policy. Set per build type. */
enum class Mode {
    MONITOR,
    ENFORCE;

    companion object {
        @JvmStatic
        @Volatile
        var current: Mode = MONITOR
    }
}
