package tech.ssemaj.poseidon.gradle

import java.io.File

/** Injects the Poseidon shim as a DT_NEEDED into a prebuilt ELF .so (pure JVM). */
object ElfInjector {
    const val SHIM_SONAME = "libposeidon_shim.so"

    /** @return true if injection ran (false if already present / failed). */
    fun inject(so: File, soname: String = SHIM_SONAME): Boolean = try {
        ElfDtNeededInjector.inject(so, soname)
    } catch (t: Throwable) {
        System.err.println("[poseidon] ELF inject failed for ${so.name}: ${t.message}")
        false
    }
}
