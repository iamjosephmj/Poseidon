package tech.ssemaj.poseidon.gradle

import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault

/**
 * Injects the Poseidon shim (DT_NEEDED) into the merged+stripped native libs IN
 * PLACE, wired to run after the strip task and before the package task — so AGP
 * packages + signs normally afterward (no re-sign, nothing runs after R8).
 *
 * Native libs are AGP-internal Replaceable artifacts (not Transformable, and not
 * readable via Artifacts.get()), so this hooks the task graph + intermediates dir
 * directly. The injector is idempotent, so reruns / up-to-date strip are safe.
 */
@DisableCachingByDefault(because = "edits intermediates in place; idempotent")
abstract class PoseidonNativeInjectTask : DefaultTask() {

    @get:Internal
    abstract val strippedDir: DirectoryProperty

    init {
        outputs.upToDateWhen { false } // always run; injector skips already-injected libs
    }

    @TaskAction
    fun run() {
        val root = strippedDir.get().asFile
        if (!root.exists()) {
            logger.lifecycle("[poseidon] no native libs to inject")
            return
        }
        var injected = 0
        root.walkTopDown()
            .filter { it.isFile && it.extension == "so" && it.name != ElfInjector.SHIM_SONAME }
            .forEach { if (ElfInjector.inject(it)) injected++ }
        logger.lifecycle("[poseidon] injected shim into $injected native lib(s) (pre-packaging, in place)")
    }
}
