package tech.ssemaj.poseidon.gradle

import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.instrumentation.FramesComputationMode
import com.android.build.api.instrumentation.InstrumentationScope
import com.android.build.api.variant.AndroidComponentsExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import tech.ssemaj.poseidon.gradle.elf.PoseidonNativeInjectTask
import tech.ssemaj.poseidon.gradle.policy.GeneratePolicyTask
import tech.ssemaj.poseidon.gradle.transform.PoseidonClassVisitorFactory

// ---------------------------------------------------------------------------
/** Runtime AAR version the plugin pulls in automatically (kept in lockstep with the
 *  plugin release) so consumers only apply the plugin — no separate `implementation(...)`. */
private const val POSEIDON_RUNTIME_VERSION = "0.1.4"
private const val POSEIDON_GROUP = "com.github.iamjosephmj.Poseidon"

// Task name prefixes — one task per variant is registered as "<prefix><Variant>".
// ---------------------------------------------------------------------------
/** Prefix for the per-variant policy-generation task (e.g. generatePoseidonPolicyDebug). */
private const val TASK_GENERATE_POLICY = "generatePoseidonPolicy"
/** Prefix for the per-variant native ELF injection task (e.g. poseidonInjectNativeDebug). */
private const val TASK_INJECT_NATIVE   = "poseidonInjectNative"

// ---------------------------------------------------------------------------
// AGP task name fragments — used to locate AGP-internal tasks by name pattern.
// The actual string values must stay identical so task-graph wiring resolves correctly.
// ---------------------------------------------------------------------------
/** AGP strip-task prefix: task name is "<prefix><Variant><suffix>" (e.g. stripDebugDebugSymbols). */
private const val AGP_STRIP_PREFIX      = "strip"
/** AGP strip-task suffix: appended after the capitalised variant name. */
private const val AGP_STRIP_SUFFIX      = "DebugSymbols"
/** AGP APK packager task prefix: task name is "<prefix><Variant>" (e.g. packageDebug). */
private const val AGP_PACKAGE_PREFIX    = "package"
/** AGP AAB pre-bundle task prefix: task name is "<prefix><Variant><suffix>" (e.g. buildDebugPreBundle). */
private const val AGP_PRE_BUNDLE_PREFIX = "build"
/** AGP AAB pre-bundle task suffix: appended after the capitalised variant name. */
private const val AGP_PRE_BUNDLE_SUFFIX = "PreBundle"

// ---------------------------------------------------------------------------
// AGP intermediates path — the directory where AGP places stripped native libs
// between the strip task and the package task.
// ---------------------------------------------------------------------------
/** Relative path (from build dir) to the stripped native libs intermediates directory. */
private const val AGP_STRIPPED_LIBS_PATH = "intermediates/stripped_native_libs/"

/**
 * Applies after the Android application/library plugin. For now wires the OkHttp
 * path-interceptor bytecode transform. Later: native ELF interposition over merged
 * native libs, compiled policy generation, and the static native-domain audit.
 */
class PoseidonPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        val ext = project.extensions.create("poseidon", PoseidonExtension::class.java)

        // Pull the Poseidon runtime in automatically so a consumer only applies the plugin —
        // no separate `implementation("...poseidon-all")` line. injectNative picks the native
        // umbrella vs the Play-clean JVM-only core. Deferred to afterEvaluate so the
        // consumer's `poseidon { }` block has been configured.
        project.afterEvaluate {
            val artifact = if (ext.injectNative) "poseidon-all" else "poseidon-core"
            project.dependencies.add(
                "implementation",
                "$POSEIDON_GROUP:$artifact:$POSEIDON_RUNTIME_VERSION",
            )
        }

        val components = project.extensions.findByType(AndroidComponentsExtension::class.java)
            ?: error("Poseidon must be applied after an Android application/library plugin")

        components.onVariants { variant ->
            val capitalizedVariant = variant.name.replaceFirstChar { it.uppercase() }
            val policyYamlPath = ext.policyFile
            val mergedManifestProvider = variant.artifacts.get(SingleArtifact.MERGED_MANIFEST)

            // Compiled policy (DSL + optional YAML) -> generated asset, loaded at startup.
            val genTask = project.tasks.register(
                "$TASK_GENERATE_POLICY$capitalizedVariant", GeneratePolicyTask::class.java,
            )
            genTask.configure {
                allowedHosts.set(ext.allowedHosts.toList())
                deniedPaths.set(ext.deniedPaths.toList())
                mode.set(ext.mode)
                dnsCorrelation.set(ext.nativeDnsCorrelation)
                allowedCidrs.set(ext.allowedCidrs.toList())
                if (policyYamlPath != null) policyFile.set(project.layout.projectDirectory.file(policyYamlPath))
                proposalsAction.set(ext.proposalsAction)
                acceptProposals.set(ext.acceptProposals)
                ext.policyXml?.let { appPolicyXml.set(project.layout.projectDirectory.file(it)) }
                mergedManifest.set(mergedManifestProvider)
            }
            variant.sources.assets?.addGeneratedSourceDirectory(genTask) { it.outputDir }

            // Path layer: inject HTTP-client adapters (OkHttp interceptor, HttpURLConnection
            // call-site guard, …) via bytecode — runs before R8.
            variant.instrumentation.transformClassesWith(
                PoseidonClassVisitorFactory::class.java,
                InstrumentationScope.ALL,
            ) { /* InstrumentationParameters.None */ }
            variant.instrumentation.setAsmFramesComputationMode(
                FramesComputationMode.COMPUTE_FRAMES_FOR_INSTRUMENTED_METHODS,
            )

            // Native host layer: inject the shim into the stripped native libs in place,
            // AFTER strip and BEFORE package — no re-sign, nothing after R8.
            // Gated by ext.injectNative (default true; the task self-skips when the shim
            // isn't packaged, so a JVM-only :poseidon-core build stays Play-clean).
            if (ext.injectNative) registerNativeInjection(project, capitalizedVariant, variant.name)
        }
    }

    private fun registerNativeInjection(project: Project, capitalizedVariant: String, variantName: String) {
        val inject = project.tasks.register(
            "$TASK_INJECT_NATIVE$capitalizedVariant", PoseidonNativeInjectTask::class.java,
        )
        inject.configure {
            strippedDir.set(
                project.layout.buildDirectory.dir("$AGP_STRIPPED_LIBS_PATH$variantName"),
            )
            // Ordering only (lenient: ignored if the task name differs/absent),
            // so we don't force creation of AGP's strip task.
            mustRunAfter("$AGP_STRIP_PREFIX$capitalizedVariant$AGP_STRIP_SUFFIX")
        }
        // Both the APK packager and the AAB pre-bundle consume the (now-injected)
        // stripped libs; AGP signs each normally afterward (no re-sign).
        project.tasks.configureEach {
            if (name == "$AGP_PACKAGE_PREFIX$capitalizedVariant" ||
                name == "$AGP_PRE_BUNDLE_PREFIX$capitalizedVariant$AGP_PRE_BUNDLE_SUFFIX") {
                dependsOn(inject)
            }
        }
    }
}
