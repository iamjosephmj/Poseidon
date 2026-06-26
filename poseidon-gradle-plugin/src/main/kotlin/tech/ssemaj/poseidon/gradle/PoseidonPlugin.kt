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

/**
 * Applies after the Android application/library plugin. For now wires the OkHttp
 * path-interceptor bytecode transform. Later: native ELF interposition over merged
 * native libs, compiled policy generation, and the static native-domain audit.
 */
class PoseidonPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        val ext = project.extensions.create("poseidon", PoseidonExtension::class.java)

        val components = project.extensions.findByType(AndroidComponentsExtension::class.java)
            ?: error("Poseidon must be applied after an Android application/library plugin")

        components.onVariants { variant ->
            val capitalizedVariant = variant.name.replaceFirstChar { c -> c.uppercase() }
            val policyYamlPath = ext.policyFile
            val mergedManifestProvider = variant.artifacts.get(SingleArtifact.MERGED_MANIFEST)

            // Compiled policy (DSL + optional YAML) -> generated asset, loaded at startup.
            val genTask = project.tasks.register(
                "generatePoseidonPolicy$capitalizedVariant", GeneratePolicyTask::class.java,
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
            // Gated by ext.injectNative (default false) — keeps the JVM-only
            // :poseidon-core path Play-clean (no binary modification).
            if (ext.injectNative) registerNativeInjection(project, capitalizedVariant, variant.name)
        }
    }

    private fun registerNativeInjection(project: Project, capitalizedVariant: String, variantName: String) {
        val inject = project.tasks.register(
            "poseidonInjectNative$capitalizedVariant", PoseidonNativeInjectTask::class.java,
        )
        inject.configure {
            strippedDir.set(
                project.layout.buildDirectory.dir("intermediates/stripped_native_libs/$variantName"),
            )
            // Ordering only (lenient: ignored if the task name differs/absent),
            // so we don't force creation of AGP's strip task.
            mustRunAfter("strip${capitalizedVariant}DebugSymbols")
        }
        // Both the APK packager and the AAB pre-bundle consume the (now-injected)
        // stripped libs; AGP signs each normally afterward (no re-sign).
        project.tasks.configureEach {
            if (name == "package$capitalizedVariant" || name == "build${capitalizedVariant}PreBundle") {
                dependsOn(inject)
            }
        }
    }
}
