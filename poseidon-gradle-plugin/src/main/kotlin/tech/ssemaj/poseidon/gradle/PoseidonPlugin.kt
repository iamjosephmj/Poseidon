package tech.ssemaj.poseidon.gradle

import com.android.build.api.instrumentation.FramesComputationMode
import com.android.build.api.instrumentation.InstrumentationScope
import com.android.build.api.variant.AndroidComponentsExtension
import org.gradle.api.Plugin
import org.gradle.api.Project

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
            // Compiled policy (DSL + optional YAML) -> generated asset, loaded at startup.
            val cap = variant.name.replaceFirstChar { c -> c.uppercase() }
            val hosts = ext.allowedHosts.toList()
            val paths = ext.deniedPaths.toList()
            val md = ext.mode
            val pf = ext.policyFile
            val dns = ext.nativeDnsCorrelation
            val mergedManifestProvider = variant.artifacts.get(com.android.build.api.artifact.SingleArtifact.MERGED_MANIFEST)
            val genTask = project.tasks.register("generatePoseidonPolicy$cap", GeneratePolicyTask::class.java)
            genTask.configure {
                allowedHosts.set(hosts)
                deniedPaths.set(paths)
                mode.set(md)
                dnsCorrelation.set(dns)
                if (pf != null) policyFile.set(project.layout.projectDirectory.file(pf))
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

            // Native host layer: inject the shim into the stripped native libs in
            // place, AFTER strip and BEFORE package — no re-sign, nothing after R8.
            // (AGP exposes native libs only as internal Replaceable artifacts, so we
            // hook the task graph rather than the Artifacts API.)
            val inject = project.tasks.register(
                "poseidonInjectNative$cap", PoseidonNativeInjectTask::class.java,
            )
            inject.configure {
                strippedDir.set(
                    project.layout.buildDirectory.dir("intermediates/stripped_native_libs/${variant.name}"),
                )
                // Ordering only (lenient: ignored if the task name differs/absent),
                // so we don't force creation of AGP's strip task.
                mustRunAfter("strip${cap}DebugSymbols")
            }
            // Both the APK packager and the AAB pre-bundle consume the (now-injected)
            // stripped libs; AGP signs each normally afterward (no re-sign).
            project.tasks.configureEach {
                if (name == "package$cap" || name == "build${cap}PreBundle") dependsOn(inject)
            }
        }
    }
}
