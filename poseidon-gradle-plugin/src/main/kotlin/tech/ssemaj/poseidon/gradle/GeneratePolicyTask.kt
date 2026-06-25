package tech.ssemaj.poseidon.gradle

import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault
import org.yaml.snakeyaml.Yaml
import java.io.File

/** Merges DSL + optional YAML into a compiled policy asset: poseidon/policy.json. */
@DisableCachingByDefault(because = "trivial codegen")
abstract class GeneratePolicyTask : DefaultTask() {

    @get:Input
    abstract val allowedHosts: ListProperty<String>

    @get:Input
    abstract val deniedPaths: ListProperty<String>

    @get:Input
    abstract val mode: Property<String>

    @get:Input
    abstract val dnsCorrelation: Property<Boolean>

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val policyFile: RegularFileProperty

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val appPolicyXml: RegularFileProperty

    @get:Input
    abstract val proposalsAction: Property<String>

    @get:Input
    abstract val acceptProposals: Property<Boolean>

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun generate() {
        // DSL/YAML escape hatch (unchanged path) provides augmenting hosts + fallback mode.
        val dslHosts = allowedHosts.get().toMutableList()
        val app = if (appPolicyXml.isPresent && appPolicyXml.get().asFile.exists()) {
            PolicyXml.parseAppPolicy(appPolicyXml.get().asFile.readText())
        } else {
            CompiledPolicy(mode.get(), emptyList(), deniedPaths.get().toList(), dnsCorrelation.get(), emptySet())
        }

        // Fix 1: OR-in the DSL nativeDnsCorrelation so the escape-hatch augments the XML value.
        var effectiveApp = app.copy(dnsCorrelation = app.dnsCorrelation || dnsCorrelation.get())

        // Fix 2: Parse optional YAML policyFile and union its fields into the compile inputs.
        if (policyFile.isPresent && policyFile.get().asFile.exists()) {
            @Suppress("UNCHECKED_CAST")
            val yaml = Yaml().load<Map<String, Any?>>(policyFile.get().asFile.readText())
            if (yaml != null) {
                // YAML allowedHosts → union into dslHosts
                (yaml["allowedHosts"] as? List<*>)?.filterIsInstance<String>()?.forEach { host ->
                    if (host !in dslHosts) dslHosts.add(host)
                }
                // YAML deniedPaths → union into effectiveApp.deniedPaths
                val yamlDenied = (yaml["deniedPaths"] as? List<*>)?.filterIsInstance<String>() ?: emptyList()
                if (yamlDenied.isNotEmpty()) {
                    effectiveApp = effectiveApp.copy(
                        deniedPaths = (effectiveApp.deniedPaths + yamlDenied).distinct()
                    )
                }
                // YAML mode (if present) → override effectiveApp.mode
                (yaml["mode"] as? String)?.let { yamlMode ->
                    effectiveApp = effectiveApp.copy(mode = yamlMode)
                }
                // YAML nativeDnsCorrelation → OR into effectiveApp.dnsCorrelation
                if (yaml["nativeDnsCorrelation"] == true) {
                    effectiveApp = effectiveApp.copy(dnsCorrelation = true)
                }
            }
        }

        // Library proposals are merged into the manifest by AGP; for now read none here
        // (Task 2.4 wires the merged-manifest proposal extraction). Empty list = app-only.
        val result = PolicyCompiler.compile(effectiveApp, proposals = emptyList(), dslHosts = dslHosts,
            acceptProposals = acceptProposals.get())

        val dir = File(outputDir.get().asFile, "poseidon").apply { mkdirs() }
        File(dir, "policy.json").writeText(result.policyJson)
        File(dir, "policy-report.txt").writeText(result.report)
        logger.lifecycle("[poseidon] ${result.report.lines().first()}")
        if (result.unapprovedProposals.isNotEmpty()) {
            val msg = "[poseidon] ${result.unapprovedProposals.size} unapproved library proposal(s)"
            if (proposalsAction.get() == "error") error(msg) else logger.warn(msg)
        }
    }
}
