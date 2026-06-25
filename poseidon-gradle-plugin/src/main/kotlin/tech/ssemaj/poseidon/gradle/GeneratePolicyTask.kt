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

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val mergedManifest: RegularFileProperty

    @get:Input
    abstract val allowedCidrs: ListProperty<String>

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

        // Union DSL CIDRs into effectiveApp.
        effectiveApp = effectiveApp.copy(
            allowedCidrs = (effectiveApp.allowedCidrs + allowedCidrs.get()).distinct()
        )

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
                // YAML allowedCidrs → union into effectiveApp.allowedCidrs
                val yamlCidrs = (yaml["allowedCidrs"] as? List<*>)?.filterIsInstance<String>() ?: emptyList()
                if (yamlCidrs.isNotEmpty()) {
                    effectiveApp = effectiveApp.copy(
                        allowedCidrs = (effectiveApp.allowedCidrs + yamlCidrs).distinct()
                    )
                }
            }
        }

        // Extract library proposals from the merged manifest when available.
        val proposals = if (mergedManifest.isPresent && mergedManifest.get().asFile.exists())
            extractProposals(mergedManifest.get().asFile.readText()) else emptyList()
        val result = PolicyCompiler.compile(effectiveApp, proposals = proposals, dslHosts = dslHosts,
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

    companion object {
        /** Reads inline poseidon proposal meta-data from a merged manifest. */
        fun extractProposals(manifestXml: String): List<Proposal> {
            val doc = javax.xml.parsers.DocumentBuilderFactory.newInstance()
                .newDocumentBuilder()
                .parse(java.io.ByteArrayInputStream(manifestXml.toByteArray()))
            val nodes = doc.getElementsByTagName("meta-data")
            val out = mutableListOf<Proposal>()
            for (i in 0 until nodes.length) {
                val el = nodes.item(i) as org.w3c.dom.Element
                if (el.getAttribute("android:name") != "tech.ssemaj.poseidon.proposes") continue
                val lib = el.getAttribute("tools:node").ifEmpty { "unknown" }
                el.getAttribute("android:value").split(",").map { it.trim() }.filter { it.isNotEmpty() }
                    .forEach { out.add(Proposal(lib, it)) }
            }
            return out
        }
    }
}
