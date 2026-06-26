package tech.ssemaj.poseidon.gradle.policy

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
import java.io.File

/** Merges DSL + optional YAML into a compiled policy asset: poseidon/policy.json. */
@DisableCachingByDefault(because = "trivial codegen")
abstract class GeneratePolicyTask : DefaultTask() {

    @get:Input abstract val allowedHosts: ListProperty<String>
    @get:Input abstract val deniedPaths: ListProperty<String>
    @get:Input abstract val mode: Property<String>
    @get:Input abstract val dnsCorrelation: Property<Boolean>

    @get:InputFile @get:Optional @get:PathSensitive(PathSensitivity.NONE)
    abstract val policyFile: RegularFileProperty

    @get:InputFile @get:Optional @get:PathSensitive(PathSensitivity.NONE)
    abstract val appPolicyXml: RegularFileProperty

    @get:InputFile @get:Optional @get:PathSensitive(PathSensitivity.NONE)
    abstract val mergedManifest: RegularFileProperty

    @get:Input abstract val allowedCidrs: ListProperty<String>
    @get:Input abstract val proposalsAction: Property<String>
    @get:Input abstract val acceptProposals: Property<Boolean>

    @get:OutputDirectory abstract val outputDir: DirectoryProperty

    @TaskAction
    fun generate() {
        val dslHosts = allowedHosts.get().toMutableList()

        // Build the base declared policy from XML or DSL fallback.
        var effectiveApp = if (appPolicyXml.isPresent && appPolicyXml.get().asFile.exists()) {
            AppPolicyXmlParser.parseAppPolicy(appPolicyXml.get().asFile.readText())
        } else {
            DeclaredPolicy(
                mode.get(), emptyList(), deniedPaths.get().toList(), dnsCorrelation.get(), emptySet(),
            )
        }

        // OR-in the DSL nativeDnsCorrelation so the escape-hatch augments the XML value;
        // union DSL CIDRs into effectiveApp.
        effectiveApp = effectiveApp.copy(
            dnsCorrelation = effectiveApp.dnsCorrelation || dnsCorrelation.get(),
            allowedCidrs = (effectiveApp.allowedCidrs + allowedCidrs.get()).distinct(),
        )

        // Apply optional YAML overlay (hosts unioned into dslHosts; mode/paths/cidrs merged).
        if (policyFile.isPresent && policyFile.get().asFile.exists()) {
            effectiveApp = YamlPolicyOverlay.merge(effectiveApp, dslHosts, policyFile.get().asFile)
        }

        // Extract library proposals from the merged manifest when available.
        val proposals = if (mergedManifest.isPresent && mergedManifest.get().asFile.exists())
            AppPolicyXmlParser.parseManifestProposals(mergedManifest.get().asFile.readText())
        else emptyList()

        val result = PolicyCompiler.compile(
            effectiveApp, proposals = proposals, dslHosts = dslHosts,
            acceptProposals = acceptProposals.get(),
        )

        val dir = File(outputDir.get().asFile, "poseidon").apply { mkdirs() }
        File(dir, "policy.json").writeText(result.policyJson)
        File(dir, "policy-report.txt").writeText(result.report)
        logger.lifecycle("[poseidon] ${result.report.lines().first()}")
        if (result.unapprovedProposals.isNotEmpty()) {
            val msg = "[poseidon] ${result.unapprovedProposals.size} unapproved library proposal(s)"
            if (proposalsAction.get() == PROPOSALS_ERROR) error(msg) else logger.warn(msg)
        }
    }
}
