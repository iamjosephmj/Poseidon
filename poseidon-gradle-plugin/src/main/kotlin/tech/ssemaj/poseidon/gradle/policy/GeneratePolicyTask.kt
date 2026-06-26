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

// ---------------------------------------------------------------------------
// Asset output paths — these values are read verbatim by the runtime at
// startup and MUST NOT be changed without a matching runtime update.
// ---------------------------------------------------------------------------
/** Subdirectory (inside the generated assets dir) that holds all Poseidon outputs. */
private const val POLICY_ASSET_SUBDIR   = "poseidon"
/** Filename of the compiled policy JSON asset; loaded by the runtime at startup. */
private const val POLICY_JSON_FILE      = "policy.json"
/** Filename of the human-readable build report (not packaged into the APK). */
private const val POLICY_REPORT_FILE    = "policy-report.txt"

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

        val dir = File(outputDir.get().asFile, POLICY_ASSET_SUBDIR).apply { mkdirs() }
        File(dir, POLICY_JSON_FILE).writeText(result.policyJson)
        File(dir, POLICY_REPORT_FILE).writeText(result.report)
        logger.lifecycle("[poseidon] ${result.report.lines().first()}")
        if (result.unapprovedProposals.isNotEmpty()) {
            val msg = "[poseidon] ${result.unapprovedProposals.size} unapproved library proposal(s)"
            if (proposalsAction.get() == PROPOSALS_ERROR) error(msg) else logger.warn(msg)
        }
    }
}
