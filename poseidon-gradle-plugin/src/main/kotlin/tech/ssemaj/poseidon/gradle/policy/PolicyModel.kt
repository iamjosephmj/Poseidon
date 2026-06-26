package tech.ssemaj.poseidon.gradle.policy

/** Canonical mode values used as DSL defaults and matched in tasks/reports. */
const val MODE_MONITOR = "monitor"
const val MODE_ENFORCE = "enforce"

/** Unapproved-proposal action values. */
const val PROPOSALS_WARN = "warn"
const val PROPOSALS_ERROR = "error"

/** A network-host proposal emitted by an SDK library (from its merged manifest meta-data). */
data class Proposal(val library: String, val host: String)

/**
 * The parsed, declared network policy — the INPUT to [PolicyCompiler.compile].
 * Produced from the app's poseidon_policy.xml (plus optional DSL overrides).
 */
data class DeclaredPolicy(
    val mode: String,
    val allowedHosts: List<String>,
    val deniedPaths: List<String>,
    val dnsCorrelation: Boolean,
    val approvedLibraries: Set<String>,
    val allowedCidrs: List<String> = emptyList(),
)

/**
 * The output of [PolicyCompiler.compile]: the generated JSON asset, a human-readable
 * build report, and any proposals that were not approved.
 */
data class CompileResult(
    val policyJson: String,
    val report: String,
    val unapprovedProposals: List<Proposal>,
)
