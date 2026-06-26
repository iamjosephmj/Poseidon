package tech.ssemaj.poseidon.runtime.policy

import tech.ssemaj.poseidon.runtime.model.Action
import tech.ssemaj.poseidon.runtime.model.Decision
import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.runtime.model.Tier

/**
 * Host = allow-list (default-deny once configured); Path = deny-list (default-allow).
 * Configured at runtime for now; the Gradle plugin will later generate this table
 * from the DSL/YAML and install it at startup.
 */
object PolicyEngine {
    @Volatile private var allowedHosts: List<String> = emptyList()
    @Volatile private var deniedPaths: List<String> = emptyList()

    // ---- Semantic rule-tag constants ----
    // These string values are embedded verbatim in Decision.matchedRule and are therefore
    // part of the observable audit contract.  Renaming a constant MUST be paired with any
    // consumer code that pattern-matches on rule tags.

    /** Tag emitted when no allow-list rule matches (default-deny posture). */
    private const val RULE_DEFAULT_DENY = "default-deny"

    /** Prefix for a rule tag that names the denied path pattern; e.g. deny-path:/admin/foo. */
    private const val RULE_DENY_PATH_PREFIX = "deny-path:"

    /** Prefix for a rule tag that names the matched allow pattern; e.g. "allow:*.example.com". */
    private const val RULE_ALLOW_PREFIX = "allow:"

    @JvmStatic
    fun configure(allowedHosts: List<String>, deniedPaths: List<String>) {
        this.allowedHosts = allowedHosts
        this.deniedPaths = deniedPaths
    }

    /** The single decision point. Host allow-list first, then path deny-list (JVM tier only). */
    @JvmStatic
    fun evaluate(event: EgressEvent): Decision {
        val matchedAllowRule = event.host?.let { h -> allowedHosts.firstOrNull { Glob.matches(it, h) } }
        if (allowedHosts.isNotEmpty() && matchedAllowRule == null) {
            return Decision(Action.BLOCK, matchedRule = RULE_DEFAULT_DENY, reason = "host not in allow-list")
        }
        if (event.tier == Tier.JVM) {
            val deny = event.path?.let { path -> deniedPaths.firstOrNull { Glob.matches(it, path) } }
            if (deny != null) {
                return Decision(Action.BLOCK, matchedRule = "$RULE_DENY_PATH_PREFIX$deny", reason = "path in deny-list")
            }
        }
        return Decision(Action.ALLOW, matchedRule = matchedAllowRule?.let { "$RULE_ALLOW_PREFIX$it" }, reason = "")
    }
}
