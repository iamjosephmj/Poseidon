package tech.ssemaj.poseidon.runtime

/**
 * Host = allow-list (default-deny once configured); Path = deny-list (default-allow).
 * Configured at runtime for now; the Gradle plugin will later generate this table
 * from the DSL/YAML and install it at startup.
 */
object PolicyEngine {
    @Volatile private var allowedHosts: List<String> = emptyList()
    @Volatile private var deniedPaths: List<String> = emptyList()

    @JvmStatic
    fun configure(allowedHosts: List<String>, deniedPaths: List<String>) {
        this.allowedHosts = allowedHosts
        this.deniedPaths = deniedPaths
    }

    /** The single decision point. Host allow-list first, then path deny-list (JVM tier only). */
    @JvmStatic
    fun evaluate(event: EgressEvent): Decision {
        val host = event.host
        if (allowedHosts.isNotEmpty()) {
            val matched = host?.let { h -> allowedHosts.firstOrNull { glob(it, h) } }
            if (matched == null) {
                return Decision(Action.BLOCK, matchedRule = "default-deny", reason = "host not in allow-list")
            }
        }
        if (event.tier == Tier.JVM) {
            val path = event.path
            if (path != null) {
                val deny = deniedPaths.firstOrNull { glob(it, path) }
                if (deny != null) {
                    return Decision(Action.BLOCK, matchedRule = "deny-path:$deny", reason = "path in deny-list")
                }
            }
        }
        val allowRule = host?.let { h -> allowedHosts.firstOrNull { glob(it, h) } }?.let { "allow:$it" }
        return Decision(Action.ALLOW, matchedRule = allowRule, reason = "")
    }

    /** Visible for the equivalence suite; mirrors the native fnmatch semantics. */
    @JvmStatic
    fun matches(pattern: String, value: String): Boolean = glob(pattern, value)

    private fun glob(pattern: String, value: String): Boolean {
        val regex = buildString {
            append('^')
            for (c in pattern) when (c) {
                '*' -> append(".*")
                '.', '?', '+', '(', ')', '[', ']', '{', '}', '\\', '^', '$', '|' -> {
                    append('\\'); append(c)
                }
                else -> append(c)
            }
            append('$')
        }
        return Regex(regex).matches(value)
    }
}
