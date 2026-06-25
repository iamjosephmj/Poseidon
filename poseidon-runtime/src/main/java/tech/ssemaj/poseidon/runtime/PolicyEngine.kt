package tech.ssemaj.poseidon.runtime

/** Result of a policy lookup. reroute is null unless a host rule rewrites the destination. */
data class Decision(
    val block: Boolean,
    val rerouteHost: String? = null,
    val reroutePort: Int = -1,
    val reason: String = "",
)

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

    /** Allow-list: if an allow-list is set, the host must match one of its globs. */
    @JvmStatic
    fun evaluateHost(host: String, port: Int): Decision {
        if (allowedHosts.isEmpty()) return Decision(block = false)
        val allowed = allowedHosts.any { glob(it, host) }
        return if (allowed) Decision(block = false)
        else Decision(block = true, reason = "host not in allow-list")
    }

    /** Deny-list: block if the path matches any denied glob. */
    @JvmStatic
    fun evaluatePath(host: String, path: String): Decision {
        val denied = deniedPaths.any { glob(it, path) }
        return if (denied) Decision(block = true, reason = "path in deny-list")
        else Decision(block = false)
    }

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
