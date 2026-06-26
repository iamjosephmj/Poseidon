package tech.ssemaj.poseidon.runtime

/** Shared glob-matching logic; semantics mirror native fnmatch. '*' matches any sequence. */
internal object Glob {
    fun matches(pattern: String, value: String): Boolean {
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
