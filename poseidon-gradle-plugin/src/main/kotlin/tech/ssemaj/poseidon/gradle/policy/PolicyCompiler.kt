package tech.ssemaj.poseidon.gradle.policy

/** Merges app policy + DSL + (approved) proposals into the runtime policy.json + a build report. */
object PolicyCompiler {
    fun compile(
        app: DeclaredPolicy,
        proposals: List<Proposal>,
        dslHosts: List<String>,
        acceptProposals: Boolean,
    ): CompileResult {
        val granted = proposals.filter { acceptProposals || it.library in app.approvedLibraries }
        val unapproved = proposals.filter { it !in granted }
        val hosts = (app.allowedHosts + dslHosts + granted.map { it.host }).distinct()

        val json = buildString {
            append("{\"mode\":\"").append(app.mode).append("\",")
            append("\"dnsCorrelation\":").append(app.dnsCorrelation).append(",")
            append("\"allowedHosts\":[").append(hosts.joinToString(",") { jstr(it) }).append("],")
            append("\"deniedPaths\":[").append(app.deniedPaths.joinToString(",") { jstr(it) }).append("],")
            append("\"allowedCidrs\":[").append(app.allowedCidrs.joinToString(",") { jstr(it) }).append("]}")
        }
        val report = buildString {
            appendLine("Poseidon effective policy (mode=${app.mode})")
            appendLine("Allowed hosts:"); hosts.forEach { appendLine("  - $it") }
            appendLine("Denied paths:"); app.deniedPaths.forEach { appendLine("  - $it") }
            appendLine("Allowed CIDRs:"); app.allowedCidrs.forEach { appendLine("  - $it") }
            appendLine("Library proposals:")
            proposals.forEach {
                val status = if (it in granted) "GRANTED" else "NOT GRANTED (needs <approve> or acceptProposals)"
                appendLine("  - ${it.library} -> ${it.host}  [$status]")
            }
        }
        return CompileResult(json, report, unapproved)
    }

    private fun jstr(s: String) = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
}
