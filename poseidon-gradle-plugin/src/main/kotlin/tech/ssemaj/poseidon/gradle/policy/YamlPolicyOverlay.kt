package tech.ssemaj.poseidon.gradle.policy

import org.yaml.snakeyaml.Yaml
import java.io.File

/**
 * Loads a SnakeYAML policy overlay file and merges its fields into a [DeclaredPolicy].
 * Lists are unioned (distinct), mode is overridden if set, booleans are OR-ed in.
 */
object YamlPolicyOverlay {

    /**
     * Merges [overlayFile] into [base], also unioning YAML allowedHosts into [dslHosts]
     * (mutated in place so the caller's host list gains YAML entries).
     * @return updated [DeclaredPolicy] (same as [base] if the file is empty or unreadable)
     */
    fun merge(base: DeclaredPolicy, dslHosts: MutableList<String>, overlayFile: File): DeclaredPolicy {
        @Suppress("UNCHECKED_CAST")
        val yaml = Yaml().load<Map<String, Any?>>(overlayFile.readText()) ?: return base
        var result = base

        // YAML allowedHosts → union into dslHosts (passed by reference)
        (yaml["allowedHosts"] as? List<*>)?.filterIsInstance<String>()?.forEach { host ->
            if (host !in dslHosts) dslHosts.add(host)
        }
        // YAML deniedPaths → union into result
        val yamlDenied = (yaml["deniedPaths"] as? List<*>)?.filterIsInstance<String>() ?: emptyList()
        if (yamlDenied.isNotEmpty()) {
            result = result.copy(deniedPaths = (result.deniedPaths + yamlDenied).distinct())
        }
        // YAML mode (if present) → override
        (yaml["mode"] as? String)?.let { yamlMode -> result = result.copy(mode = yamlMode) }
        // YAML nativeDnsCorrelation → OR in
        if (yaml["nativeDnsCorrelation"] == true) result = result.copy(dnsCorrelation = true)
        // YAML allowedCidrs → union
        val yamlCidrs = (yaml["allowedCidrs"] as? List<*>)?.filterIsInstance<String>() ?: emptyList()
        if (yamlCidrs.isNotEmpty()) {
            result = result.copy(allowedCidrs = (result.allowedCidrs + yamlCidrs).distinct())
        }
        return result
    }
}
