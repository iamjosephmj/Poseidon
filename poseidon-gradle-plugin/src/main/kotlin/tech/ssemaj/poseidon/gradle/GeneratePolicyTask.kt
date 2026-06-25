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

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun generate() {
        val hosts = allowedHosts.get().toMutableList()
        val paths = deniedPaths.get().toMutableList()
        var m = mode.get()
        var dns = dnsCorrelation.get()

        if (policyFile.isPresent && policyFile.get().asFile.exists()) {
            @Suppress("UNCHECKED_CAST")
            val y = Yaml().load<Map<String, Any?>>(policyFile.get().asFile.readText()) ?: emptyMap()
            (y["allowedHosts"] as? List<*>)?.forEach { hosts.add(it.toString()) }
            (y["deniedPaths"] as? List<*>)?.forEach { paths.add(it.toString()) }
            (y["mode"] as? String)?.let { m = it }
            (y["nativeDnsCorrelation"] as? Boolean)?.let { dns = it }
        }

        val json = buildString {
            append("{\"mode\":\"").append(m).append("\",")
            append("\"dnsCorrelation\":").append(dns).append(",")
            append("\"allowedHosts\":[").append(hosts.distinct().joinToString(",") { jstr(it) }).append("],")
            append("\"deniedPaths\":[").append(paths.distinct().joinToString(",") { jstr(it) }).append("]}")
        }
        val dir = File(outputDir.get().asFile, "poseidon").apply { mkdirs() }
        File(dir, "policy.json").writeText(json)
        logger.lifecycle("[poseidon] policy: mode=$m, ${hosts.size} allowed host(s), ${paths.size} denied path(s)")
    }

    private fun jstr(s: String) = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
}
