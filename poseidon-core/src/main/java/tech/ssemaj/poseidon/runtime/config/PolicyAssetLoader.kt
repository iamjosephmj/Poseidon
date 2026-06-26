package tech.ssemaj.poseidon.runtime.config

import tech.ssemaj.poseidon.runtime.model.Mode

import android.content.Context
import org.json.JSONObject

/**
 * Opens and parses poseidon/policy.json from the app assets.
 * Pure and testable — no side effects; returns a [PolicyConfig] value type.
 */
internal object PolicyAssetLoader {
    fun load(context: Context): PolicyConfig {
        val json = context.assets.open("poseidon/policy.json")
            .bufferedReader().use { it.readText() }
        return with(JSONObject(json)) {
            PolicyConfig(
                mode = if (optString("mode") == "enforce") Mode.ENFORCE else Mode.MONITOR,
                allowedHosts = stringList("allowedHosts"),
                deniedPaths = stringList("deniedPaths"),
                allowedCidrs = stringList("allowedCidrs"),
                dnsCorrelation = optBoolean("dnsCorrelation", false),
            )
        }
    }

    private fun JSONObject.stringList(key: String): List<String> =
        optJSONArray(key)?.let { arr -> (0 until arr.length()).map { arr.getString(it) } }
            ?: emptyList()
}
