package tech.ssemaj.poseidon.runtime

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
        val o = JSONObject(json)
        return PolicyConfig(
            mode = if (o.optString("mode") == "enforce") Mode.ENFORCE else Mode.MONITOR,
            allowedHosts = o.strings("allowedHosts"),
            deniedPaths = o.strings("deniedPaths"),
            allowedCidrs = o.strings("allowedCidrs"),
            dnsCorrelation = o.optBoolean("dnsCorrelation", false),
        )
    }

    private fun JSONObject.strings(key: String): List<String> {
        val arr = optJSONArray(key) ?: return emptyList()
        return (0 until arr.length()).map { arr.getString(it) }
    }
}
