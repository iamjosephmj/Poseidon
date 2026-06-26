package tech.ssemaj.poseidon

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * The compiled policy the app actually ships — read straight from the asset the Poseidon
 * Gradle plugin generates (`assets/poseidon/policy.json`). Drives the "what we're
 * filtering" panel so the demo shows exactly which hosts/paths/ranges are enforced.
 */
data class PolicyInfo(
    val mode: String,
    val allowedHosts: List<String>,
    val deniedPaths: List<String>,
    val allowedCidrs: List<String>,
    val dnsCorrelation: Boolean,
) {
    companion object {
        private const val ASSET_PATH = "poseidon/policy.json"

        fun load(context: Context): PolicyInfo = runCatching {
            val json = context.assets.open(ASSET_PATH).bufferedReader().use { it.readText() }
            with(JSONObject(json)) {
                PolicyInfo(
                    mode           = optString("mode", "monitor"),
                    allowedHosts   = optJSONArray("allowedHosts").toStringList(),
                    deniedPaths    = optJSONArray("deniedPaths").toStringList(),
                    allowedCidrs   = optJSONArray("allowedCidrs").toStringList(),
                    dnsCorrelation = optBoolean("dnsCorrelation", false),
                )
            }
        }.getOrDefault(PolicyInfo("unknown", emptyList(), emptyList(), emptyList(), false))

        private fun JSONArray?.toStringList(): List<String> =
            if (this == null) emptyList() else (0 until length()).map { getString(it) }
    }
}
