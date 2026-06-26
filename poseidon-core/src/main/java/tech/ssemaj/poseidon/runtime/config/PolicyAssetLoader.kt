package tech.ssemaj.poseidon.runtime.config

import tech.ssemaj.poseidon.runtime.model.Mode

import android.content.Context
import org.json.JSONObject

/**
 * Opens and parses poseidon/policy.json from the app assets.
 * Pure and testable — no side effects; returns a [PolicyConfig] value type.
 *
 * String values for the asset path and all JSON keys are defined here as named constants
 * because they form a contract with the Gradle plugin that writes the file:
 * renaming a constant must be paired with a plugin-side change.
 */
internal object PolicyAssetLoader {

    // ---- Asset location ----

    /** Path of the compiled policy file inside the app's assets directory.
     *  The Gradle plugin writes this file; must not change without a plugin update. */
    const val POLICY_ASSET_PATH = "poseidon/policy.json"

    // ---- JSON key names (must match values written by the Gradle plugin) ----

    /** Top-level key: enforcement mode ("enforce" or "monitor"). */
    const val KEY_MODE = "mode"

    /** Top-level key: ordered list of allowed host glob patterns. */
    const val KEY_ALLOWED_HOSTS = "allowedHosts"

    /** Top-level key: ordered list of denied URL path glob patterns. */
    const val KEY_DENIED_PATHS = "deniedPaths"

    /** Top-level key: optional CIDR ranges that complement the host allow-list. */
    const val KEY_ALLOWED_CIDRS = "allowedCidrs"

    /** Top-level key: boolean; enable in-process DNS correlation via seccomp supervisor. */
    const val KEY_DNS_CORRELATION = "dnsCorrelation"

    // ---- Mode value ----

    /** Value of [KEY_MODE] that activates blocking enforcement.
     *  Any other value (or absence) falls back to monitor mode. */
    const val MODE_ENFORCE = "enforce"

    // ---- Loader ----

    fun load(context: Context): PolicyConfig {
        val json = context.assets.open(POLICY_ASSET_PATH)
            .bufferedReader().use { it.readText() }
        return with(JSONObject(json)) {
            PolicyConfig(
                mode = if (optString(KEY_MODE) == MODE_ENFORCE) Mode.ENFORCE else Mode.MONITOR,
                allowedHosts = stringList(KEY_ALLOWED_HOSTS),
                deniedPaths = stringList(KEY_DENIED_PATHS),
                allowedCidrs = stringList(KEY_ALLOWED_CIDRS),
                dnsCorrelation = optBoolean(KEY_DNS_CORRELATION, false),
            )
        }
    }

    private fun JSONObject.stringList(key: String): List<String> =
        optJSONArray(key)?.let { arr -> (0 until arr.length()).map { arr.getString(it) } }
            ?: emptyList()
}
