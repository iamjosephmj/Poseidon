package tech.ssemaj.poseidon.probes

/**
 * Canonical URL corpus shared by all demo probes.
 *
 * - [ALLOWED]      — allow-listed host + allow-listed path; expected to proceed (HTTP 404 from server).
 * - [DENIED_PATH]  — allow-listed host but DENIED path; Poseidon returns HTTP 403 before egress.
 * - [DENIED_HOST]  — host NOT in the allow-list; Poseidon returns HTTP 403 before egress.
 */
object DemoUrls {
    const val ALLOWED      = "https://aparture.thessemaj.tech/demo/path?x=1"
    const val DENIED_PATH  = "https://aparture.thessemaj.tech/blocked/secret"
    const val DENIED_HOST  = "https://www.google.com/"
}
