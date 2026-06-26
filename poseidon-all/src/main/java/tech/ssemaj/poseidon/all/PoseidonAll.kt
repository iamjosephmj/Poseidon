package tech.ssemaj.poseidon.all

/**
 * Marker object for the poseidon-all umbrella artifact.
 *
 * Adding a single dependency on `:poseidon-all` (or the published `tech.ssemaj:poseidon-all`
 * AAR) pulls in all three Poseidon interception tiers transitively:
 *
 * | Tier | Module | What it covers |
 * |------|--------|----------------|
 * | **core** | `:poseidon-core` | Play-clean JVM policy pipeline, OkHttp interceptor, HttpURLConnection call-site rewrite, Volley gate, [NativeBridge][tech.ssemaj.poseidon.runtime.NativeBridge] SEAM (no .so) |
 * | **native** | `:poseidon-native` | libc shim ELF interposition via `libposeidon_shim.so`; covers Cronet native stack + any NDK HTTP client |
 * | **seccomp** | `:poseidon-seccomp` | In-process seccomp USER_NOTIF gate for Go / raw-syscall `connect()` and `sendto()` callers; DNS-correlation maps IPs back to hostnames; same .so as the native tier |
 *
 * **Recommended entry point** — add exactly one line to your app's `build.gradle.kts`:
 * ```kotlin
 * implementation("tech.ssemaj:poseidon-all:<version>")
 * ```
 * then configure the allow-list in your Poseidon Gradle DSL block and `res/xml/poseidon_policy.xml`.
 *
 * @see tech.ssemaj.poseidon.seccomp.PoseidonSeccomp — seccomp-tier marker with detailed activation notes
 */
object PoseidonAll
