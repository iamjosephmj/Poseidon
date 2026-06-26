# poseidon-all

Umbrella artifact that aggregates all three Poseidon network-interception tiers into a single
dependency.

## What it includes

| Tier | Module | Coverage |
|------|--------|----------|
| **core** | `:poseidon-core` | JVM policy pipeline · OkHttp interceptor · HttpURLConnection call-site rewrite · Volley RequestQueue gate · NativeBridge SEAM (no native library) |
| **native** | `:poseidon-native` | `libposeidon_shim.so` ELF DT_NEEDED interposition · catches Cronet native stack · any NDK HTTP client |
| **seccomp** | `:poseidon-seccomp` | In-process seccomp USER_NOTIF supervisor · intercepts Go/raw-syscall `connect()` and `sendto()` · DNS-correlation maps resolved IPs back to hostnames for policy enforcement (same `.so` as the native tier) |

## Usage

Add one line to your app module's `build.gradle.kts`:

```kotlin
implementation("tech.ssemaj:poseidon-all:<version>")
```

Then configure the allow-list policy in your Poseidon Gradle DSL block and
`res/xml/poseidon_policy.xml`.  No further code changes are required — the plugin handles
bytecode instrumentation and native library injection at build time.

## Selecting individual tiers

If you only need a subset of tiers (e.g. JVM-only for a Play-clean build without native
libraries), depend on `:poseidon-core` or `:poseidon-native` directly instead of this umbrella.
