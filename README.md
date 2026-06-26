<div align="center">

# 🔱 Poseidon

**Constrain and observe what the third‑party SDKs in your Android app can reach on the network — across JVM, native, and Go/raw‑syscall code, in‑process, with no VPN and no root.**

[![CI](https://github.com/iamjosephmj/Poseidon/actions/workflows/poseidon-ci.yml/badge.svg)](https://github.com/iamjosephmj/Poseidon/actions/workflows/poseidon-ci.yml)
[![Release](https://jitpack.io/v/iamjosephmj/Poseidon.svg)](https://jitpack.io/#iamjosephmj/Poseidon)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Android-3DDC84.svg?logo=android&logoColor=white)](#)
[![minSdk](https://img.shields.io/badge/minSdk-24-blue.svg)](#)
[![Kotlin](https://img.shields.io/badge/Kotlin-7F52FF.svg?logo=kotlin&logoColor=white)](#)
[![C](https://img.shields.io/badge/native%20shim-C-A8B9CC.svg?logo=c&logoColor=white)](#)

[Why](#why-i-built-this) · [What it is](#what-it-is) · [Install](#install) · [Usage](#usage) · [Coverage](#what-it-covers) · [Limits](#what-it-does-not-do) · [Architecture](ARCH.md) · [Contributing](CONTRIBUTING.md)

</div>

---

## Why I built this

I've always wondered what a third‑party SDK can quietly exfiltrate from inside an app.

You drop in an analytics, ads, attribution, or chat SDK — usually **closed‑source**, and
sometimes open‑source but with a **native (C/C++) layer** that nobody actually reads — and
it runs with *your* app's `INTERNET` permission, in *your* process, with access to *your*
data. Android's permission model is all‑or‑nothing here: once an app holds `INTERNET`, every
library linked into it can talk to *anywhere*. There's no built‑in way to say "this SDK may
only reach these hosts," and no easy way to even *see* where each one is actually connecting.

That bothered me enough to turn it into a research project. The question I wanted to answer:

> Can you pin an integrated SDK's network egress to a declared allow‑list — and get a
> per‑SDK audit of what it really reaches — **in‑process**, covering not just JVM HTTP
> clients but native libc traffic and even Go/raw‑syscall code, with no VPN, no root, and
> nothing that gets you kicked off the Play Store?

Poseidon is what came out of that — a build‑time + runtime safeguard, validated end‑to‑end
on a real device. It is **not** a hardened sandbox against a hostile SDK (nothing in‑process
can be — see [limits](#what-it-does-not-do)); it's a strong default‑deny egress control and
a per‑SDK audit for the realistic, non‑adversarial case.

## What it is

You list the hosts your app's SDKs are allowed to reach. Poseidon enforces that list and
shows you where each SDK actually connects — covering ordinary HTTP libraries, native
(C/C++) SDKs, and even Go/raw‑syscall code, all inside your app, with no VPN and no root.

Run it in **monitor** mode to just watch and log where each SDK goes, or **enforce** mode to
block anything that isn't on your list.

Curious how it works under the hood? It's all in **[ARCH.md](ARCH.md)** — diagrams included.

## Install

### Runtime — via JitPack

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        google(); mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}
```
```kotlin
// app/build.gradle.kts
dependencies {
    implementation("com.github.iamjosephmj.Poseidon:poseidon-all:<version>")  // full umbrella
    // …or just the Play-clean JVM core:
    // implementation("com.github.iamjosephmj.Poseidon:poseidon-core:<version>")
}
```

See the [latest version on JitPack](https://jitpack.io/#iamjosephmj/Poseidon). `:poseidon-core`
alone is **Play‑clean** (no binary modification); native + seccomp are opt‑in (below).

### Build‑time plugin

The Gradle plugin (it weaves the bytecode adapters and injects the native shim) builds from
source and resolves via `mavenLocal`:

```bash
export JAVA_HOME=/path/to/jbr            # JDK 17 (Android Studio's bundled JBR works)
./gradlew -p poseidon-gradle-plugin publishToMavenLocal
```
```kotlin
// app/build.gradle.kts
plugins {
    id("com.android.application")
    id("tech.ssemaj.poseidon") version "0.1.0"   // resolved from mavenLocal
}
```

## Usage

### 1. Declare your policy (app‑authoritative)

`app/src/main/res/xml/poseidon_policy.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<poseidon mode="enforce">                 <!-- or "monitor" -->
    <allow host="example.com"/>
    <allow host="*.api.yourbackend.com"/>
    <deny-path pattern="/internal/*"/>    <!-- JVM tier only (above TLS) -->

    <!-- Opt-in: pin Go/raw + native traffic to IP ranges (closes the bare-IP residual).
         Include the CDN ranges of your allow-listed hosts, e.g. Cloudflare: -->
    <allow-cidr value="104.16.0.0/13"/>
    <allow-cidr value="172.64.0.0/13"/>
    <allow-cidr value="2606:4700::/32"/>
</poseidon>
```

Point the manifest at it (`AndroidManifest.xml`, inside `<application>`):

```xml
<meta-data android:name="tech.ssemaj.poseidon.policy"
           android:resource="@xml/poseidon_policy"/>
```

> Host rules are an **allow‑list** (default‑deny once non‑empty); path rules are a
> **deny‑list** (default‑allow), enforced only at the JVM tier. Wildcards (`*.example.com`)
> are supported.

### 2. Enable the native / seccomp tiers (optional)

```kotlin
// app/build.gradle.kts
poseidon {
    injectNative = true            // inject the shim DT_NEEDED into your native libs
    nativeDnsCorrelation = true    // correlate Go/raw DNS so it's gated by hostname
}
```

`injectNative` defaults to **`false`**, so the core stays Play‑clean unless you opt in. The
seccomp gate ships inside `libposeidon_shim.so`, so depending on the native tier includes it.

### 3. See the audit

Every decision is recorded in both modes; the default sink logs to Logcat (tag `Poseidon`):

```
[ENFORCE/JVM]     example.com/demo/path        -> ALLOW
[ENFORCE/JVM]     example.com/internal/secret  -> BLOCK (path in deny-list)
[ENFORCE/JVM]     evil.tracker.com/            -> BLOCK (host not in allow-list)
[ENFORCE/NATIVE]  example.com                  -> ALLOW
[ENFORCE/SECCOMP] 142.250.x.x                  -> BLOCK (native-block)
```

Pipe it anywhere (metrics, a file, your own UI) — it composes with the default, and a
misbehaving sink can never break enforcement:

```kotlin
Observer.addSink { event ->
    myMetrics.record(event.tier, event.host, event.decision?.block == true)
}
```

No per‑request app code — the adapters and shim are wired by the build.

> **Library proposals:** a library can *propose* the hosts it needs in its own manifest;
> the build records each proposal with package attribution but **does not grant it** unless
> the app approves (`<approve library="…"/>` / `acceptProposals = true`). A CI knob
> (`proposalsAction = "error"`) fails the build on unapproved proposals.

## What it covers

- **Host allow / block** for any native or JVM code that reaches the net through libc
  (TCP/UDP/QUIC + DNS), plus Go/raw‑syscall code via seccomp.
- **Path deny‑list** for JVM HTTP clients (plaintext, above TLS).
- **Per‑SDK egress audit** — `monitor` mode maps what each library actually reaches,
  attributed by originating `.so` / Java caller.

## What it does NOT do

I'd rather be honest than oversell this:

- **No payload inspection / no TLS MITM** — it controls *destinations*; it can't stop
  exfiltration *through* an allow‑listed host.
- **Not a security boundary against a hostile, same‑privilege SDK** — adversarial code in
  your process can tamper with state or race the filter install. Only kernel/MDM/network
  can truly contain that.
- **Kernels < 5.0** have no seccomp `USER_NOTIF`; Go/raw is ungated there (libc + DNS still
  enforce for libc code).
- **DoH/DoT** hides the hostname from correlation (the connect to the resolved IP is still
  gated); **ECH** will hide SNI.
- An **un‑correlated bare‑IP** raw/Go connect passes unless you declare `<allow-cidr>` ranges;
  CIDR allow is host‑agnostic *within* a range.

Positioning: a **strong default‑deny egress control + per‑SDK audit for non‑adversarial
SDKs** — not a guarantee against a hostile SDK or exfil via permitted destinations.

## Status & demo

Validated end‑to‑end on a **Pixel 6 Pro (Android 16)** across all three tiers — including
real `org.chromium.net:cronet-embedded` (native host enforced + Java‑API path observed) and
a Go‑style raw‑syscall probe (gated by seccomp). The lock‑free audit ring and the JVM↔native
glob equivalence are exercised in CI.

```bash
./gradlew -p poseidon-gradle-plugin publishToMavenLocal
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n tech.ssemaj.poseidon/.MainActivity   # live egress dashboard
adb logcat -s Poseidon PoseidonDemo                         # …and the same stream in Logcat
```

The demo app fires probes through OkHttp, HttpURLConnection, Volley, Cronet, and a raw
syscall path — against an allowed host, a denied path, and a denied host — and shows each
tier's decision live.

## Architecture

See **[ARCH.md](ARCH.md)** — module layout, use‑case and flow diagrams, the runtime
pipeline, the three enforcement tiers, the native shim internals, and the underlying
techniques (ELF `DT_NEEDED` interposition, ASM bytecode transform, seccomp `USER_NOTIF`,
in‑process DNS correlation, the opt‑in CIDR allow‑list, the lock‑free event ring).
Design‑pattern notes: [`docs/design-patterns.md`](docs/design-patterns.md).

## Contributing

Issues and PRs welcome. The codebase has a few **load‑bearing constraints** (the frozen
`tech.ssemaj.poseidon.runtime` package, the plugin's injected FQN literals, the JNI symbols,
the native hot‑path rule) that break *silently* if missed — all written up in
**[CONTRIBUTING.md](CONTRIBUTING.md)**, along with how to build, test, and verify on a device.

## License

[MIT](LICENSE) © iamjosephmj
