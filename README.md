# Poseidon

**Constrain and observe what the third‑party SDKs in your Android app can reach on the network — across JVM, native, and Go/raw‑syscall code, in‑process, with no VPN and no root.**

---

## Why I built this

I've always wondered what a third‑party SDK can quietly exfiltrate from inside an app.

You drop in an analytics, ads, attribution, or chat SDK — usually **closed‑source**, and
sometimes open‑source but with a **native (C/C++) layer** that nobody actually reads — and
it runs with *your* app's `INTERNET` permission, in *your* process, with access to *your*
data. Android's permission model is all‑or‑nothing here: once an app holds `INTERNET`, every
library linked into it can talk to *anywhere*. There is no built‑in way to say "this SDK may
only reach these hosts," and no easy way to even *see* where each one is actually connecting.

That bothered me enough to turn it into a research project. The question I wanted to answer:

> Can you actually pin an integrated SDK's network egress to a declared allow‑list — and
> get a per‑SDK audit of what it really reaches — **in‑process**, covering not just JVM HTTP
> clients but native libc traffic and even Go/raw‑syscall code, without a VPN, without root,
> and without anything that gets you kicked off the Play Store?

Poseidon is what came out of that. It's a build‑time + runtime safeguard that I validated
end‑to‑end on a real device. It is **not** a hardened sandbox against a hostile SDK (nothing
in‑process can be — see [Honest limits](#what-it-does-not-do)); it's a strong default‑deny
egress control and a per‑SDK audit for the realistic, non‑adversarial case.

---

## What it is

Poseidon lets the **app author** declare, in the manifest, which hosts the app's SDKs may
reach. At build time it compiles that policy and weaves enforcement into the app; at runtime
it allows / blocks / audits every outbound connection across three layers:

| Layer | Covers | How |
|---|---|---|
| **JVM bytecode** | OkHttp (incl. Retrofit / Ktor‑OkHttp), HttpURLConnection (incl. Volley HurlStack / Ktor‑Android), Volley, Cronet (Java API) | ASM transform at build time — host **and** path (path is only visible above TLS) |
| **Native libc** *(opt‑in)* | Any native SDK that reaches the network through libc — Cronet, WebRTC, … | `libposeidon_shim.so` injected as the first `DT_NEEDED` of each `.so`; interposes `connect`/`sendto`/`getaddrinfo`… |
| **seccomp** *(opt‑in)* | Go runtimes and raw `syscall()` that bypass libc entirely | A `SECCOMP_RET_USER_NOTIF` filter on the app's **own** process traps connects below libc |

Two modes, selectable per build: **`monitor`** (log what *would* happen — produces the
per‑SDK egress map) and **`enforce`** (additionally block). Same pipeline.

Deep architecture, diagrams, and the underlying techniques live in **[ARCH.md](ARCH.md)**.

---

## Quick start

> Poseidon is a research codebase, not yet published to a public Maven repository. You
> consume it from source: the Gradle plugin builds standalone and is resolved from
> `mavenLocal`, and the runtime ships as the in‑repo modules.

### 1. Build the plugin

```bash
export JAVA_HOME=/path/to/jbr   # a JDK 17 (Android Studio's bundled JBR works)
./gradlew -p poseidon-gradle-plugin publishToMavenLocal
```

Make sure `mavenLocal()` is in your root `settings.gradle.kts` `pluginManagement.repositories`
(this repo already does).

### 2. Apply the plugin + add the runtime to your app

```kotlin
// app/build.gradle.kts
plugins {
    id("com.android.application")
    id("tech.ssemaj.poseidon") version "0.1.0"
}

dependencies {
    // Play-clean JVM-only core:        implementation(project(":poseidon-core"))
    // …or the full umbrella (adds native + seccomp tiers):
    implementation(project(":poseidon-all"))
}
```

`:poseidon-core` alone is **Play‑clean** (no binary modification). The native and seccomp
tiers are opt‑in (see step 4).

### 3. Declare your policy (app‑authoritative)

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

Point the manifest at it (`app/src/main/AndroidManifest.xml`, inside `<application>`):

```xml
<meta-data android:name="tech.ssemaj.poseidon.policy"
           android:resource="@xml/poseidon_policy"/>
```

> Host rules are an **allow‑list** (default‑deny once non‑empty). Path rules are a
> **deny‑list** (default‑allow), enforced only at the JVM tier (the only layer that sees the
> URL before TLS). Wildcards (`*.example.com`) are supported.

### 4. Enable the native / seccomp tiers (optional)

To gate native SDKs (e.g. Cronet) at the libc layer and Go/raw‑syscall code via seccomp:

```kotlin
// app/build.gradle.kts
poseidon {
    injectNative = true               // inject the shim DT_NEEDED into your native libs
    nativeDnsCorrelation = true       // correlate Go/raw DNS so it's gated by hostname
    // optional escape hatch (the manifest XML is canonical):
    // allowedHosts.add("…"); allowedCidrs.add("…")
}
```

`injectNative` defaults to **`false`**, so the core stays Play‑clean unless you opt in. The
seccomp gate ships inside `libposeidon_shim.so`, so depending on `:poseidon-native` (or
`:poseidon-all`) already includes it.

### 5. See the audit

Every decision is recorded in both modes. The default sink logs to Logcat (tag `Poseidon`):

```
[ENFORCE/JVM]     example.com/demo/path        -> ALLOW
[ENFORCE/JVM]     example.com/internal/secret  -> BLOCK (path in deny-list)
[ENFORCE/JVM]     evil.tracker.com/            -> BLOCK (host not in allow-list)
[ENFORCE/NATIVE]  example.com                  -> ALLOW
[ENFORCE/SECCOMP] 142.250.x.x                  -> BLOCK (native-block)
```

To pipe it somewhere else (metrics, a file, a UI), register your own observer — it composes
with the default and a misbehaving sink can never break enforcement:

```kotlin
Observer.addSink { event ->
    myMetrics.record(event.tier, event.host, event.decision?.block == true)
}
```

That's it — no per‑request app code; the adapters and shim are wired by the build.

---

## Library proposals (optional)

A library can *propose* the hosts it needs in **its own** manifest
(`<meta-data android:name="tech.ssemaj.poseidon.proposes" .../>`). The build records every
proposal **with package attribution but does not grant it** unless the app explicitly
approves (`<approve library="…"/>` or `poseidon { acceptProposals = true }`). A CI knob
(`proposalsAction = "error"`) fails the build on unapproved proposals. The compiled
`policy-report.txt` lists the effective allow‑list and every proposal — a reviewable audit
artifact.

---

## What it covers

- **Host allow / block** for any native or JVM code that reaches the network through libc
  (TCP/UDP/QUIC + DNS), plus Go/raw‑syscall code via seccomp.
- **Path deny‑list** for JVM HTTP clients (plaintext, above TLS).
- **Per‑SDK egress audit** — `monitor` mode produces a map of what each library actually
  reaches, attributed by originating `.so` / Java caller.

## What it does NOT do

I'd rather be honest than oversell this:

- **No payload inspection / no TLS MITM.** It controls *destinations*. It cannot stop
  exfiltration *through* an allow‑listed host.
- **Not a security boundary against a hostile, same‑privilege SDK.** Adversarial code in
  your process can tamper with in‑process state or race the filter install. Only the
  kernel/MDM/network can truly contain that.
- **Kernels < 5.0** have no seccomp `USER_NOTIF`, so Go/raw is ungated there (libc + DNS
  still enforce for libc code).
- **DoH/DoT** hides the hostname from correlation (the connect to the resolved IP is still
  gated); **ECH** will hide SNI.
- An **un‑correlated bare‑IP** raw/Go connect passes unless you declare `<allow-cidr>` ranges
  (then anything outside them is blocked); CIDR allow is host‑agnostic *within* a range.

Positioning: a **strong default‑deny egress control + per‑SDK audit for non‑adversarial
SDKs** — not a guarantee against a hostile SDK or exfil via permitted destinations.

---

## Status

Research project, validated end‑to‑end on a **Pixel 6 Pro (Android 16)** across all three
tiers — including real `org.chromium.net:cronet-embedded` (native host enforced + Java‑API
path observed) and a Go‑style raw‑syscall probe (gated by seccomp). The lock‑free audit ring
and the JVM↔native policy equivalence are exercised in CI.

## Try the demo

```bash
export JAVA_HOME=/path/to/jbr
./gradlew -p poseidon-gradle-plugin publishToMavenLocal
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n tech.ssemaj.poseidon/.MainActivity
adb logcat -s Poseidon PoseidonDemo     # watch allow/block across every tier
```

The demo app fires probes through OkHttp, HttpURLConnection, Volley, Cronet, and a raw
syscall path, against an allowed host, a denied path, and a denied host — so you can watch
each tier make its decision.

---

## Architecture

See **[ARCH.md](ARCH.md)** — module layout, use‑case and flow diagrams, the runtime
pipeline, the three enforcement tiers, the native shim internals, and the underlying
techniques (ELF `DT_NEEDED` interposition, ASM bytecode transform, seccomp `USER_NOTIF`,
in‑process DNS correlation, the opt‑in CIDR allow‑list, and the lock‑free event ring).
Design‑pattern notes are in [`docs/design-patterns.md`](docs/design-patterns.md).
