<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0a2540,50:0077b6,100:00d4ff&height=210&section=header&text=POSEIDON&fontSize=80&fontColor=ffffff&fontAlignY=38&desc=%F0%9F%94%B1%20%20Network%20egress%20gate%20for%20your%20Android%20SDKs&descSize=20&descAlignY=60&animation=fadeIn" width="100%"/>

<a href="#-why">
  <img src="https://readme-typing-svg.demolab.com/?font=Fira+Code&weight=600&size=22&pause=900&color=00D4FF&center=true&vCenter=true&width=760&height=46&lines=Tell+your+app+which+servers+each+SDK+may+reach;Block+the+rest+%E2%80%94+or+just+watch;In-process.+No+VPN.+No+root.;Declared+in+your+manifest" alt="What Poseidon does"/>
</a>

<br/>

[![CI](https://img.shields.io/github/actions/workflow/status/iamjosephmj/Poseidon/poseidon-ci.yml?branch=master&style=for-the-badge&logo=githubactions&logoColor=white&label=CI&color=00d4ff)](https://github.com/iamjosephmj/Poseidon/actions/workflows/poseidon-ci.yml)
[![JitPack](https://img.shields.io/jitpack/version/com.github.iamjosephmj/Poseidon?style=for-the-badge&logo=jitpack&logoColor=white&label=JitPack&color=0077b6)](https://jitpack.io/#iamjosephmj/Poseidon)
[![License](https://img.shields.io/badge/License-MIT-0a2540?style=for-the-badge)](LICENSE)
[![Android](https://img.shields.io/badge/Android-24%2B-3DDC84?style=for-the-badge&logo=android&logoColor=white)](#)

### 🌊 [Why](#-why) • [What](#-what) • [How](#-how-to-use-it) • [Rules](#-the-rules-you-can-write) • [Demo](#-try-it) • [Deep dive](ARCH.md)

</div>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:0a2540,50:0077b6,100:00d4ff&height=3" width="100%"/>

## 🔱 Why

I've always wondered what a third-party SDK can quietly exfiltrate from inside an app.

You drop in an analytics, ads, or chat SDK — usually **closed-source**, sometimes with a
**native layer** nobody reads — and it runs with *your* app's `INTERNET` permission, in
*your* process, with *your* data. Android is all-or-nothing here: once an app can use the
internet, every library inside it can talk to **anywhere**, and there's no built-in way to
see — let alone restrict — where each one actually connects.

Poseidon fixes that. You declare the allowed servers **in your manifest**, and it enforces
and audits them — without a VPN, root, or any per-request code.

> Honest scope: this is a strong default-deny egress control + per-SDK audit for normal,
> non-adversarial SDKs. It is **not** a sandbox against deliberately malicious code, and it
> can't stop exfiltration *through* a server you've allowed. More in [ARCH.md](ARCH.md).

## 🌊 What

```
          your app                                    the world
   ┌──────────────────────┐
   │  your code           │── api.mybackend.com ─────────▶ ✅ allowed
   │  analytics SDK       │── example.com ───────────────▶ ✅ allowed
   │  ads SDK             │── evil-tracker.com ──╳         🚫 blocked
   │  native / Go SDK     │── 9.9.9.9 ───────────╳         🚫 blocked
   └──────────┬───────────┘
              └── Poseidon checks every connection against your manifest rules
```

- **One allow-list, every layer** — HTTP libraries (OkHttp, HttpURLConnection, Volley,
  Cronet), native C/C++ code, and even Go/raw-syscall traffic.
- **Two modes** — `monitor` (just watch and log where each SDK goes) or `enforce` (block
  anything off the list).
- **Per-SDK audit** — see exactly which library reached which host.

## 🚀 How to use it

### 1. Add Poseidon

```kotlin
// settings.gradle.kts → repositories
maven { url = uri("https://jitpack.io") }
```
```kotlin
// app/build.gradle.kts
plugins {
    id("com.android.application")
    id("tech.ssemaj.poseidon") version "0.1.1"
}
dependencies {
    implementation("com.github.iamjosephmj.Poseidon:poseidon-all:0.1.1")
}
```

### 2. Declare your rules — in the manifest

This is the whole idea: you write plain rules, Poseidon does the rest.

Create **`app/src/main/res/xml/poseidon_policy.xml`**:

```xml
<poseidon mode="enforce">                       <!-- enforce = block · monitor = just watch -->

    <allow host="example.com"/>                 <!-- ✅ may talk to example.com          -->
    <allow host="*.api.mybackend.com"/>         <!-- ✅ wildcard: any subdomain           -->

    <deny-path pattern="/internal/*"/>          <!-- 🚫 never allow these URL paths        -->

    <allow-cidr value="104.16.0.0/13"/>         <!-- ✅ allow an IP range (native/Go calls)-->

</poseidon>
```

Then point your **`AndroidManifest.xml`** at it (inside `<application>`):

```xml
<meta-data
    android:name="tech.ssemaj.poseidon.policy"
    android:resource="@xml/poseidon_policy" />
```

**That's it.** Add one `<allow host>` and everything else is denied by default. No code to
write — the HTTP clients and native libraries are wired up automatically at build time.

### 3. See what each SDK does

Every decision is logged (tag `Poseidon`) in **both** modes:

```
[ENFORCE/JVM]     example.com/home          -> ALLOW
[ENFORCE/JVM]     example.com/internal/x    -> BLOCK (denied path)
[ENFORCE/JVM]     evil-tracker.com/         -> BLOCK (host not allowed)
[ENFORCE/NATIVE]  example.com               -> ALLOW
[ENFORCE/SECCOMP] 9.9.9.9                   -> BLOCK
```

Want it in your own metrics/UI instead of Logcat? Add a sink:

```kotlin
Observer.addSink { e -> myMetrics.record(e.tier, e.host, e.decision?.block == true) }
```

## 📋 The rules you can write

| In your manifest XML | What it does |
|---|---|
| `<poseidon mode="enforce">` | **Block** anything off the list. |
| `<poseidon mode="monitor">` | **Watch only** — log where SDKs go, block nothing. |
| `<allow host="example.com">` | Permit a host. Supports `*.wildcards`. *Adding any `allow` flips everything else to denied.* |
| `<deny-path pattern="/internal/*">` | Block specific URL paths (HTTP libraries only — paths are hidden by TLS for native traffic). |
| `<allow-cidr value="104.16.0.0/13">` | Permit an IP range — for native/Go code that connects by raw IP. |

With `:poseidon-all`, native (C/C++) and Go/raw-syscall coverage is **on by default** —
nothing to configure. You can tune it if you want:

```kotlin
// app/build.gradle.kts (optional — these are the defaults)
poseidon {
    injectNative = true            // guard native-library (libc) traffic
    nativeDnsCorrelation = true    // map Go/raw connections back to hostnames
}
```

> Want a **Play-clean, JVM-only** build with no binary changes? Depend on
> `com.github.iamjosephmj.Poseidon:poseidon-core:0.1.1` instead of `poseidon-all`, or set
> `injectNative = false`.

## 🧪 Try it

A demo app (live egress dashboard + an editable URL you can fire through each client) is
attached to every release, or build it yourself:

```bash
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n tech.ssemaj.poseidon/.MainActivity
```

Validated end-to-end on a Pixel 6 Pro across all three layers. 📥 Grab the APK from the
[latest release](https://github.com/iamjosephmj/Poseidon/releases/latest).

## 🏛️ Want the how-it-works?

The mechanisms (build-time bytecode weaving, native ELF interposition, the seccomp gate,
DNS correlation, the lock-free audit pipeline) and diagrams live in **[ARCH.md](ARCH.md)**.
Contributing notes: **[CONTRIBUTING.md](CONTRIBUTING.md)**.

## 📜 License

[MIT](LICENSE) © [iamjosephmj](https://github.com/iamjosephmj)

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:00d4ff,50:0077b6,100:0a2540&height=120&section=footer" width="100%"/>

</div>
