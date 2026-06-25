# Poseidon Re-architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-found the proven Poseidon prototype on the clean, decoupled pipeline and manifest-first configuration described in `docs/superpowers/specs/2026-06-25-poseidon-rearchitecture-design.md`, without losing any on-device-validated behavior.

**Architecture:** A single source-agnostic `EgressEvent` flows from dumb interceptors into one `PolicyEngine` (the only decision-maker), then to one `Observer` (audit, both modes) and one `Enforcer` (block, enforce only). The runtime splits into `poseidon-core` (JVM, Play-clean, no binary mod), `poseidon-native` (libc shim), and `poseidon-seccomp` (Go/raw gate). Configuration moves from a Gradle DSL to an app-authoritative manifest XML resource compiled by the plugin, with library *proposals* recorded but not granted.

**Tech Stack:** Kotlin, AGP 9 (built-in Kotlin), JUnit4 + Robolectric (JVM unit), AndroidX Test + on-device instrumented tests (Pixel 6 Pro, serial `19011FDEE0040L`), C11 shim via CMake/NDK, ASM 9.7 bytecode transform, snakeyaml→XML manifest parsing.

## Global Constraints

- **JAVA_HOME must be exported for every Gradle/apksigner invocation:** `export JAVA_HOME=/snap/android-studio/230/jbr` (not on PATH by default).
- **Package root:** `tech.ssemaj.poseidon` (runtime classes under `tech.ssemaj.poseidon.runtime`; plugin under `tech.ssemaj.poseidon.gradle`). Plugin id: `tech.ssemaj.poseidon`.
- **AGP 9 provides built-in Kotlin** — never apply `org.jetbrains.kotlin.android` on an Android module (double-registers the `kotlin` extension). (`poseidon-modules` gotcha 1.)
- **The plugin builds standalone** and is consumed via `publishToMavenLocal` → `mavenLocal()` in root `pluginManagement`. Do NOT `includeBuild` it in `pluginManagement` (kotlin-dsl leaks Kotlin onto the shared classpath). (`poseidon-modules` gotcha 2.)
- **Native hot path is log-free / lock-free / allocation-free.** Never call `__android_log_print` (or anything taking a lock / doing I/O) synchronously inside `connect`/`sendto`/`getaddrinfo` or the seccomp supervisor's decision path. Observability goes through an async sink only. (`poseidon-spike-results`, mandatory.)
- **Reentrancy guard is mandatory** in the shim: thread-local `in_poseidon`; if already inside an interceptor, resolve the real symbol via `RTLD_NEXT` and pass straight through.
- **JNI native-method classes must be kept by R8** (`consumer-rules.pro`) so `Java_..._configure` symbols don't rename to silent native death.
- **Host rules = allow-list (default-deny once configured); path rules = deny-list (default-allow). Path enforcement is JVM-only** (only tier above TLS with the URL).
- **minSdk 24, compileSdk 37.** NDK auto-installed by AGP. ABIs: `arm64-v8a, armeabi-v7a, x86, x86_64`.
- **Each phase ends at a green on-device checkpoint.** Keep the existing `:poseidon-runtime` module untouched as a reference until the phase that retires it (Phase 6).

---

## Phase 0 — Test infrastructure (foundation for all TDD below)

### Task 0: Add JVM unit-test harness to a scratch module

The prototype `:poseidon-runtime` has no `src/test`. Phase 1 builds `poseidon-core` test-first, so we need a JVM unit-test toolchain that runs `PolicyEngine` (pure Kotlin) without a device. We validate the harness against the *existing* `PolicyEngine` before moving code.

**Files:**
- Create: `poseidon-runtime/src/test/java/tech/ssemaj/poseidon/runtime/PolicyEngineSmokeTest.kt`
- Modify: `poseidon-runtime/build.gradle.kts` (add `testImplementation` deps + `testOptions`)

**Interfaces:**
- Consumes: existing `PolicyEngine.configure(List<String>, List<String>)`, `evaluateHost(String, Int): Decision`, `evaluatePath(String, String): Decision`.
- Produces: a runnable `:poseidon-runtime:testDebugUnitTest` task (proves the JUnit toolchain).

- [ ] **Step 1: Add test deps to `poseidon-runtime/build.gradle.kts`** (append inside `dependencies { }`):

```kotlin
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.13")
    testImplementation("androidx.test:core:1.6.1")
```

And add inside the `android { }` block:

```kotlin
    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            isReturnDefaultValues = true
        }
    }
```

- [ ] **Step 2: Write a smoke test that fails before the toolchain works**

```kotlin
package tech.ssemaj.poseidon.runtime

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PolicyEngineSmokeTest {
    @Test fun allowListBlocksUnlistedHost() {
        PolicyEngine.configure(allowedHosts = listOf("example.com"), deniedPaths = emptyList())
        assertTrue(PolicyEngine.evaluateHost("evil.test", -1).block)
        assertFalse(PolicyEngine.evaluateHost("example.com", -1).block)
    }
}
```

- [ ] **Step 3: Run it**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-runtime:testDebugUnitTest --tests '*PolicyEngineSmokeTest'`
Expected: BUILD SUCCESSFUL, 1 test passed. (If the toolchain is misconfigured the task fails to resolve — fix deps until green.)

- [ ] **Step 4: Commit**

```bash
git add poseidon-runtime/build.gradle.kts poseidon-runtime/src/test
git commit -m "test: add JVM unit-test harness to poseidon-runtime"
```

> **Checkpoint 0:** `:poseidon-runtime:testDebugUnitTest` runs JUnit on the JVM. (If the repo is not a git repo yet, run `git init` first — the prototype dir currently is not under git.)

---

## Phase 1 — Core pipeline (EgressEvent → PolicyEngine → Observer / Enforcer)

This phase introduces the keystone types and the single decision-maker **inside the existing `:poseidon-runtime` module** (no module split yet — that is Phase 6). It replaces the per-adapter `PoseidonGate` policy sprawl with dumb producers. All work here is pure-JVM and unit-testable; on-device behavior must remain identical, verified at Checkpoint 1.

### Task 1.1: `EgressEvent` + `Decision` keystone types

**Files:**
- Create: `poseidon-runtime/src/main/java/tech/ssemaj/poseidon/runtime/EgressEvent.kt`
- Test: `poseidon-runtime/src/test/java/tech/ssemaj/poseidon/runtime/EgressEventTest.kt`

**Interfaces:**
- Produces: `Transport { TCP, UDP, DNS }`; `Tier { JVM, NATIVE, SECCOMP }`; `Action { ALLOW, BLOCK }`; `Decision(action, matchedRule, reason)`; `EgressEvent(ts, tid, host, ip, port, transport, path, tier, originToken, decision)`. These exact names are consumed by every later Phase-1 task.

- [ ] **Step 1: Write the failing test**

```kotlin
package tech.ssemaj.poseidon.runtime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class EgressEventTest {
    @Test fun defaultsAreRawAndUndecided() {
        val e = EgressEvent(ts = 1L, tid = 2, host = "example.com", ip = null, port = 443,
            transport = Transport.TCP, path = "/v1", tier = Tier.JVM, originToken = 0L)
        assertNull(e.decision)
        assertEquals("example.com", e.host)
        assertEquals(Transport.TCP, e.transport)
    }

    @Test fun decisionCarriesRuleAndReason() {
        val d = Decision(Action.BLOCK, matchedRule = "allow:example.com", reason = "host not in allow-list")
        assertEquals(Action.BLOCK, d.action)
        assertEquals("allow:example.com", d.matchedRule)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-runtime:testDebugUnitTest --tests '*EgressEventTest'`
Expected: FAIL — `Unresolved reference: EgressEvent`.

- [ ] **Step 3: Write `EgressEvent.kt`**

```kotlin
package tech.ssemaj.poseidon.runtime

enum class Transport { TCP, UDP, DNS }
enum class Tier { JVM, NATIVE, SECCOMP }
enum class Action { ALLOW, BLOCK }

/** Result of a policy lookup. matchedRule is the glob/rule that decided it (for audit). */
data class Decision(
    val action: Action,
    val matchedRule: String? = null,
    val reason: String = "",
) {
    val block: Boolean get() = action == Action.BLOCK
}

/**
 * Source-agnostic egress record. Interceptors fill everything except [decision];
 * PolicyEngine fills [decision]. The engine, sink, and enforcer never branch on [tier].
 * [originToken] is captured cheaply (native return-address or a JVM stack ref) and
 * symbolized OFF the hot path by the Observer drain.
 */
data class EgressEvent(
    val ts: Long,
    val tid: Int,
    val host: String?,
    val ip: String?,
    val port: Int,
    val transport: Transport,
    val path: String? = null,
    val tier: Tier = Tier.JVM,
    val originToken: Any? = null,
    var decision: Decision? = null,
)
```

- [ ] **Step 4: Run to verify it passes**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-runtime:testDebugUnitTest --tests '*EgressEventTest'`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add poseidon-runtime/src/main/java/tech/ssemaj/poseidon/runtime/EgressEvent.kt poseidon-runtime/src/test/java/tech/ssemaj/poseidon/runtime/EgressEventTest.kt
git commit -m "feat: add source-agnostic EgressEvent and Decision keystone types"
```

### Task 1.2: `PolicyEngine.evaluate(event)` — the single decision-maker

Collapse `evaluateHost` + `evaluatePath` into one `evaluate(EgressEvent): Decision` that applies host allow-list (default-deny) then path deny-list (JVM tier only), preserving the existing glob semantics exactly. Keep the old methods temporarily delegating to the new one so adapters compile until Task 1.5 migrates them.

**Files:**
- Modify: `poseidon-runtime/src/main/java/tech/ssemaj/poseidon/runtime/PolicyEngine.kt`
- Test: `poseidon-runtime/src/test/java/tech/ssemaj/poseidon/runtime/PolicyEngineEvaluateTest.kt`

**Interfaces:**
- Consumes: `EgressEvent`, `Decision`, `Action`, `Tier` (Task 1.1).
- Produces: `PolicyEngine.evaluate(event: EgressEvent): Decision`; retains `configure(List<String>, List<String>)`. `matchedRule` is `"allow:<glob>"` on allow, `"deny-path:<glob>"` on path block, `null`/`"default-deny"` otherwise.

- [ ] **Step 1: Write the failing test**

```kotlin
package tech.ssemaj.poseidon.runtime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class PolicyEngineEvaluateTest {
    private fun ev(host: String?, path: String? = null, tier: Tier = Tier.JVM) =
        EgressEvent(0L, 0, host, ip = null, port = 443, transport = Transport.TCP, path = path, tier = tier)

    @Before fun setup() = PolicyEngine.configure(listOf("example.com", "*.api.foo.com"), listOf("/internal/*"))

    @Test fun unlistedHostBlocked() = assertTrue(PolicyEngine.evaluate(ev("evil.test")).block)
    @Test fun allowedHostAllowed() = assertFalse(PolicyEngine.evaluate(ev("example.com")).block)
    @Test fun wildcardHostAllowed() = assertFalse(PolicyEngine.evaluate(ev("v2.api.foo.com")).block)

    @Test fun deniedPathBlockedOnAllowedHost() {
        val d = PolicyEngine.evaluate(ev("example.com", "/internal/secrets"))
        assertTrue(d.block); assertEquals("deny-path:/internal/*", d.matchedRule)
    }

    @Test fun pathIgnoredForNativeTier() =
        assertFalse(PolicyEngine.evaluate(ev("example.com", "/internal/secrets", Tier.NATIVE)).block)

    @Test fun emptyAllowListAllowsAll() {
        PolicyEngine.configure(emptyList(), emptyList())
        assertFalse(PolicyEngine.evaluate(ev("anything.test")).block)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-runtime:testDebugUnitTest --tests '*PolicyEngineEvaluateTest'`
Expected: FAIL — `Unresolved reference: evaluate`.

- [ ] **Step 3: Add `evaluate` to `PolicyEngine.kt`** (insert after `configure`, keep `glob` private helper and existing `evaluateHost`/`evaluatePath` for now):

```kotlin
    /** The single decision point. Host allow-list first, then path deny-list (JVM tier only). */
    @JvmStatic
    fun evaluate(event: EgressEvent): Decision {
        val host = event.host
        if (allowedHosts.isNotEmpty()) {
            val matched = host?.let { h -> allowedHosts.firstOrNull { glob(it, h) } }
            if (matched == null) {
                return Decision(Action.BLOCK, matchedRule = "default-deny", reason = "host not in allow-list")
            }
        }
        if (event.tier == Tier.JVM) {
            val path = event.path
            if (path != null) {
                val deny = deniedPaths.firstOrNull { glob(it, path) }
                if (deny != null) {
                    return Decision(Action.BLOCK, matchedRule = "deny-path:$deny", reason = "path in deny-list")
                }
            }
        }
        val allowRule = host?.let { h -> allowedHosts.firstOrNull { glob(it, h) } }?.let { "allow:$it" }
        return Decision(Action.ALLOW, matchedRule = allowRule, reason = "")
    }
```

- [ ] **Step 4: Run to verify it passes**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-runtime:testDebugUnitTest --tests '*PolicyEngineEvaluateTest'`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add poseidon-runtime/src/main/java/tech/ssemaj/poseidon/runtime/PolicyEngine.kt poseidon-runtime/src/test/java/tech/ssemaj/poseidon/runtime/PolicyEngineEvaluateTest.kt
git commit -m "feat: add PolicyEngine.evaluate(EgressEvent) single decision point"
```

### Task 1.3: `Enforcer` — apply a BLOCK per transport, knows nothing about why

**Files:**
- Create: `poseidon-runtime/src/main/java/tech/ssemaj/poseidon/runtime/Enforcer.kt`
- Test: `poseidon-runtime/src/test/java/tech/ssemaj/poseidon/runtime/EnforcerTest.kt`

**Interfaces:**
- Consumes: `Decision`, `Mode` (existing).
- Produces: `Enforcer.shouldBlock(decision: Decision): Boolean` — true iff `Mode.current == ENFORCE && decision.block`. (The transport-specific *action* — 403, IOException, cancel — stays in each adapter; the Enforcer owns only the gate predicate.)

- [ ] **Step 1: Write the failing test**

```kotlin
package tech.ssemaj.poseidon.runtime

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EnforcerTest {
    @Test fun monitorNeverBlocks() {
        Mode.current = Mode.MONITOR
        assertFalse(Enforcer.shouldBlock(Decision(Action.BLOCK, reason = "x")))
    }
    @Test fun enforceBlocksOnBlockDecision() {
        Mode.current = Mode.ENFORCE
        assertTrue(Enforcer.shouldBlock(Decision(Action.BLOCK, reason = "x")))
        assertFalse(Enforcer.shouldBlock(Decision(Action.ALLOW)))
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-runtime:testDebugUnitTest --tests '*EnforcerTest'`
Expected: FAIL — `Unresolved reference: Enforcer`.

- [ ] **Step 3: Write `Enforcer.kt`**

```kotlin
package tech.ssemaj.poseidon.runtime

/** The only unit that decides whether a BLOCK decision becomes an actual block. */
object Enforcer {
    @JvmStatic
    fun shouldBlock(decision: Decision): Boolean =
        Mode.current == Mode.ENFORCE && decision.block
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-runtime:testDebugUnitTest --tests '*EnforcerTest'`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add poseidon-runtime/src/main/java/tech/ssemaj/poseidon/runtime/Enforcer.kt poseidon-runtime/src/test/java/tech/ssemaj/poseidon/runtime/EnforcerTest.kt
git commit -m "feat: add Enforcer gate predicate (enforce-mode-only block)"
```

### Task 1.4: `Observer.record(event)` — async audit on the EgressEvent, both modes

Replace the `record(host, path, decision, mode)` signature with `record(event: EgressEvent)`. Keep the default logging sink but make it consume the unified event, and add a swappable callback so apps can subscribe (spec §7). Symbolization of `originToken` is deferred to Phase 5; here we just log host/path/tier/decision.

**Files:**
- Modify: `poseidon-runtime/src/main/java/tech/ssemaj/poseidon/runtime/Observer.kt`
- Test: `poseidon-runtime/src/test/java/tech/ssemaj/poseidon/runtime/ObserverTest.kt`

**Interfaces:**
- Consumes: `EgressEvent` (with `decision` already filled).
- Produces: `Observer.record(event: EgressEvent)`; `Observer.setSink(sink: (EgressEvent) -> Unit)`; `Observer.resetSink()`. Records in BOTH modes (audit is mode-independent).

- [ ] **Step 1: Write the failing test**

```kotlin
package tech.ssemaj.poseidon.runtime

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList

class ObserverTest {
    @After fun tearDown() = Observer.resetSink()

    @Test fun recordsInBothModes() {
        val seen = CopyOnWriteArrayList<EgressEvent>()
        Observer.setSink { seen.add(it) }
        val allow = EgressEvent(0L, 0, "example.com", null, 443, Transport.TCP, "/", Tier.JVM,
            decision = Decision(Action.ALLOW))
        val block = allow.copy(host = "evil.test", decision = Decision(Action.BLOCK, reason = "x"))
        Mode.current = Mode.MONITOR; Observer.record(allow)
        Mode.current = Mode.ENFORCE; Observer.record(block)
        assertEquals(2, seen.size)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-runtime:testDebugUnitTest --tests '*ObserverTest'`
Expected: FAIL — `setSink`/`record(EgressEvent)` unresolved.

- [ ] **Step 3: Rewrite `Observer.kt`**

```kotlin
package tech.ssemaj.poseidon.runtime

import android.util.Log

/**
 * The only audit output. Records every decision in BOTH modes (monitor = enforce minus
 * the block). Default sink logs off the JVM path; apps can swap a callback. The NATIVE
 * shim must NOT log on its hot path — native events arrive here via the async ring
 * (Phase 5), already off-thread.
 */
object Observer {
    @Volatile private var sink: (EgressEvent) -> Unit = ::logSink

    @JvmStatic fun record(event: EgressEvent) = sink(event)

    @JvmStatic fun setSink(sink: (EgressEvent) -> Unit) { this.sink = sink }
    @JvmStatic fun resetSink() { this.sink = ::logSink }

    private fun logSink(e: EgressEvent) {
        val d = e.decision
        val verdict = if (d?.block == true) "BLOCK (${d.reason})" else "ALLOW"
        Log.i("Poseidon", "[${Mode.current}/${e.tier}] ${e.host ?: e.ip}${e.path ?: ""} -> $verdict")
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-runtime:testDebugUnitTest --tests '*ObserverTest'`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add poseidon-runtime/src/main/java/tech/ssemaj/poseidon/runtime/Observer.kt poseidon-runtime/src/test/java/tech/ssemaj/poseidon/runtime/ObserverTest.kt
git commit -m "feat: Observer records unified EgressEvent in both modes, swappable sink"
```

### Task 1.5: Re-home `PoseidonGate` onto the pipeline; make adapters dumb producers

`PoseidonGate.shouldBlock(host, path)` becomes a thin builder that constructs a JVM-tier `EgressEvent`, calls `PolicyEngine.evaluate`, records via `Observer`, seeds the native IP cache on allow (unchanged behavior), and returns `Enforcer.shouldBlock`. The four adapters (`PoseidonInterceptor`, `PoseidonHttpUrl`, `PoseidonVolley`, `PoseidonCronet`) keep calling `PoseidonGate.shouldBlock` — so their transport-specific block actions are untouched, but the decision/record/enforce logic now lives in the pipeline, not in the gate.

**Files:**
- Modify: `poseidon-runtime/src/main/java/tech/ssemaj/poseidon/runtime/PoseidonGate.kt`
- Test: `poseidon-runtime/src/test/java/tech/ssemaj/poseidon/runtime/PoseidonGateTest.kt`

**Interfaces:**
- Consumes: `PolicyEngine.evaluate`, `Observer.record`, `Enforcer.shouldBlock`, `EgressEvent`, `Transport`, `Tier`.
- Produces: unchanged public surface `PoseidonGate.shouldBlock(host: String, path: String): Boolean` (so the four adapters and their injected bytecode are unaffected).

- [ ] **Step 1: Write the failing test** (asserts the gate now drives the pipeline end to end)

```kotlin
package tech.ssemaj.poseidon.runtime

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList

class PoseidonGateTest {
    private val seen = CopyOnWriteArrayList<EgressEvent>()

    @Before fun setup() {
        PolicyEngine.configure(listOf("example.com"), listOf("/blocked/*"))
        Observer.setSink { seen.add(it) }
        seen.clear()
    }

    @Test fun enforceBlocksUnlistedHostAndRecords() {
        Mode.current = Mode.ENFORCE
        assertTrue(PoseidonGate.shouldBlock("evil.test", "/"))
        assertTrue(seen.single().decision!!.block)
    }

    @Test fun monitorRecordsButNeverBlocks() {
        Mode.current = Mode.MONITOR
        assertFalse(PoseidonGate.shouldBlock("evil.test", "/"))
        assertTrue(seen.single().decision!!.block) // recorded as would-block
    }

    @Test fun allowedHostPathDenyBlocksInEnforce() {
        Mode.current = Mode.ENFORCE
        assertTrue(PoseidonGate.shouldBlock("example.com", "/blocked/x"))
        assertFalse(PoseidonGate.shouldBlock("example.com", "/ok"))
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-runtime:testDebugUnitTest --tests '*PoseidonGateTest'`
Expected: FAIL — current `PoseidonGate` calls `Observer.record(host, path, decision, mode)` which no longer exists; module won't compile. (Robolectric is needed because `InetAddress.getAllByName` runs; the seed is wrapped in try/catch so it is harmless in tests.)

- [ ] **Step 3: Rewrite `PoseidonGate.kt`**

```kotlin
package tech.ssemaj.poseidon.runtime

/**
 * Thin JVM-tier producer: builds an EgressEvent, runs it through the one PolicyEngine,
 * records via the one Observer, and returns the Enforcer's gate. The seccomp IP-cache
 * seed for allowed hosts (so the connect gate recognizes platform-resolved IPs) stays
 * here — it is a JVM-tier side effect, not a policy decision.
 */
object PoseidonGate {
    private val seeded = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    @JvmStatic
    fun shouldBlock(host: String, path: String): Boolean {
        val event = EgressEvent(
            ts = System.currentTimeMillis(),
            tid = android.os.Process.myTid(),
            host = host, ip = null, port = -1,
            transport = Transport.TCP, path = path, tier = Tier.JVM,
        )
        val decision = PolicyEngine.evaluate(event)
        event.decision = decision
        Observer.record(event)
        val block = Enforcer.shouldBlock(decision)
        if (!block && host.isNotEmpty() && seeded.add(host)) {
            try {
                val ips = java.net.InetAddress.getAllByName(host).mapNotNull { it.hostAddress }
                if (ips.isNotEmpty()) NativeBridge.cacheHostIps(host, ips.toTypedArray())
            } catch (_: Throwable) {
            }
        }
        return block
    }
}
```

- [ ] **Step 4: Delete the now-dead `evaluateHost`/`evaluatePath`** from `PolicyEngine.kt` and the old `record` overload usages. Confirm nothing references them:

Run: `grep -rn "evaluateHost\|evaluatePath" poseidon-runtime/src/main`
Expected: no matches. (If any remain, migrate them to `evaluate`.) Then remove the two methods from `PolicyEngine.kt`.

- [ ] **Step 5: Run the full module unit-test suite**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-runtime:testDebugUnitTest`
Expected: PASS (all Phase-1 tests).

- [ ] **Step 6: Commit**

```bash
git add poseidon-runtime/src/main poseidon-runtime/src/test
git commit -m "refactor: route all JVM adapters through EgressEvent/PolicyEngine/Observer/Enforcer pipeline"
```

### Task 1.6 — Checkpoint 1: on-device parity

No new code — verify the refactor preserves the proven on-device behavior (`poseidon-modules`: OkHttp 403, HUC IOException, Volley cancel, native block).

- [ ] **Step 1: Build + install on the Pixel 6 Pro**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-runtime:publishToMavenLocal :app:assembleDebug && adb -s 19011FDEE0040L install -r app/build/outputs/apk/debug/app-debug.apk`
Expected: BUILD SUCCESSFUL; APK installs.

- [ ] **Step 2: Exercise the app and capture logs**

Run: `adb -s 19011FDEE0040L logcat -c && adb -s 19011FDEE0040L shell am start -n tech.ssemaj.poseidon/.MainActivity && sleep 5 && adb -s 19011FDEE0040L logcat -d -s Poseidon`
Expected: `[ENFORCE/JVM] example.com... -> ALLOW` for the allowed host and `-> BLOCK` for a denied host/path — matching the prototype's pre-refactor log lines. Record the output in the commit message.

- [ ] **Step 3: Commit the verification note**

```bash
git commit --allow-empty -m "test: Checkpoint 1 — on-device JVM parity after pipeline refactor (Pixel 6 Pro)"
```

> **Checkpoint 1 (review gate):** JVM enforcement is now fully routed through the decoupled pipeline with the same on-device behavior. STOP for review before Phase 2.

---

## Phase 2 — Manifest-first configuration (plugin compile + app surface)

Move the authoritative policy from the Gradle DSL to an app XML resource the plugin compiles, with library *proposals* recorded but not granted (spec §7). The compiled output stays `assets/poseidon/policy.json` so `PoseidonInitializer` (Phase 1 untouched) keeps loading it. The DSL remains as the escape hatch.

### Task 2.1: Define the manifest policy resource format + parser (plugin-side, pure JVM)

**Files:**
- Create: `poseidon-gradle-plugin/src/main/kotlin/tech/ssemaj/poseidon/gradle/PolicyXml.kt`
- Test: `poseidon-gradle-plugin/src/test/kotlin/tech/ssemaj/poseidon/gradle/PolicyXmlTest.kt`
- Modify: `poseidon-gradle-plugin/build.gradle.kts` (add `testImplementation("junit:junit:4.13.2")` if absent)

**Interfaces:**
- Produces: `data class CompiledPolicy(mode, allowedHosts, deniedPaths, dnsCorrelation, proposals)`; `data class Proposal(library: String, host: String)`; `PolicyXml.parseAppPolicy(xml: String): CompiledPolicy`; `PolicyXml.parseProposals(library: String, xml: String): List<Proposal>`. The `<poseidon>` schema is exactly the spec §7 XML (`mode` attr; `<allow host=…/>`, `<deny-path pattern=…/>`, optional `<approve library=…/>`).

- [ ] **Step 1: Write the failing test**

```kotlin
package tech.ssemaj.poseidon.gradle

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PolicyXmlTest {
    private val app = """
        <poseidon mode="enforce">
          <allow host="example.com"/>
          <allow host="*.api.foo.com"/>
          <deny-path pattern="/internal/*"/>
          <approve library="com.foo.sdk"/>
        </poseidon>
    """.trimIndent()

    @Test fun parsesAppPolicy() {
        val p = PolicyXml.parseAppPolicy(app)
        assertEquals("enforce", p.mode)
        assertTrue(p.allowedHosts.containsAll(listOf("example.com", "*.api.foo.com")))
        assertEquals(listOf("/internal/*"), p.deniedPaths)
        assertEquals(setOf("com.foo.sdk"), p.approvedLibraries)
    }

    @Test fun parsesLibraryProposals() {
        val lib = """<poseidon><allow host="telemetry.sdk.com"/></poseidon>"""
        val props = PolicyXml.parseProposals("com.foo.sdk", lib)
        assertEquals(listOf(Proposal("com.foo.sdk", "telemetry.sdk.com")), props)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew -p poseidon-gradle-plugin test --tests '*PolicyXmlTest'`
Expected: FAIL — `Unresolved reference: PolicyXml`.

- [ ] **Step 3: Write `PolicyXml.kt`** (use `javax.xml.parsers.DocumentBuilderFactory`, already on the JDK):

```kotlin
package tech.ssemaj.poseidon.gradle

import org.w3c.dom.Element
import java.io.ByteArrayInputStream
import javax.xml.parsers.DocumentBuilderFactory

data class Proposal(val library: String, val host: String)

data class CompiledPolicy(
    val mode: String,
    val allowedHosts: List<String>,
    val deniedPaths: List<String>,
    val dnsCorrelation: Boolean,
    val approvedLibraries: Set<String>,
)

/** Parses the spec §7 <poseidon> XML for the app (authoritative) and libraries (proposals). */
object PolicyXml {
    private fun parse(xml: String): Element {
        val doc = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = false }
            .newDocumentBuilder().parse(ByteArrayInputStream(xml.toByteArray()))
        return doc.documentElement
    }

    private fun Element.childElements(tag: String): List<Element> {
        val nodes = getElementsByTagName(tag)
        return (0 until nodes.length).map { nodes.item(it) as Element }
    }

    fun parseAppPolicy(xml: String): CompiledPolicy {
        val root = parse(xml)
        return CompiledPolicy(
            mode = root.getAttribute("mode").ifEmpty { "monitor" },
            allowedHosts = root.childElements("allow").map { it.getAttribute("host") },
            deniedPaths = root.childElements("deny-path").map { it.getAttribute("pattern") },
            dnsCorrelation = root.getAttribute("nativeDnsCorrelation") == "true",
            approvedLibraries = root.childElements("approve").map { it.getAttribute("library") }.toSet(),
        )
    }

    fun parseProposals(library: String, xml: String): List<Proposal> =
        parse(xml).childElements("allow").map { Proposal(library, it.getAttribute("host")) }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew -p poseidon-gradle-plugin test --tests '*PolicyXmlTest'`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add poseidon-gradle-plugin/src/main/kotlin/tech/ssemaj/poseidon/gradle/PolicyXml.kt poseidon-gradle-plugin/src/test poseidon-gradle-plugin/build.gradle.kts
git commit -m "feat(plugin): parse app-authoritative + library-proposal poseidon XML"
```

### Task 2.2: Compile merged policy + emit build report, with the warn/error CI knob

**Files:**
- Create: `poseidon-gradle-plugin/src/main/kotlin/tech/ssemaj/poseidon/gradle/PolicyCompiler.kt`
- Test: `poseidon-gradle-plugin/src/test/kotlin/tech/ssemaj/poseidon/gradle/PolicyCompilerTest.kt`

**Interfaces:**
- Consumes: `CompiledPolicy`, `Proposal`, the existing DSL `PoseidonExtension` (override/augment), the existing JSON shape written by `GeneratePolicyTask` (`{mode, dnsCorrelation, allowedHosts, deniedPaths}`).
- Produces: `PolicyCompiler.compile(app: CompiledPolicy, proposals: List<Proposal>, dslHosts: List<String>, acceptProposals: Boolean): CompileResult` where `CompileResult(policyJson: String, report: String, unapprovedProposals: List<Proposal>)`. Effective allow-list = app hosts ∪ DSL hosts ∪ (approved-or-accepted proposal hosts). The report lists the effective allow-list and EVERY proposal with its library + granted/not-granted status.

- [ ] **Step 1: Write the failing test**

```kotlin
package tech.ssemaj.poseidon.gradle

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PolicyCompilerTest {
    private val app = CompiledPolicy("enforce", listOf("example.com"), listOf("/internal/*"), false, setOf("com.ok.sdk"))

    @Test fun approvedProposalGrantedUnapprovedRecordedOnly() {
        val proposals = listOf(Proposal("com.ok.sdk", "ok.host.com"), Proposal("com.bad.sdk", "bad.host.com"))
        val r = PolicyCompiler.compile(app, proposals, dslHosts = emptyList(), acceptProposals = false)
        assertTrue(r.policyJson.contains("ok.host.com"))      // approved → granted
        assertFalse(r.policyJson.contains("bad.host.com"))    // unapproved → NOT granted
        assertEquals(listOf(Proposal("com.bad.sdk", "bad.host.com")), r.unapprovedProposals)
        assertTrue(r.report.contains("com.bad.sdk"))          // but still reported
    }

    @Test fun acceptProposalsGrantsAll() {
        val proposals = listOf(Proposal("com.bad.sdk", "bad.host.com"))
        val r = PolicyCompiler.compile(app, proposals, emptyList(), acceptProposals = true)
        assertTrue(r.policyJson.contains("bad.host.com"))
        assertTrue(r.unapprovedProposals.isEmpty())
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew -p poseidon-gradle-plugin test --tests '*PolicyCompilerTest'`
Expected: FAIL — `Unresolved reference: PolicyCompiler`.

- [ ] **Step 3: Write `PolicyCompiler.kt`**

```kotlin
package tech.ssemaj.poseidon.gradle

data class CompileResult(
    val policyJson: String,
    val report: String,
    val unapprovedProposals: List<Proposal>,
)

/** Merges app policy + DSL + (approved) proposals into the runtime policy.json + a build report. */
object PolicyCompiler {
    fun compile(
        app: CompiledPolicy,
        proposals: List<Proposal>,
        dslHosts: List<String>,
        acceptProposals: Boolean,
    ): CompileResult {
        val granted = proposals.filter { acceptProposals || it.library in app.approvedLibraries }
        val unapproved = proposals.filter { it !in granted }
        val hosts = (app.allowedHosts + dslHosts + granted.map { it.host }).distinct()

        val json = buildString {
            append("{\"mode\":\"").append(app.mode).append("\",")
            append("\"dnsCorrelation\":").append(app.dnsCorrelation).append(",")
            append("\"allowedHosts\":[").append(hosts.joinToString(",") { jstr(it) }).append("],")
            append("\"deniedPaths\":[").append(app.deniedPaths.joinToString(",") { jstr(it) }).append("]}")
        }
        val report = buildString {
            appendLine("Poseidon effective policy (mode=${app.mode})")
            appendLine("Allowed hosts:"); hosts.forEach { appendLine("  - $it") }
            appendLine("Denied paths:"); app.deniedPaths.forEach { appendLine("  - $it") }
            appendLine("Library proposals:")
            proposals.forEach {
                val status = if (it in granted) "GRANTED" else "NOT GRANTED (needs <approve> or acceptProposals)"
                appendLine("  - ${it.library} -> ${it.host}  [$status]")
            }
        }
        return CompileResult(json, report, unapproved)
    }

    private fun jstr(s: String) = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew -p poseidon-gradle-plugin test --tests '*PolicyCompilerTest'`
Expected: PASS (2 tests). (Add `import org.junit.Assert.assertEquals` — fix the import if the compiler flags it.)

- [ ] **Step 5: Commit**

```bash
git add poseidon-gradle-plugin/src/main/kotlin/tech/ssemaj/poseidon/gradle/PolicyCompiler.kt poseidon-gradle-plugin/src/test
git commit -m "feat(plugin): compile merged policy with proposal approval gating + build report"
```

### Task 2.3: Wire the compiler into `GeneratePolicyTask` + the `proposalsAction` knob; read the app XML resource

**Files:**
- Modify: `poseidon-gradle-plugin/src/main/kotlin/tech/ssemaj/poseidon/gradle/GeneratePolicyTask.kt`
- Modify: `poseidon-gradle-plugin/src/main/kotlin/tech/ssemaj/poseidon/gradle/PoseidonExtension.kt`
- Modify: `poseidon-gradle-plugin/src/main/kotlin/tech/ssemaj/poseidon/gradle/PoseidonPlugin.kt`
- Create (app fixture): `app/src/main/res/xml/poseidon_policy.xml`
- Modify: `app/src/main/AndroidManifest.xml` (add the `<meta-data>` pointer), `app/build.gradle.kts` (slim the `poseidon { }` block to escape-hatch use)

**Interfaces:**
- Consumes: `PolicyXml.parseAppPolicy`, `PolicyCompiler.compile`.
- Produces: `GeneratePolicyTask` gains `@get:InputFile @Optional val appPolicyXml` and `@get:Input val proposalsAction` (`"warn"`|`"error"`); writes `poseidon/policy.json` (assets) and `poseidon/policy-report.txt` (build report). `PoseidonExtension` gains `var policyXml: String? = null` (default `"src/main/res/xml/poseidon_policy.xml"`) and `var proposalsAction: String = "warn"` and `var acceptProposals: Boolean = false`.

- [ ] **Step 1: Add the new DSL fields to `PoseidonExtension.kt`**

```kotlin
    /** App-authoritative manifest policy XML (relative to the module). Canonical source. */
    var policyXml: String? = "src/main/res/xml/poseidon_policy.xml"

    /** Grant every library proposal without explicit <approve> (default: only approved are granted). */
    var acceptProposals: Boolean = false

    /** Unapproved proposals: "warn" (default) logs them; "error" fails the build (CI gate). */
    var proposalsAction: String = "warn"
```

- [ ] **Step 2: Rewrite `GeneratePolicyTask.generate()`** to parse the app XML (if present) and call the compiler; keep the existing DSL/YAML fields as augmentation. Replace the `@TaskAction` body:

```kotlin
    @get:InputFile @get:Optional @get:PathSensitive(PathSensitivity.NONE)
    abstract val appPolicyXml: RegularFileProperty

    @get:Input abstract val proposalsAction: Property<String>
    @get:Input abstract val acceptProposals: Property<Boolean>

    @TaskAction
    fun generate() {
        // DSL/YAML escape hatch (unchanged path) provides augmenting hosts + fallback mode.
        val dslHosts = allowedHosts.get().toList()
        val app = if (appPolicyXml.isPresent && appPolicyXml.get().asFile.exists()) {
            PolicyXml.parseAppPolicy(appPolicyXml.get().asFile.readText())
        } else {
            CompiledPolicy(mode.get(), emptyList(), deniedPaths.get().toList(), dnsCorrelation.get(), emptySet())
        }
        // Library proposals are merged into the manifest by AGP; for now read none here
        // (Task 2.4 wires the merged-manifest proposal extraction). Empty list = app-only.
        val result = PolicyCompiler.compile(app, proposals = emptyList(), dslHosts = dslHosts,
            acceptProposals = acceptProposals.get())

        val dir = File(outputDir.get().asFile, "poseidon").apply { mkdirs() }
        File(dir, "policy.json").writeText(result.policyJson)
        File(dir, "policy-report.txt").writeText(result.report)
        logger.lifecycle("[poseidon] ${result.report.lines().first()}")
        if (result.unapprovedProposals.isNotEmpty()) {
            val msg = "[poseidon] ${result.unapprovedProposals.size} unapproved library proposal(s)"
            if (proposalsAction.get() == "error") error(msg) else logger.warn(msg)
        }
    }
```

- [ ] **Step 3: Wire the new properties in `PoseidonPlugin.apply`** (inside `genTask.configure { }` add):

```kotlin
                proposalsAction.set(ext.proposalsAction)
                acceptProposals.set(ext.acceptProposals)
                ext.policyXml?.let { appPolicyXml.set(project.layout.projectDirectory.file(it)) }
```

- [ ] **Step 4: Create the app fixture `app/src/main/res/xml/poseidon_policy.xml`**

```xml
<?xml version="1.0" encoding="utf-8"?>
<poseidon mode="enforce">
    <allow host="example.com"/>
    <deny-path pattern="/blocked/*"/>
</poseidon>
```

And add to `app/src/main/AndroidManifest.xml` inside `<application>`:

```xml
        <meta-data android:name="tech.ssemaj.poseidon.policy"
            android:resource="@xml/poseidon_policy"/>
```

- [ ] **Step 5: Build the app and confirm the compiled asset matches the XML**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-gradle-plugin:publishToMavenLocal :app:assembleDebug && unzip -p app/build/outputs/apk/debug/app-debug.apk assets/poseidon/policy.json`
Expected: `{"mode":"enforce",...,"allowedHosts":["example.com"],"deniedPaths":["/blocked/*"]}` — derived from the XML, not the DSL. Confirm `app/build/.../poseidon/policy-report.txt` exists and lists the effective allow-list.

- [ ] **Step 6: Commit**

```bash
git add poseidon-gradle-plugin/src/main app/src/main/res/xml/poseidon_policy.xml app/src/main/AndroidManifest.xml app/build.gradle.kts
git commit -m "feat(plugin): manifest-first policy compile from app XML + build report + CI knob"
```

### Task 2.4: Extract library proposals from the merged manifest

**Files:**
- Modify: `poseidon-gradle-plugin/src/main/kotlin/tech/ssemaj/poseidon/gradle/GeneratePolicyTask.kt` (consume merged-manifest proposals)
- Modify: `poseidon-gradle-plugin/src/main/kotlin/tech/ssemaj/poseidon/gradle/PoseidonPlugin.kt` (wire the merged-manifest artifact)
- Test: `poseidon-gradle-plugin/src/test/kotlin/tech/ssemaj/poseidon/gradle/ProposalExtractionTest.kt`

**Interfaces:**
- Consumes: AGP `SingleArtifact.MERGED_MANIFEST` (public artifact) → the merged `AndroidManifest.xml`; `PolicyXml.parseProposals`.
- Produces: `GeneratePolicyTask` gains `@get:InputFile @Optional val mergedManifest`; a helper `extractProposals(manifestXml: String): List<Proposal>` that reads every `<meta-data android:name="tech.ssemaj.poseidon.proposes" android:resource="…"/>` — for this milestone, libraries embed proposals inline via `<meta-data ... android:value="host1,host2"/>` keyed by the contributing package. (Resource-ref resolution across AARs is deferred; inline value keeps the milestone self-contained and testable.)

- [ ] **Step 1: Write the failing test**

```kotlin
package tech.ssemaj.poseidon.gradle

import org.junit.Assert.assertEquals
import org.junit.Test

class ProposalExtractionTest {
    @Test fun extractsInlineProposalsFromMergedManifest() {
        val manifest = """
            <manifest package="com.app">
              <application>
                <meta-data android:name="tech.ssemaj.poseidon.proposes"
                           android:value="telemetry.sdk.com,crash.sdk.com"
                           tools:node="com.foo.sdk"/>
              </application>
            </manifest>
        """.trimIndent()
        val props = GeneratePolicyTask.extractProposals(manifest)
        assertEquals(2, props.size)
        assertEquals("telemetry.sdk.com", props[0].host)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew -p poseidon-gradle-plugin test --tests '*ProposalExtractionTest'`
Expected: FAIL — `extractProposals` unresolved.

- [ ] **Step 3: Add the companion helper to `GeneratePolicyTask.kt`**

```kotlin
    companion object {
        /** Reads inline poseidon proposal meta-data from a merged manifest. */
        fun extractProposals(manifestXml: String): List<Proposal> {
            val doc = javax.xml.parsers.DocumentBuilderFactory.newInstance()
                .newDocumentBuilder()
                .parse(java.io.ByteArrayInputStream(manifestXml.toByteArray()))
            val nodes = doc.getElementsByTagName("meta-data")
            val out = mutableListOf<Proposal>()
            for (i in 0 until nodes.length) {
                val el = nodes.item(i) as org.w3c.dom.Element
                if (el.getAttribute("android:name") != "tech.ssemaj.poseidon.proposes") continue
                val lib = el.getAttribute("tools:node").ifEmpty { "unknown" }
                el.getAttribute("android:value").split(",").map { it.trim() }.filter { it.isNotEmpty() }
                    .forEach { out.add(Proposal(lib, it)) }
            }
            return out
        }
    }
```

Then in `generate()` replace `proposals = emptyList()` with:

```kotlin
        val proposals = if (mergedManifest.isPresent && mergedManifest.get().asFile.exists())
            extractProposals(mergedManifest.get().asFile.readText()) else emptyList()
```

and declare the input:

```kotlin
    @get:InputFile @get:Optional @get:PathSensitive(PathSensitivity.NONE)
    abstract val mergedManifest: RegularFileProperty
```

- [ ] **Step 4: Wire the merged manifest in `PoseidonPlugin.apply`** (inside `onVariants`, before `genTask.configure`):

```kotlin
            val mergedManifestProvider = variant.artifacts.get(com.android.build.api.artifact.SingleArtifact.MERGED_MANIFEST)
```

and inside `genTask.configure { }`:

```kotlin
                mergedManifest.set(mergedManifestProvider)
```

- [ ] **Step 5: Run the unit test + app build**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew -p poseidon-gradle-plugin test --tests '*ProposalExtractionTest' && ./gradlew :poseidon-gradle-plugin:publishToMavenLocal :app:assembleDebug`
Expected: unit test PASS; app build SUCCESSFUL; `policy-report.txt` now has a "Library proposals" section (empty for the demo app, present and correct).

- [ ] **Step 6: Commit**

```bash
git add poseidon-gradle-plugin/src/main poseidon-gradle-plugin/src/test
git commit -m "feat(plugin): extract library proposals from merged manifest, gate by approval"
```

> **Checkpoint 2 (review gate):** Policy now compiles from the app manifest XML + library proposals with approval gating, emits a human-readable build report, and still produces the same `policy.json` the runtime loads. STOP for review before Phase 3.

---

## Phase 3 — Native ↔ JVM policy mirror equivalence (shared test vectors)

Spec §5 invariant 4: the JVM and native evaluators must be proven equivalent by a shared glob test-vector suite run against both in CI. The native evaluator already exists in `shim.c` (`fnmatch`-based glob). This phase pins equivalence so future edits can't drift.

### Task 3.1: Shared glob test-vector fixture (single source of truth)

**Files:**
- Create: `poseidon-runtime/src/main/cpp/test/glob_vectors.txt` (canonical pattern|value|expect rows)
- Test: `poseidon-runtime/src/test/java/tech/ssemaj/poseidon/runtime/GlobVectorEquivalenceTest.kt`

**Interfaces:**
- Produces: a checked-in vector file consumed by both the JVM test (this task) and the native test (Task 3.2). Row format: `pattern|value|1` (match) or `…|0` (no match). Vectors must cover: exact, `*` prefix/suffix/middle, dot-literal, multi-label wildcard `*.api.foo.com`, empty path `/`.

- [ ] **Step 1: Write the failing test** (drives both the fixture and a JVM `glob` accessor)

```kotlin
package tech.ssemaj.poseidon.runtime

import org.junit.Assert.assertEquals
import org.junit.Test

class GlobVectorEquivalenceTest {
    @Test fun jvmGlobMatchesVectors() {
        val vectors = javaClass.classLoader!!.getResourceAsStream("glob_vectors.txt")!!
            .bufferedReader().readLines().filter { it.isNotBlank() && !it.startsWith("#") }
        for (line in vectors) {
            val (pattern, value, expect) = line.split("|")
            val configured = PolicyEngine.matches(pattern, value)
            assertEquals("pattern=$pattern value=$value", expect == "1", configured)
        }
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-runtime:testDebugUnitTest --tests '*GlobVectorEquivalenceTest'`
Expected: FAIL — resource missing AND `PolicyEngine.matches` is private/unresolved.

- [ ] **Step 3: Expose `matches` on `PolicyEngine`** (rename the private `glob` to an internal-visible testable form):

```kotlin
    /** Visible for the equivalence suite; mirrors the native fnmatch semantics. */
    @JvmStatic
    fun matches(pattern: String, value: String): Boolean = glob(pattern, value)
```

- [ ] **Step 4: Create `glob_vectors.txt`** and place it on the unit-test resource path. Create `poseidon-runtime/src/test/resources/glob_vectors.txt`:

```
# pattern|value|expect
example.com|example.com|1
example.com|evil.test|0
*.api.foo.com|v2.api.foo.com|1
*.api.foo.com|api.foo.com|0
*.example.com|a.b.example.com|1
/internal/*|/internal/secrets|1
/internal/*|/public|0
/|/|1
*|anything|1
```

(Also copy it to `src/main/cpp/test/glob_vectors.txt` so the native test in Task 3.2 reads the identical file; keep them byte-identical — a follow-up can symlink.)

- [ ] **Step 5: Run to verify it passes**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-runtime:testDebugUnitTest --tests '*GlobVectorEquivalenceTest'`
Expected: PASS. (If any row fails, the JVM regex glob and the intended fnmatch semantics differ — reconcile the vector or the glob, do not skip.)

- [ ] **Step 6: Commit**

```bash
git add poseidon-runtime/src/main/java/tech/ssemaj/poseidon/runtime/PolicyEngine.kt poseidon-runtime/src/test/resources/glob_vectors.txt poseidon-runtime/src/main/cpp/test/glob_vectors.txt poseidon-runtime/src/test/java/tech/ssemaj/poseidon/runtime/GlobVectorEquivalenceTest.kt
git commit -m "test: shared glob vectors, JVM evaluator pinned"
```

### Task 3.2: Native evaluator runs the same vectors (host CMake test)

**Files:**
- Create: `poseidon-runtime/src/main/cpp/test/glob_test.c` (compiles `poseidon_host_match` from shim against the vectors on the host)
- Create: `poseidon-runtime/src/main/cpp/test/CMakeLists.txt` (host-target test, not Android)
- Modify: `poseidon-runtime/src/main/cpp/shim.c` (extract the glob into a tiny header so the host test links it without pulling Android-only deps)

**Interfaces:**
- Consumes: the glob/fnmatch routine currently inside `shim.c`'s `poseidon_check`.
- Produces: a host executable `glob_test` returning non-zero on any vector mismatch; runnable as `cmake -S … && cmake --build … && ./glob_test glob_vectors.txt`.

- [ ] **Step 1: Extract the matcher** from `shim.c` into `poseidon-runtime/src/main/cpp/host_match.h` (move the fnmatch-based host-glob into a standalone `static int poseidon_host_match(const char* pattern, const char* value)`), and `#include "host_match.h"` from `shim.c`, replacing the inline matching with a call. (No behavior change — verified by the existing on-device tests at Checkpoint 4.)

- [ ] **Step 2: Write `glob_test.c`**

```c
#include <stdio.h>
#include <string.h>
#include "../host_match.h"

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "r");
    if (!f) { perror("open vectors"); return 2; }
    char line[512]; int failures = 0;
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char* nl = strchr(line, '\n'); if (nl) *nl = 0;
        char* pat = strtok(line, "|");
        char* val = strtok(NULL, "|");
        char* exp = strtok(NULL, "|");
        if (!pat || !val || !exp) continue;
        int got = poseidon_host_match(pat, val) ? 1 : 0;
        if (got != (exp[0] - '0')) { printf("MISMATCH %s|%s exp=%s got=%d\n", pat, val, exp, got); failures++; }
    }
    fclose(f);
    printf(failures ? "FAIL %d\n" : "OK\n", failures);
    return failures ? 1 : 0;
}
```

- [ ] **Step 3: Write `test/CMakeLists.txt`**

```cmake
cmake_minimum_required(VERSION 3.18)
project(poseidon_glob_test C)
add_executable(glob_test glob_test.c)
```

- [ ] **Step 4: Build + run on the host** (uses system clang/gcc, not the NDK — pure POSIX `fnmatch`):

Run: `cd poseidon-runtime/src/main/cpp/test && cmake -S . -B build && cmake --build build && ./build/glob_test glob_vectors.txt`
Expected: `OK`. (If `MISMATCH` lines appear, the native glob diverges from the JVM glob — fix `host_match.h` until both evaluators agree on every vector.)

- [ ] **Step 5: Commit**

```bash
git add poseidon-runtime/src/main/cpp/host_match.h poseidon-runtime/src/main/cpp/shim.c poseidon-runtime/src/main/cpp/test
git commit -m "test: native evaluator passes the shared glob vectors (host CMake test)"
```

> **Checkpoint 3:** JVM and native glob evaluators are proven equivalent against one checked-in vector set. Wire both test commands into CI (Phase 7).

---

## Phase 4 — Module split (`poseidon-core` / `poseidon-native` / `poseidon-seccomp`)

Split the single `:poseidon-runtime` into the tiered modules of spec §2, moving already-working code behind clean boundaries. `poseidon-core` is pure-JVM and Play-clean (no native). `poseidon-native` ships the libc-interposition shim. `poseidon-seccomp` ships the Go/raw gate. The app depends on `poseidon-all` (umbrella) or picks tiers.

### Task 4.1: Create `poseidon-core` (JVM only) and move the pipeline into it

**Files:**
- Create: `poseidon-core/build.gradle.kts`, `poseidon-core/src/main/AndroidManifest.xml`, `poseidon-core/consumer-rules.pro`
- Move (git mv): all Phase-1 JVM classes + adapters from `poseidon-runtime/src/main/java/...` into `poseidon-core/src/main/java/...`: `EgressEvent.kt`, `PolicyEngine.kt`, `Decision`(in EgressEvent), `Enforcer.kt`, `Observer.kt`, `Mode.kt`, `PoseidonGate.kt`, `PoseidonInterceptor.kt`, `PoseidonOkHttp.kt`, `PoseidonHttpUrl.kt`, `PoseidonVolley.kt`, `PoseidonCronet.kt`, `PoseidonInitializer.kt`
- Move: `poseidon-runtime/src/test/...` → `poseidon-core/src/test/...`
- Create: `poseidon-core/src/main/java/tech/ssemaj/poseidon/runtime/NativeBridge.kt` as a **no-op stub interface** (core must not depend on native): `cacheHostIps`/`apply`/`installSeccompGate` become no-ops overridable by the native module.
- Modify: `settings.gradle.kts` (`include(":poseidon-core")`)

**Interfaces:**
- Consumes: nothing new.
- Produces: module `:poseidon-core` with namespace `tech.ssemaj.poseidon.runtime`, no `externalNativeBuild`, no NDK. `NativeBridge` in core exposes the same method names but they delegate to an optional `NativeBridge.Backend` registered by `poseidon-native` (default backend = no-op). This keeps `PoseidonGate`'s seed call and `PoseidonInitializer`'s native push compiling without a hard native dependency.

- [ ] **Step 1: Create `poseidon-core/build.gradle.kts`** (copy `poseidon-runtime`'s, delete the `ndk { }` + `externalNativeBuild { }` blocks and the CMake; keep the `compileOnly` client deps + `androidx.startup` + the Phase-0 test deps).

- [ ] **Step 2: Define the `NativeBridge` seam in core** — replace the hard JNI bridge with a backend interface:

```kotlin
package tech.ssemaj.poseidon.runtime

/** Core-side seam. poseidon-native registers a real backend; default is no-op (Play-clean core). */
object NativeBridge {
    interface Backend {
        fun apply(allowedHosts: List<String>, enforce: Boolean)
        fun cacheHostIps(host: String, ips: Array<String>)
        fun installSeccompGate(dnsCorrelation: Boolean)
    }
    @Volatile private var backend: Backend? = null
    @JvmStatic fun register(b: Backend) { backend = b }
    fun apply(allowedHosts: List<String>, enforce: Boolean) { backend?.apply(allowedHosts, enforce) }
    fun cacheHostIps(host: String, ips: Array<String>) { backend?.cacheHostIps(host, ips) }
    fun installSeccompGate(dnsCorrelation: Boolean) { backend?.installSeccompGate(dnsCorrelation) }
}
```

- [ ] **Step 3: `git mv` the JVM sources + tests** into `poseidon-core`, update `settings.gradle.kts` to `include(":poseidon-core")`, and move the androidx.startup `<provider>` manifest entry into `poseidon-core/src/main/AndroidManifest.xml` (so core auto-inits standalone).

- [ ] **Step 4: Build core + run its unit tests in isolation**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-core:testDebugUnitTest :poseidon-core:assembleDebug`
Expected: BUILD SUCCESSFUL; all Phase-1/3 JVM tests pass under the new module. (Core has no native code — verify with `find poseidon-core -name '*.so' -o -name CMakeLists.txt` → empty.)

- [ ] **Step 5: Commit**

```bash
git add poseidon-core settings.gradle.kts && git rm -r --cached poseidon-runtime/src/main/java poseidon-runtime/src/test 2>/dev/null
git commit -m "refactor: extract Play-clean poseidon-core (JVM pipeline) with no-op native seam"
```

### Task 4.2: Create `poseidon-native` — the libc shim + real `NativeBridge.Backend`

**Files:**
- Create: `poseidon-native/build.gradle.kts` (the `ndk { }` + CMake config from old `poseidon-runtime`)
- Move: `poseidon-runtime/src/main/cpp/{shim.c,poseidon.ver,CMakeLists.txt,host_match.h,test/}` → `poseidon-native/src/main/cpp/`
- Create: `poseidon-native/src/main/java/tech/ssemaj/poseidon/runtime/NativeShimBackend.kt` (the JNI methods from the old `NativeBridge` + `NativeBridge.register(this)` on load)
- Create: `poseidon-native/src/main/AndroidManifest.xml` (startup initializer that calls `NativeBridge.register`)
- Modify: `settings.gradle.kts` (`include(":poseidon-native")`), `poseidon-native/consumer-rules.pro` (keep the JNI class — `NativeShimBackend` native methods must not rename)

**Interfaces:**
- Consumes: `NativeBridge.Backend` (core).
- Produces: `NativeShimBackend : NativeBridge.Backend` exposing the JNI externals (`configure`, `cacheHost`, `installSeccomp`, plus the test helpers `rawConnect`/`rawResolve`/`rawSendto`/`seccompProbe`). It registers itself as the core backend in an androidx.startup initializer (dependency-ordered BEFORE `PoseidonInitializer` so the push lands).

- [ ] **Step 1: Move the cpp tree + create `poseidon-native/build.gradle.kts`** (depends on `:poseidon-core`; restore the `ndk { abiFilters … }`, `externalNativeBuild { cmake { … } }`, `consumerProguardFiles`).

- [ ] **Step 2: Port the JNI surface** from the old `NativeBridge.kt` into `NativeShimBackend.kt`, implementing `NativeBridge.Backend` and keeping the `external fun` declarations + `System.loadLibrary("poseidon_shim")`. Add an initializer that calls `NativeBridge.register(NativeShimBackend)`. Keep the JNI symbol names identical (`Java_..._NativeShimBackend_configure`) — update `shim.c`'s `JNIEXPORT` function names + `poseidon.ver` exports to match the new class name.

- [ ] **Step 3: Build the native module**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-native:assembleDebug`
Expected: BUILD SUCCESSFUL; `find poseidon-native -name 'libposeidon_shim.so'` lists all four ABIs.

- [ ] **Step 4: Commit**

```bash
git add poseidon-native settings.gradle.kts && git rm -r --cached poseidon-runtime/src/main/cpp 2>/dev/null
git commit -m "refactor: extract poseidon-native (libc shim + JNI backend) depending on core"
```

### Task 4.3: Create `poseidon-seccomp` and `poseidon-all` umbrella

**Files:**
- Create: `poseidon-seccomp/build.gradle.kts` + the seccomp supervisor source. (The seccomp code currently lives inside `shim.c`; split the `installSeccomp`/supervisor/DNS-correlation functions into `poseidon-native/src/main/cpp/seccomp.c` compiled into the same `libposeidon_shim.so`, and gate the `poseidon-seccomp` *module* as a thin Kotlin facade that calls `NativeBridge.installSeccompGate`. Rationale: one `.so` already carries both; the module split is about the dependency/opt-in surface, not separate binaries — record this in the module README.)
- Create: `poseidon-all/build.gradle.kts` (`api(project(":poseidon-core")); api(project(":poseidon-native")); api(project(":poseidon-seccomp"))`)
- Modify: `settings.gradle.kts`

**Interfaces:**
- Produces: `:poseidon-seccomp` (facade enabling the Go gate via the policy flag), `:poseidon-all` (umbrella). An app gets the JVM-only story with `:poseidon-core`, adds native host coverage with `:poseidon-native`, adds Go coverage with `:poseidon-seccomp`, or takes everything with `:poseidon-all`.

- [ ] **Step 1: Create both modules' build files** and wire `include(":poseidon-seccomp", ":poseidon-all")`. `poseidon-seccomp` depends on `:poseidon-native` (shares the `.so`); `poseidon-all` aggregates.

- [ ] **Step 2: Build the umbrella**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-all:assembleDebug`
Expected: BUILD SUCCESSFUL; transitively builds core+native+seccomp.

- [ ] **Step 3: Point the app at `poseidon-all`** — in `app/build.gradle.kts` replace `implementation(project(":poseidon-runtime"))` with `implementation(project(":poseidon-all"))`.

- [ ] **Step 4: Commit**

```bash
git add poseidon-seccomp poseidon-all settings.gradle.kts app/build.gradle.kts
git commit -m "refactor: add poseidon-seccomp facade + poseidon-all umbrella; app uses umbrella"
```

### Task 4.4 — Checkpoint 4: full on-device parity on the split modules

- [ ] **Step 1: Clean build + install**

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew clean :poseidon-gradle-plugin:publishToMavenLocal :app:assembleDebug && adb -s 19011FDEE0040L install -r app/build/outputs/apk/debug/app-debug.apk`
Expected: BUILD SUCCESSFUL; injected `libcronet` present (`unzip -l app/build/outputs/apk/debug/app-debug.apk | grep libcronet`).

- [ ] **Step 2: Verify all four enforcement behaviors** (the `poseidon-modules`/`poseidon-go-coverage` acceptance set): allowed host SUCCESS, denied host BLOCK (Cronet `ERR_CONNECTION_REFUSED`), denied path 403/IOException, raw-syscall connect seen/blocked by seccomp.

Run: `adb -s 19011FDEE0040L logcat -c && adb -s 19011FDEE0040L shell am start -n tech.ssemaj.poseidon/.MainActivity && sleep 8 && adb -s 19011FDEE0040L logcat -d -s Poseidon`
Expected: log lines proving allow (example.com), native host block (google), seccomp `[seccomp]`/`[seccomp/observe]`. Paste into the commit.

- [ ] **Step 3: Commit**

```bash
git commit --allow-empty -m "test: Checkpoint 4 — full on-device parity on split core/native/seccomp modules (Pixel 6 Pro)"
```

> **Checkpoint 4 (review gate):** the tiered module architecture matches spec §2 and reproduces every proven on-device behavior. STOP for review before Phase 5.

---

## Phase 5 — Async audit ring (native → JVM Observer) + originToken symbolization

Close the last spec gap: the native hot path is still synchronous-liblog (`poseidon-spike-results` flagged it; spec §6 requires a lock-free ring). Native interceptors push compact events into a native ring; a JVM drain thread reads, symbolizes `originToken` (dladdr → `.so` name) off-thread, and feeds the one `Observer`. This is the only phase introducing genuinely new native code; build it test-first at the C level with the host harness, then verify on-device.

### Task 5.1: Lock-free native event ring + drain JNI

**Files:**
- Create: `poseidon-native/src/main/cpp/event_ring.c`, `event_ring.h`
- Create: `poseidon-native/src/main/cpp/test/ring_test.c`, add target to `test/CMakeLists.txt`
- Modify: `shim.c`/`seccomp.c` (replace synchronous `__android_log_print` on the hot path with `ring_push`)
- Modify: `NativeShimBackend.kt` (add `external fun drainEvents(): Array<String>` + a drain thread feeding `Observer.record`)

**Interfaces:**
- Produces (C): `void ring_push(uint64_t ts, const char* host_or_ip, int port, int transport, int tier, int blocked, uint64_t origin_addr);` and `int ring_drain(struct ring_event* out, int max);` — single-producer-safe per thread via atomic head/tail, fixed-size SPSC-per-slot ring, drop-on-full (counted). No locks, no allocation in `ring_push`.
- Produces (Kotlin): a daemon thread in `NativeShimBackend` polling `drainEvents()` every ~250ms, building an `EgressEvent(tier=NATIVE, originToken=<addr>)`, symbolizing via `dladdr`-backed `external fun symbolize(addr: Long): String?`, and calling `Observer.record`.

- [ ] **Step 1: Write the failing host ring test** `ring_test.c`: push N events from 2 threads, drain, assert count == pushed (minus counted drops), FIFO-ish per producer. Run via CMake host target; expected FAIL (no `event_ring.c` yet).

Run: `cd poseidon-native/src/main/cpp/test && cmake -S . -B build && cmake --build build && ./build/ring_test`
Expected: FAIL to link (`ring_push` undefined).

- [ ] **Step 2: Implement `event_ring.{c,h}`** — fixed array of `RING_CAP` slots, `atomic_uint head/tail`, `ring_push` CAS-free per-producer reservation with a seq-lock-free drop-on-full path; `ring_drain` copies out up to `max` and advances tail. Hot path: no `malloc`, no `log`, no mutex.

- [ ] **Step 3: Run the host ring test to green**

Run: `cd poseidon-native/src/main/cpp/test && cmake --build build && ./build/ring_test`
Expected: `OK` (pushed == drained + drops; no data race under `-fsanitize=thread` if available).

- [ ] **Step 4: Swap the hot-path log for `ring_push`** in `shim.c` + `seccomp.c` (every place currently calling `__android_log_print` inside `connect`/`sendto`/`getaddrinfo`/the supervisor decision path). Keep liblog ONLY for one-time init/warnings off the hot path. Re-assert the mandatory rule: nothing in the trapped path logs synchronously.

- [ ] **Step 5: Add the JVM drain thread** to `NativeShimBackend` and feed `Observer.record(EgressEvent(tier = Tier.NATIVE, …))`.

- [ ] **Step 6: Commit**

```bash
git add poseidon-native/src/main/cpp poseidon-native/src/main/java
git commit -m "feat(native): lock-free event ring drains native egress to the JVM Observer off the hot path"
```

### Task 5.2 — Checkpoint 5: unified audit map + perf sanity, on-device

- [ ] **Step 1: Build, install, exercise** Cronet (native) + OkHttp (JVM) + raw-syscall (seccomp), confirm `Observer` receives NATIVE-tier events with symbolized `.so` origin (`libcronet.so`) AND JVM-tier events in one stream.

Run: `export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew :poseidon-gradle-plugin:publishToMavenLocal :app:assembleDebug && adb -s 19011FDEE0040L install -r app/build/outputs/apk/debug/app-debug.apk && adb -s 19011FDEE0040L logcat -c && adb -s 19011FDEE0040L shell am start -n tech.ssemaj.poseidon/.MainActivity && sleep 8 && adb -s 19011FDEE0040L logcat -d -s Poseidon`
Expected: interleaved `[…/NATIVE] …libcronet.so` and `[…/JVM] …` audit lines; no recursion/deadlock; app responsive. Record perf note (connect-gate ~negligible vs RTT per `poseidon-go-coverage`).

- [ ] **Step 2: Commit**

```bash
git commit --allow-empty -m "test: Checkpoint 5 — unified native+JVM audit via lock-free ring, no hot-path logging (Pixel 6 Pro)"
```

> **Checkpoint 5 (review gate):** the native hot path is log-free; native + JVM events land in one `Observer`. STOP for review before Phase 6.

---

## Phase 6 — Retire the prototype module + docs

### Task 6.1: Delete `:poseidon-runtime`, update docs and READMEs

**Files:**
- Delete: `poseidon-runtime/` (now fully re-homed into core/native/seccomp)
- Modify: `settings.gradle.kts` (drop `include(":poseidon-runtime")`)
- Create: `poseidon-core/README.md`, `poseidon-native/README.md`, `poseidon-seccomp/README.md` (one-paragraph: what it covers, the honest limits from spec §9, opt-in cost/risk)
- Modify: root `README.md` (module table from spec §2; manifest-first config example from spec §7)

**Interfaces:** none (cleanup).

- [ ] **Step 1: Confirm nothing references `:poseidon-runtime`**

Run: `grep -rn "poseidon-runtime" --include=*.kts --include=*.kt --include=*.md . | grep -v docs/superpowers/specs`
Expected: only historical mentions in plans/specs; no live build references. Remove any live ones.

- [ ] **Step 2: Delete the module + build everything**

Run: `git rm -r poseidon-runtime && export JAVA_HOME=/snap/android-studio/230/jbr && ./gradlew clean :poseidon-all:assembleDebug :poseidon-core:testDebugUnitTest :poseidon-gradle-plugin:test`
Expected: BUILD SUCCESSFUL; all unit tests green.

- [ ] **Step 3: Write the module READMEs + root README** (each carries spec §9 honest-limits verbatim so the positioning travels with the code).

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: retire prototype poseidon-runtime; document tiered modules + manifest config"
```

> **Checkpoint 6:** prototype retired; tiered re-architecture is the only runtime.

---

## Phase 7 — CI wiring (lock equivalence + acceptance suite)

### Task 7.1: CI runs JVM unit tests, plugin tests, both glob-equivalence tests, and (gated) the on-device acceptance suite

**Files:**
- Create: `.github/workflows/poseidon-ci.yml` (or the project's CI equivalent — match existing infra if present)

**Interfaces:** none (automation).

- [ ] **Step 1: Author the CI job** running, with `JAVA_HOME` exported: `:poseidon-core:testDebugUnitTest`, `:poseidon-gradle-plugin:test`, the host `glob_test` + `ring_test` CMake targets, and `:app:assembleDebug`. Gate the on-device acceptance suite (Checkpoints 1/4/5 logcat assertions) behind a self-hosted-runner / connected-device label, since it needs the Pixel.

- [ ] **Step 2: Add a CI assertion that the two glob evaluators agree** — fail the build if either `GlobVectorEquivalenceTest` (JVM) or `glob_test` (native) fails on the shared `glob_vectors.txt` (spec §5 invariant 4, enforced).

- [ ] **Step 3: Commit**

```bash
git add .github
git commit -m "ci: unit + plugin + JVM/native glob-equivalence + app build; on-device suite gated by device label"
```

> **Checkpoint 7:** CI enforces evaluator equivalence and the full test matrix on every change.

---

## Self-Review (spec coverage)

- **§2 module tiers** → Phase 4 (core/native/seccomp/all) + Phase 6 retire. ✅
- **§3 pipeline + invariants** (interceptors never decide; Observer async/both modes; Enforcer never explains; path JVM-only; one policy object) → Phase 1 (Tasks 1.1–1.5) + §5 invariant 4 → Phase 3. ✅
- **§4 EgressEvent keystone + originToken off-thread symbolization** → Task 1.1 (type) + Task 5.1 (symbolize off the drain thread). ✅
- **§5 one policy, two equivalent evaluators** → Task 1.2 (JVM) + Phase 3 (shared vectors, both evaluators). ✅
- **§6 native↔JVM bridge: mirror push + lock-free ring + atomic swap** → Task 4.2 (mirror push backend) + Task 5.1 (ring). *Double-buffer atomic policy swap in native* is carried by the existing proven `configure` path (`poseidon-modules`); if the prototype used a mutex, Task 5.1's review should confirm/upgrade to atomic swap — noted here as a review item, not a silent gap.
- **§7 manifest-first config + proposals + approval + warn/error knob + DSL escape hatch** → Phase 2 (Tasks 2.1–2.4). ✅
- **§8 startup + per-tier enforcement + pre-package no re-sign** → preserved from prototype (`PoseidonInitializer`, `PoseidonNativeInjectTask`), re-homed in Phase 4; not re-implemented. ✅
- **§9 honest limits** → documented in Phase 6 READMEs. ✅
- **§10 testing strategy** (policy equivalence, per-tier on-device, manifest compile units, bridge round-trip, reuse prototype probes) → Phases 0,2,3,5,7 + Checkpoints 1/4/5. ✅
- **§11 migration (keep mechanisms, re-home, split, manifest-primary, keep prototype as reference until re-verified)** → the whole phase ordering, with the prototype retired only in Phase 6. ✅

**Carried review items (not gaps, flagged for the executing reviewer):** (1) confirm native policy update uses atomic double-buffer swap, not a mutex, when Task 5.1 touches the hot path; (2) library-proposal resource-ref resolution across AARs is deferred in Task 2.4 to inline `android:value` — a follow-up plan should resolve `@xml` resource refs from AAR proposals if real third-party libraries adopt the `proposes` meta-data.
