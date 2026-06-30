# Poseidon Sample App Revamp — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure the `:app` sample into a Navigation-3, ViewModel-driven, deep-ocean-branded showpiece — delivering the Overview and Policy screens plus the full control layer, with Tiers/Playground as placeholders (Phase 2).

**Architecture:** A single `PoseidonController` is the seam to the published Poseidon runtime (reads `policy.json`, registers an `Observer` sink, aggregates `EgressEvent`s into tallies, and flips enforcement via the public `Mode.current` + `NativeBridge` APIs). A `PoseidonViewModel` exposes an immutable `UiState` `StateFlow`; stateless Compose screens render it. `MainActivity` shrinks to a theme + `PoseidonApp` nav shell.

**Tech Stack:** Kotlin, Jetpack Compose (Material 3), Navigation 3, AndroidX Lifecycle ViewModel + Compose, kotlinx-coroutines (StateFlow), JUnit4 + Robolectric for JVM unit tests.

## Global Constraints

- **App module only.** No edits under `poseidon-core`, `poseidon-native`, `poseidon-seccomp`, `poseidon-all`, `poseidon-gradle-plugin`. (verbatim from spec §1)
- **Public runtime APIs only:** `tech.ssemaj.poseidon.runtime.model.Mode` (`Mode.current`), `tech.ssemaj.poseidon.runtime.internal.NativeBridge` (`apply`, `installSeccompGate`), `tech.ssemaj.poseidon.runtime.pipeline.Observer` (`addSink`/`removeSink`), `tech.ssemaj.poseidon.runtime.model.EgressEvent`, `tech.ssemaj.poseidon.runtime.model.Tier`. (spec §6)
- **Dark-first deep-ocean theme.** Reuse existing tokens in `app/src/main/java/tech/ssemaj/poseidon/ui/theme/Color.kt` (`AbyssalNavy`, `BioluminescentTeal`, `TridentGold`, `AquaAllow`, `CoralBlock`, `TextPrimary`, `TextSecondary`). (spec §4)
- **Honesty in copy:** never claim an absolute egress guarantee; deny-path is JVM/HTTP-only. (spec §6)
- **Pinned dep versions:** `navigation3-runtime`/`navigation3-ui` = `1.2.0-alpha04`; `lifecycle-viewmodel-navigation3` = `2.11.0`; `lifecycle-viewmodel-compose` = `2.11.0`; `robolectric` = `4.13` (already in catalog); `androidx-test-core` = `1.6.1` (already in catalog).
- **JDK/build:** build/run with `JAVA_HOME=/home/joseph/.jdks/openjdk-26.0.1`. Device tests target the connected arm64 device.

---

### Task 1: Add Navigation 3 + Lifecycle ViewModel dependencies

**Files:**
- Modify: `gradle/libs.versions.toml`
- Modify: `app/build.gradle.kts` (dependencies block)

**Interfaces:**
- Produces: catalog accessors `libs.androidx.navigation3.runtime`, `libs.androidx.navigation3.ui`, `libs.androidx.lifecycle.viewmodel.navigation3`, `libs.androidx.lifecycle.viewmodel.compose`, and test accessors `libs.robolectric`, `libs.androidx.test.core` (already present).

- [ ] **Step 1: Add versions + libraries to the catalog**

In `gradle/libs.versions.toml` under `[versions]` add:
```toml
navigation3 = "1.2.0-alpha04"
lifecycleViewmodelNav3 = "2.11.0"
lifecycleViewmodelCompose = "2.11.0"
```
Under `[libraries]` add:
```toml
androidx-navigation3-runtime = { group = "androidx.navigation3", name = "navigation3-runtime", version.ref = "navigation3" }
androidx-navigation3-ui = { group = "androidx.navigation3", name = "navigation3-ui", version.ref = "navigation3" }
androidx-lifecycle-viewmodel-navigation3 = { group = "androidx.lifecycle", name = "lifecycle-viewmodel-navigation3", version.ref = "lifecycleViewmodelNav3" }
androidx-lifecycle-viewmodel-compose = { group = "androidx.lifecycle", name = "lifecycle-viewmodel-compose", version.ref = "lifecycleViewmodelCompose" }
```

- [ ] **Step 2: Add dependencies to the app**

In `app/build.gradle.kts`, in `dependencies { }`, after `implementation(libs.androidx.activity.compose)`:
```kotlin
implementation(libs.androidx.navigation3.runtime)
implementation(libs.androidx.navigation3.ui)
implementation(libs.androidx.lifecycle.viewmodel.navigation3)
implementation(libs.androidx.lifecycle.viewmodel.compose)
testImplementation(libs.robolectric)
testImplementation(libs.androidx.test.core)
```

- [ ] **Step 3: Verify the dependencies resolve**

Run: `JAVA_HOME=/home/joseph/.jdks/openjdk-26.0.1 ./gradlew :app:dependencies --configuration debugRuntimeClasspath -q 2>&1 | grep -E "navigation3|viewmodel-navigation3" | head`
Expected: lines showing `androidx.navigation3:navigation3-runtime:1.2.0-alpha04`, `...-ui:1.2.0-alpha04`, `androidx.lifecycle:lifecycle-viewmodel-navigation3:2.11.0` (no `FAILED`).

- [ ] **Step 4: Commit**
```bash
git add gradle/libs.versions.toml app/build.gradle.kts
git commit -m "build: add Navigation 3 + lifecycle-viewmodel deps to sample app"
```

---

### Task 2: `UiState` + `EnforcementGate` (control layer types)

**Files:**
- Create: `app/src/main/java/tech/ssemaj/poseidon/control/UiState.kt`
- Create: `app/src/main/java/tech/ssemaj/poseidon/control/EnforcementGate.kt`

**Interfaces:**
- Produces:
  - `data class TierTally(val tier: Tier, val allowed: Int, val blocked: Int)`
  - `data class UiState(val mode: Mode, val allowedTotal: Int, val blockedTotal: Int, val tierTallies: List<TierTally>, val events: List<EgressEvent>)` with `companion object { val EMPTY = UiState(Mode.MONITOR, 0, 0, emptyList(), emptyList()) }`
  - `interface EnforcementGate { fun setEnforcing(enforce: Boolean) }`

- [ ] **Step 1: Create `UiState.kt`**
```kotlin
package tech.ssemaj.poseidon.control

import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.runtime.model.Mode
import tech.ssemaj.poseidon.runtime.model.Tier

/** Allow/block counts for a single enforcement tier. */
data class TierTally(val tier: Tier, val allowed: Int, val blocked: Int)

/** Immutable snapshot the UI renders. Produced only by [PoseidonController]. */
data class UiState(
    val mode: Mode,
    val allowedTotal: Int,
    val blockedTotal: Int,
    val tierTallies: List<TierTally>,
    val events: List<EgressEvent>,
) {
    companion object {
        val EMPTY = UiState(Mode.MONITOR, 0, 0, emptyList(), emptyList())
    }
}
```

- [ ] **Step 2: Create `EnforcementGate.kt`**
```kotlin
package tech.ssemaj.poseidon.control

/**
 * Seam over Poseidon's runtime enforcement switch so the controller is unit-testable
 * without loading native code. The real implementation flips the public
 * Mode.current + NativeBridge APIs; tests use a fake.
 */
interface EnforcementGate {
    /** true = ENFORCE (block), false = MONITOR (log-only). */
    fun setEnforcing(enforce: Boolean)
}
```

- [ ] **Step 3: Verify it compiles**

Run: `JAVA_HOME=/home/joseph/.jdks/openjdk-26.0.1 ./gradlew :app:compileDebugKotlin -q 2>&1 | tail -5`
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 4: Commit**
```bash
git add app/src/main/java/tech/ssemaj/poseidon/control/UiState.kt app/src/main/java/tech/ssemaj/poseidon/control/EnforcementGate.kt
git commit -m "feat: add UiState + EnforcementGate control types"
```

---

### Task 3: `PoseidonController` (aggregation + mode) — TDD

**Files:**
- Create: `app/src/main/java/tech/ssemaj/poseidon/control/PoseidonController.kt`
- Test: `app/src/test/java/tech/ssemaj/poseidon/control/PoseidonControllerTest.kt`

**Interfaces:**
- Consumes: `UiState`, `TierTally`, `EnforcementGate` (Task 2); `Mode`, `Tier`, `EgressEvent`.
- Produces:
  - `class PoseidonController(initialMode: Mode, private val gate: EnforcementGate, private val maxEvents: Int = 100)`
  - `val state: StateFlow<UiState>`
  - `fun onEvent(event: EgressEvent)` — prepend event, recompute tallies/totals (block = `event.decision?.block == true`).
  - `fun setMode(mode: Mode)` — update state.mode and call `gate.setEnforcing(mode == Mode.ENFORCE)`.
  - `fun toggleMode()` — flip ENFORCE↔MONITOR via `setMode`.

- [ ] **Step 1: Write the failing test**

`app/src/test/java/tech/ssemaj/poseidon/control/PoseidonControllerTest.kt`:
```kotlin
package tech.ssemaj.poseidon.control

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import tech.ssemaj.poseidon.runtime.model.Action
import tech.ssemaj.poseidon.runtime.model.Decision
import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.runtime.model.Mode
import tech.ssemaj.poseidon.runtime.model.Tier

private class FakeGate : EnforcementGate {
    var lastEnforce: Boolean? = null
    override fun setEnforcing(enforce: Boolean) { lastEnforce = enforce }
}

private fun event(tier: Tier, host: String, block: Boolean) = EgressEvent(
    tier = tier,
    host = host,
    ip = null,
    port = 443,
    path = null,
    transport = null,
    decision = Decision(if (block) Action.BLOCK else Action.ALLOW),
)

class PoseidonControllerTest {

    @Test
    fun onEvent_updatesTotalsAndPerTierTallies() {
        val c = PoseidonController(Mode.ENFORCE, FakeGate())
        c.onEvent(event(Tier.JVM, "a.com", block = true))
        c.onEvent(event(Tier.JVM, "example.com", block = false))
        c.onEvent(event(Tier.LIBC, "b.com", block = true))

        val s = c.state.value
        assertEquals(1, s.allowedTotal)
        assertEquals(2, s.blockedTotal)
        val jvm = s.tierTallies.first { it.tier == Tier.JVM }
        assertEquals(1, jvm.allowed)
        assertEquals(1, jvm.blocked)
        // newest-first
        assertEquals("b.com", s.events.first().host)
    }

    @Test
    fun events_areCappedAtMaxEvents() {
        val c = PoseidonController(Mode.ENFORCE, FakeGate(), maxEvents = 2)
        repeat(5) { c.onEvent(event(Tier.JVM, "h$it.com", block = true)) }
        assertEquals(2, c.state.value.events.size)
        assertEquals("h4.com", c.state.value.events.first().host)
    }

    @Test
    fun setMode_flipsGateAndState() {
        val gate = FakeGate()
        val c = PoseidonController(Mode.ENFORCE, gate)
        c.setMode(Mode.MONITOR)
        assertEquals(Mode.MONITOR, c.state.value.mode)
        assertEquals(false, gate.lastEnforce)
        c.toggleMode()
        assertEquals(Mode.ENFORCE, c.state.value.mode)
        assertTrue(gate.lastEnforce == true)
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `JAVA_HOME=/home/joseph/.jdks/openjdk-26.0.1 ./gradlew :app:testDebugUnitTest --tests "tech.ssemaj.poseidon.control.PoseidonControllerTest" 2>&1 | tail -15`
Expected: FAIL — `PoseidonController` unresolved (does not compile yet).

> **Note for the implementer:** Before writing the implementation, open `EgressEvent`, `Decision`, `Action`, and `Tier` in the published runtime to confirm constructor parameter names/order and the exact `Tier` enum constants (e.g. `JVM`, `LIBC`, `SECCOMP`). The test above assumes them; adjust both test and impl to the real signatures if they differ. Find them with:
> `find ~/.gradle/caches -path '*poseidon*' -name '*.jar' 2>/dev/null` then inspect, or read the source mirror if present. Do NOT guess — verify.

- [ ] **Step 3: Write the implementation**
```kotlin
package tech.ssemaj.poseidon.control

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.runtime.model.Mode
import tech.ssemaj.poseidon.runtime.model.Tier

/**
 * Single seam to the Poseidon runtime for the demo UI. Aggregates audit events into a
 * render-ready [UiState] and flips enforcement through an [EnforcementGate]. Pure logic —
 * no Android or native types beyond the public runtime model — so it is unit-testable.
 */
class PoseidonController(
    initialMode: Mode,
    private val gate: EnforcementGate,
    private val maxEvents: Int = 100,
) {
    private val _state = MutableStateFlow(UiState.EMPTY.copy(mode = initialMode))
    val state: StateFlow<UiState> = _state.asStateFlow()

    /** Called for every EgressEvent (from the Observer sink). Thread: arbitrary. */
    @Synchronized
    fun onEvent(event: EgressEvent) {
        val events = (listOf(event) + _state.value.events).take(maxEvents)
        _state.value = _state.value.copy(
            events = events,
            allowedTotal = events.count { it.decision?.block != true },
            blockedTotal = events.count { it.decision?.block == true },
            tierTallies = tally(events),
        )
    }

    @Synchronized
    fun setMode(mode: Mode) {
        gate.setEnforcing(mode == Mode.ENFORCE)
        _state.value = _state.value.copy(mode = mode)
    }

    fun toggleMode() =
        setMode(if (_state.value.mode == Mode.ENFORCE) Mode.MONITOR else Mode.ENFORCE)

    private fun tally(events: List<EgressEvent>): List<TierTally> =
        Tier.entries.map { tier ->
            val forTier = events.filter { it.tier == tier }
            TierTally(
                tier = tier,
                allowed = forTier.count { it.decision?.block != true },
                blocked = forTier.count { it.decision?.block == true },
            )
        }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `JAVA_HOME=/home/joseph/.jdks/openjdk-26.0.1 ./gradlew :app:testDebugUnitTest --tests "tech.ssemaj.poseidon.control.PoseidonControllerTest" 2>&1 | tail -15`
Expected: PASS (3 tests). If `Tier.entries` is unavailable (older Kotlin enum API), use `Tier.values().toList()`.

- [ ] **Step 5: Commit**
```bash
git add app/src/main/java/tech/ssemaj/poseidon/control/PoseidonController.kt app/src/test/java/tech/ssemaj/poseidon/control/PoseidonControllerTest.kt
git commit -m "feat: PoseidonController aggregation + mode toggle (TDD)"
```

---

### Task 4: Real `RuntimeEnforcementGate` + `PoseidonViewModel` + Observer sink

**Files:**
- Create: `app/src/main/java/tech/ssemaj/poseidon/control/RuntimeEnforcementGate.kt`
- Create: `app/src/main/java/tech/ssemaj/poseidon/control/PoseidonViewModel.kt`

**Interfaces:**
- Consumes: `PoseidonController`, `EnforcementGate`, `UiState`; `PolicyInfo.load`; `Mode`, `NativeBridge`, `Observer`.
- Produces:
  - `class RuntimeEnforcementGate(private val allowedHosts: List<String>) : EnforcementGate`
  - `class PoseidonViewModel(app: Application) : AndroidViewModel(app)` with `val state: StateFlow<UiState>`, `fun toggleMode()`, `fun runAllProbes()`, and a `companion object { val Factory: ViewModelProvider.Factory }`.

- [ ] **Step 1: Create `RuntimeEnforcementGate.kt`**
```kotlin
package tech.ssemaj.poseidon.control

import tech.ssemaj.poseidon.runtime.internal.NativeBridge
import tech.ssemaj.poseidon.runtime.model.Mode

/**
 * Real enforcement seam against the published Poseidon runtime (public APIs only):
 * flips the JVM gate (Mode.current) and re-pushes the native allow-list with the new
 * enforce flag. The host list comes from the compiled policy so native re-config keeps
 * the same allow-list, only toggling block-vs-observe.
 */
class RuntimeEnforcementGate(private val allowedHosts: List<String>) : EnforcementGate {
    override fun setEnforcing(enforce: Boolean) {
        Mode.current = if (enforce) Mode.ENFORCE else Mode.MONITOR
        NativeBridge.apply(allowedHosts, enforce)
    }
}
```

> **Implementer note:** confirm `NativeBridge.apply(List<String>, Boolean)` and `Mode.current` are public in the resolved `poseidon-all` artifact (they are in source). If `installSeccompGate` needs re-calling under monitor, add it here only after verifying real behavior on-device; otherwise leave seccomp as initialized (document the truthful behavior in Phase 2's Tiers copy).

- [ ] **Step 2: Create `PoseidonViewModel.kt`**
```kotlin
package tech.ssemaj.poseidon.control

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import tech.ssemaj.poseidon.PolicyInfo
import tech.ssemaj.poseidon.probes.DemoProbes
import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.runtime.model.Mode
import tech.ssemaj.poseidon.runtime.pipeline.Observer

class PoseidonViewModel(app: Application) : AndroidViewModel(app) {

    private val policy = PolicyInfo.load(app)
    private val controller = PoseidonController(
        initialMode = if (policy.mode == "enforce") Mode.ENFORCE else Mode.MONITOR,
        gate = RuntimeEnforcementGate(policy.allowedHosts),
    )

    val state: StateFlow<UiState> = controller.state

    private val sink: (EgressEvent) -> Unit = { controller.onEvent(it) }

    init { Observer.addSink(sink) }

    fun toggleMode() = controller.toggleMode()

    fun runAllProbes() {
        viewModelScope.launch(Dispatchers.IO) {
            DemoProbes.runAll(getApplication())
        }
    }

    override fun onCleared() {
        Observer.removeSink(sink)
    }

    companion object {
        val Factory: ViewModelProvider.Factory = viewModelFactory {
            initializer { PoseidonViewModel(this[ViewModelProvider.AndroidViewModelFactory.APPLICATION_KEY]!!) }
        }
    }
}
```

- [ ] **Step 3: Verify compile**

Run: `JAVA_HOME=/home/joseph/.jdks/openjdk-26.0.1 ./gradlew :app:compileDebugKotlin -q 2>&1 | tail -8`
Expected: `BUILD SUCCESSFUL`. If `Observer.addSink` signature differs from `(EgressEvent) -> Unit`, match the real functional type (see `EgressDashboardState.kt`, which already uses `Observer.addSink`).

- [ ] **Step 4: Commit**
```bash
git add app/src/main/java/tech/ssemaj/poseidon/control/RuntimeEnforcementGate.kt app/src/main/java/tech/ssemaj/poseidon/control/PoseidonViewModel.kt
git commit -m "feat: RuntimeEnforcementGate + PoseidonViewModel with Observer sink"
```

---

### Task 5: Reusable ocean components

**Files:**
- Create: `app/src/main/java/tech/ssemaj/poseidon/ui/components/OceanComponents.kt`

**Interfaces:**
- Consumes: theme tokens; `Tier`, `EgressEvent`.
- Produces composables: `WaveBackground(modifier)`, `TridentHeader(mode, onModeClick)`, `ModeChip(enforcing, onClick)`, `StatTile(label, value, accent, modifier)`, `VerdictBadge(blocked)`, `EventRow(event)`.

- [ ] **Step 1: Create the components file**

Implement the composables below (reuse the wave Canvas/animation approach already present in the current `MainActivity.kt` — `rememberInfiniteTransition` + `Canvas`). Use `AquaAllow` for allowed, `CoralBlock` for blocked, `TridentGold` for the trident, gradient `AbyssalNavy`→`MarineBlue` for `WaveBackground`.
```kotlin
package tech.ssemaj.poseidon.ui.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.unit.dp
import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.ui.theme.*

@Composable
fun WaveBackground(modifier: Modifier = Modifier) {
    val t = rememberInfiniteTransition(label = "wave")
    val phase by t.animateFloat(
        initialValue = 0f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(6000, easing = LinearEasing), RepeatMode.Restart),
        label = "phase",
    )
    Canvas(modifier.fillMaxSize().background(Brush.verticalGradient(listOf(AbyssalNavy, MarineBlue)))) {
        val w = size.width; val h = size.height
        val path = Path().apply {
            moveTo(0f, h * 0.5f)
            var x = 0f
            while (x <= w) {
                val y = h * 0.5f + 24f * kotlin.math.sin((x / w * 6.28f) + phase * 6.28f)
                lineTo(x, y); x += 8f
            }
            lineTo(w, h); lineTo(0f, h); close()
        }
        drawPath(path, BioluminescentTeal.copy(alpha = 0.06f))
    }
}

@Composable
fun ModeChip(enforcing: Boolean, onClick: () -> Unit) {
    val accent = if (enforcing) AquaAllow else TridentGold
    Surface(
        color = accent.copy(alpha = 0.15f),
        shape = RoundedCornerShape(50),
        onClick = onClick,
    ) {
        Text(
            text = if (enforcing) "◐ ENFORCE" else "○ MONITOR",
            style = MaterialTheme.typography.labelMedium,
            color = accent,
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 7.dp),
        )
    }
}

@Composable
fun TridentHeader(enforcing: Boolean, onModeClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(20.dp), verticalAlignment = Alignment.CenterVertically) {
        Text("⟁ POSEIDON", style = MaterialTheme.typography.displayLarge, color = TridentGold)
        Spacer(Modifier.weight(1f))
        ModeChip(enforcing, onModeClick)
    }
}

@Composable
fun StatTile(label: String, value: String, accent: Color, modifier: Modifier = Modifier) {
    Surface(modifier, color = DeepBlue, shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.padding(18.dp)) {
            Text(value, style = MaterialTheme.typography.displayLarge, color = accent)
            Text(label, style = MaterialTheme.typography.headlineMedium, color = TextSecondary)
        }
    }
}

@Composable
fun VerdictBadge(blocked: Boolean) {
    val accent = if (blocked) CoralBlock else AquaAllow
    Surface(color = accent.copy(alpha = 0.15f), shape = RoundedCornerShape(6.dp)) {
        Text(
            if (blocked) "BLOCK" else "ALLOW",
            style = MaterialTheme.typography.labelSmall, color = accent,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
        )
    }
}

@Composable
fun EventRow(event: EgressEvent) {
    val blocked = event.decision?.block == true
    Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically) {
        VerdictBadge(blocked)
        Spacer(Modifier.width(10.dp))
        Text("[${event.tier}] ${event.host ?: event.ip ?: "?"}${event.path ?: ""}",
            style = MaterialTheme.typography.bodySmall, color = TextPrimary)
    }
}
```

- [ ] **Step 2: Verify compile**

Run: `JAVA_HOME=/home/joseph/.jdks/openjdk-26.0.1 ./gradlew :app:compileDebugKotlin -q 2>&1 | tail -8`
Expected: `BUILD SUCCESSFUL`. Fix any token name mismatches against `Color.kt`.

- [ ] **Step 3: Commit**
```bash
git add app/src/main/java/tech/ssemaj/poseidon/ui/components/OceanComponents.kt
git commit -m "feat: reusable ocean-brand Compose components"
```

---

### Task 6: Overview + Policy screens

**Files:**
- Create: `app/src/main/java/tech/ssemaj/poseidon/ui/overview/OverviewScreen.kt`
- Create: `app/src/main/java/tech/ssemaj/poseidon/ui/policy/PolicyScreen.kt`

**Interfaces:**
- Consumes: `UiState`, ocean components (Task 5), `PolicyInfo`, `Mode`.
- Produces:
  - `@Composable fun OverviewScreen(state: UiState, onToggleMode: () -> Unit, onRunAll: () -> Unit)`
  - `@Composable fun PolicyScreen(policy: PolicyInfo)`

- [ ] **Step 1: Create `OverviewScreen.kt`**
```kotlin
package tech.ssemaj.poseidon.ui.overview

import androidx.compose.foundation.layout.*
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import tech.ssemaj.poseidon.control.UiState
import tech.ssemaj.poseidon.runtime.model.Mode
import tech.ssemaj.poseidon.ui.components.StatTile
import tech.ssemaj.poseidon.ui.components.TridentHeader
import tech.ssemaj.poseidon.ui.theme.AquaAllow
import tech.ssemaj.poseidon.ui.theme.CoralBlock
import tech.ssemaj.poseidon.ui.theme.TextSecondary

@Composable
fun OverviewScreen(state: UiState, onToggleMode: () -> Unit, onRunAll: () -> Unit) {
    Column(Modifier.fillMaxSize()) {
        TridentHeader(enforcing = state.mode == Mode.ENFORCE, onModeClick = onToggleMode)
        Text(
            "Default-deny egress control across three enforcement tiers.",
            style = MaterialTheme.typography.bodyLarge,
            color = TextSecondary,
            modifier = Modifier.padding(horizontal = 20.dp),
        )
        Row(Modifier.fillMaxWidth().padding(20.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatTile("ALLOWED", state.allowedTotal.toString(), AquaAllow, Modifier.weight(1f))
            StatTile("BLOCKED", state.blockedTotal.toString(), CoralBlock, Modifier.weight(1f))
        }
        Button(onClick = onRunAll, modifier = Modifier.padding(horizontal = 20.dp)) {
            Text("RUN ALL PROBES", style = MaterialTheme.typography.labelMedium)
        }
    }
}
```

- [ ] **Step 2: Create `PolicyScreen.kt`**
```kotlin
package tech.ssemaj.poseidon.ui.policy

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import tech.ssemaj.poseidon.PolicyInfo
import tech.ssemaj.poseidon.ui.theme.TextPrimary
import tech.ssemaj.poseidon.ui.theme.TextSecondary

@Composable
fun PolicyScreen(policy: PolicyInfo) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("WHAT WE'RE FILTERING", style = MaterialTheme.typography.headlineMedium, color = TextSecondary)
        Row { Text("mode  ", color = TextSecondary, style = MaterialTheme.typography.bodySmall)
              Text(policy.mode, color = TextPrimary, style = MaterialTheme.typography.bodySmall) }
        Text("allow hosts: ${policy.allowedHosts.joinToString().ifEmpty { "—" }}",
            color = TextPrimary, style = MaterialTheme.typography.bodySmall)
        Text("deny paths: ${policy.deniedPaths.joinToString().ifEmpty { "—" }} (JVM/HTTP-only)",
            color = TextPrimary, style = MaterialTheme.typography.bodySmall)
        Text("allow CIDRs: ${policy.allowedCidrs.joinToString().ifEmpty { "—" }}",
            color = TextPrimary, style = MaterialTheme.typography.bodySmall)
        Text("Strict default-deny posture — not an absolute egress guarantee.",
            color = TextSecondary, style = MaterialTheme.typography.bodyMedium)
    }
}
```

- [ ] **Step 3: Verify compile**

Run: `JAVA_HOME=/home/joseph/.jdks/openjdk-26.0.1 ./gradlew :app:compileDebugKotlin -q 2>&1 | tail -8`
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 4: Commit**
```bash
git add app/src/main/java/tech/ssemaj/poseidon/ui/overview/OverviewScreen.kt app/src/main/java/tech/ssemaj/poseidon/ui/policy/PolicyScreen.kt
git commit -m "feat: Overview + Policy screens"
```

---

### Task 7: `PoseidonApp` nav shell + slim `MainActivity`

**Files:**
- Create: `app/src/main/java/tech/ssemaj/poseidon/ui/PoseidonApp.kt`
- Modify: `app/src/main/java/tech/ssemaj/poseidon/MainActivity.kt` (replace body)

**Interfaces:**
- Consumes: `PoseidonViewModel`, `OverviewScreen`, `PolicyScreen`, `WaveBackground`, Navigation 3 (`NavDisplay`, `entryProvider`), Material 3 `NavigationBar`.
- Produces: `@Composable fun PoseidonApp(vm: PoseidonViewModel)`.

- [ ] **Step 1: Create `PoseidonApp.kt`**

Four flat top-level destinations; Tiers & Playground are Phase-2 placeholders. Single-entry back stack (each tab replaces the visible entry; back exits). Follow the `navigation-3` skill's common-ui recipe for exact `NavDisplay`/`entryProvider` imports.
```kotlin
package tech.ssemaj.poseidon.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.ui.NavDisplay
import tech.ssemaj.poseidon.PolicyInfo
import tech.ssemaj.poseidon.control.PoseidonViewModel
import tech.ssemaj.poseidon.ui.components.WaveBackground
import tech.ssemaj.poseidon.ui.overview.OverviewScreen
import tech.ssemaj.poseidon.ui.policy.PolicyScreen

private sealed interface Dest { val label: String; val icon: ImageVector }
private data object Overview : Dest { override val label = "Overview"; override val icon = Icons.Default.Shield }
private data object Tiers : Dest { override val label = "Tiers"; override val icon = Icons.Default.List }
private data object Playground : Dest { override val label = "Play"; override val icon = Icons.Default.PlayArrow }
private data object Policy : Dest { override val label = "Policy"; override val icon = Icons.Default.Lock }
private val DESTS = listOf(Overview, Tiers, Playground, Policy)

@Composable
fun PoseidonApp(vm: PoseidonViewModel) {
    val state by vm.state.collectAsState()
    var current by remember { mutableStateOf<Dest>(Overview) }
    val backStack = remember(current) { mutableListOf<Any>(current) }
    val policy = remember { vm.policySnapshot() }

    Scaffold(
        containerColor = Color.Transparent,
        bottomBar = {
            NavigationBar {
                DESTS.forEach { d ->
                    NavigationBarItem(
                        selected = d == current,
                        onClick = { current = d },
                        icon = { Icon(d.icon, contentDescription = d.label) },
                        label = { Text(d.label, style = MaterialTheme.typography.labelMedium) },
                    )
                }
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize()) {
            WaveBackground()
            Box(Modifier.fillMaxSize().padding(padding)) {
                NavDisplay(
                    backStack = backStack,
                    onBack = {},
                    entryProvider = entryProvider {
                        entry<Overview> { OverviewScreen(state, vm::toggleMode, vm::runAllProbes) }
                        entry<Tiers> { PlaceholderScreen("Tiers — Phase 2") }
                        entry<Playground> { PlaceholderScreen("Playground — Phase 2") }
                        entry<Policy> { PolicyScreen(policy) }
                    },
                )
            }
        }
    }
}

@Composable
private fun PlaceholderScreen(text: String) {
    Box(Modifier.fillMaxSize()) { Text(text, modifier = Modifier.padding(24.dp)) }
}
```

> **Implementer note:** `entry<Overview>` requires the destination keys to be supported by the entryProvider DSL. If `NavDisplay` requires keys implementing `NavKey`, make each `Dest` a `@Serializable` `NavKey` per the navigation-3 skill (`basicsaveable`/`common-ui` recipes). Wire the back stack with the recipe's `TopLevelBackStack` if the simple single-entry list does not satisfy the API. Adapt imports/`padding` import as the compiler requires. Add `fun policySnapshot(): PolicyInfo = policy` (expose the already-loaded policy) to `PoseidonViewModel` rather than reloading.

- [ ] **Step 2: Add `policySnapshot()` to the ViewModel**

In `PoseidonViewModel`, add: `fun policySnapshot(): PolicyInfo = policy` and import `tech.ssemaj.poseidon.PolicyInfo` (already imported).

- [ ] **Step 3: Replace `MainActivity` body**

Replace the entire `MainActivity.kt` with:
```kotlin
package tech.ssemaj.poseidon

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import tech.ssemaj.poseidon.control.PoseidonViewModel
import tech.ssemaj.poseidon.probes.DemoProbes
import tech.ssemaj.poseidon.ui.PoseidonApp
import tech.ssemaj.poseidon.ui.theme.PoseidonTheme

class MainActivity : ComponentActivity() {
    private val vm: PoseidonViewModel by viewModels { PoseidonViewModel.Factory }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { PoseidonTheme { PoseidonApp(vm) } }
        // Fire the probe suite once on launch so the dashboard has live data.
        DemoProbes.runAll(applicationContext)
    }
}
```

- [ ] **Step 4: Verify compile**

Run: `JAVA_HOME=/home/joseph/.jdks/openjdk-26.0.1 ./gradlew :app:compileDebugKotlin -q 2>&1 | tail -15`
Expected: `BUILD SUCCESSFUL`. Resolve any Navigation 3 API mismatches using the `navigation-3` skill recipes before proceeding.

- [ ] **Step 5: Commit**
```bash
git add app/src/main/java/tech/ssemaj/poseidon/ui/PoseidonApp.kt app/src/main/java/tech/ssemaj/poseidon/control/PoseidonViewModel.kt app/src/main/java/tech/ssemaj/poseidon/MainActivity.kt
git commit -m "feat: PoseidonApp nav shell + slim MainActivity"
```

---

### Task 8: Remove dead UI + on-device verification

**Files:**
- Delete: `app/src/main/java/tech/ssemaj/poseidon/EgressDashboardState.kt` (superseded by `PoseidonController`)
- Keep but review: `VerifyState.kt`, `PolicyInfo.kt` (PolicyInfo still used; VerifyState moves to Phase 2 Playground — leave in place, unused, for now)

**Interfaces:** none new.

- [ ] **Step 1: Remove the superseded dashboard state**

Confirm nothing references it: `grep -rn "EgressDashboardState" app/src/main` → expect no hits after Task 7. Then delete the file.
> If any old composables in the previous `MainActivity` referenced it, they were replaced in Task 7. If `grep` shows references, fix them before deleting.

- [ ] **Step 2: Run the unit tests**

Run: `JAVA_HOME=/home/joseph/.jdks/openjdk-26.0.1 ./gradlew :app:testDebugUnitTest 2>&1 | tail -10`
Expected: `BUILD SUCCESSFUL`, `PoseidonControllerTest` green.

- [ ] **Step 3: Install + launch on device, verify the revamped UI**

Run:
```bash
JAVA_HOME=/home/joseph/.jdks/openjdk-26.0.1 ./gradlew :app:installDebug -q
ADB=$(command -v adb || echo ~/Android/Sdk/platform-tools/adb)
"$ADB" shell am force-stop tech.ssemaj.poseidon
"$ADB" logcat -c
"$ADB" shell am start -n tech.ssemaj.poseidon/.MainActivity
sleep 8
"$ADB" logcat -d -s PoseidonDemo:* Poseidon:* | grep -iE "BLOCK|ALLOW|rootbeer|mmkv|grpc" | head
```
Expected: app launches showing the Overview screen (trident header, ALLOWED/BLOCKED stat tiles populated after probes fire), bottom nav with 4 tabs, Policy tab shows the compiled allow-list. Logcat shows `[ENFORCE/...] ... -> BLOCK`/`ALLOW` lines, confirming events flowed into the controller.

- [ ] **Step 4: Tap-through sanity (manual)**

Confirm: bottom-nav switches Overview/Tiers/Playground/Policy; the ModeChip tap flips ENFORCE↔MONITOR (re-tap "RUN ALL PROBES" and observe blocked count behavior differ between modes); Tiers/Playground show the Phase-2 placeholder.

- [ ] **Step 5: Commit**
```bash
git add -A app/src/main/java/tech/ssemaj/poseidon/
git commit -m "chore: remove superseded EgressDashboardState; Phase 1 on-device verified"
```

---

## Self-Review

**Spec coverage:**
- §2 architecture (controller/ViewModel/StateFlow) → Tasks 2–4. ✓
- §3.1 Overview, §3.4 Policy → Task 6/7. ✓ §3.2 Tiers, §3.3 Playground → Phase-2 placeholders (Task 7), full build Phase 2. ✓ (deferred by design)
- §4 theme → reused existing tokens + Task 5 components. ✓
- §5 file layout → Tasks 2–7 create the directories. ✓
- §6 toggle via public APIs → Task 4 `RuntimeEnforcementGate`; honesty copy in Task 6 Policy screen. ✓
- §8 testing: controller/ViewModel unit tests → Task 3; existing probe tests untouched. ✓
- §9 nav3 dep → Task 1. ✓

**Placeholder scan:** No "TBD/implement later". The "Implementer note" blocks are verification instructions against the published artifact (real signatures must be confirmed), not deferred work — each task still has concrete code.

**Type consistency:** `PoseidonController(initialMode, gate, maxEvents)`, `state: StateFlow<UiState>`, `onEvent`, `setMode`, `toggleMode`, `UiState(mode, allowedTotal, blockedTotal, tierTallies, events)`, `TierTally(tier, allowed, blocked)`, `EnforcementGate.setEnforcing(Boolean)`, `PoseidonViewModel.{state, toggleMode, runAllProbes, policySnapshot, Factory}` — used consistently across Tasks 2–8.

**Known risk to verify first in execution:** exact `EgressEvent`/`Decision`/`Action` constructor signatures and `Tier` enum constants in the resolved `poseidon-all` artifact, and the `Observer.addSink` functional type. Task 3 Step 2 and Task 4 Step 3 call this out explicitly; `EgressDashboardState.kt` (pre-deletion) is the in-repo reference for `Observer.addSink` + `EgressEvent` usage.
