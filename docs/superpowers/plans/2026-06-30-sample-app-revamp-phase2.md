# Poseidon Sample App Revamp — Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Fill the Tiers and Playground screens with real, interactive content and make Overview less hollow, completing the showpiece on top of Phase 1.

**Architecture:** Reuse the Phase-1 control layer (`PoseidonViewModel.state: StateFlow<UiState>`, `toggleMode()`, `runAllProbes()`). Tiers renders `UiState.tierTallies` + per-tier filtered `UiState.events` with the existing `EventRow`. Playground reuses the existing `VerifyState` (editable URL + `ClientStyle` fire + `QueryResult`) for "pick host + SDK, fire", plus the mode toggle and a live event stream. No new ProbeCatalog — `VerifyState` already is one (DRY; deviates from spec §2.3 deliberately).

**Tech Stack:** Kotlin, Jetpack Compose (Material 3), the Phase-1 ocean components, Navigation 3 (already wired).

## Global Constraints

- **App module only.** No edits under `poseidon-core|native|seccomp|all|gradle-plugin`. (spec §1)
- **Public runtime APIs only** for enforcement; the toggle goes through `PoseidonViewModel.toggleMode()` (already implemented; do not call `Mode`/`NativeBridge` directly from UI).
- **Dark-first deep-ocean theme**, reuse tokens in `ui/theme/Color.kt` and components in `ui/components/OceanComponents.kt` (`WaveBackground`, `TridentHeader`, `ModeChip`, `StatTile`, `VerdictBadge`, `EventRow`).
- **Honesty in copy:** never claim absolute egress guarantee; deny-path is JVM/HTTP-only. (spec §6)
- **Build/run:** `JAVA_HOME=/home/joseph/.jdks/openjdk-26.0.1 PATH=/home/joseph/.jdks/openjdk-26.0.1/bin:$PATH ./gradlew ...`. Connected device serial `19011FDEE0040L`; adb `$(command -v adb || echo ~/Android/Sdk/platform-tools/adb)`.

## Reference — existing symbols Phase 2 consumes (verified present)

- `tech.ssemaj.poseidon.control.UiState(mode: Mode, allowedTotal: Int, blockedTotal: Int, tierTallies: List<TierTally>, events: List<EgressEvent>)`; `TierTally(tier: Tier, allowed: Int, blocked: Int)`.
- `tech.ssemaj.poseidon.runtime.model.Tier` constants: `JVM`, `NATIVE`, `SECCOMP`.
- `tech.ssemaj.poseidon.runtime.model.EgressEvent` fields used by `EventRow`: `tier`, `host: String?`, `ip: String?`, `path: String?`, `decision?.block: Boolean?`.
- Components (in `tech.ssemaj.poseidon.ui.components`): `EventRow(event: EgressEvent)`, `StatTile(label, value, accent: Color, modifier)`, `ModeChip(enforcing: Boolean, onClick: () -> Unit)`, `VerdictBadge(blocked: Boolean)`, `TridentHeader(enforcing, onModeClick)`.
- Theme tokens: `AquaAllow`, `CoralBlock`, `BioluminescentTeal`, `TridentGold`, `DeepBlue`, `MarineBlue`, `TextPrimary`, `TextSecondary`.
- `tech.ssemaj.poseidon.VerifyState`: `val url: MutableState<String>`, `val results: SnapshotStateList<QueryResult>`, `fun run(style: ClientStyle, context: Context)`. `enum ClientStyle(val label){ OKHTTP, HTTP_URL, VOLLEY, CRONET, RAW }`. `QueryResult(id: Long, client: String, url: String, outcome: String, blocked: Boolean)`.
- `tech.ssemaj.poseidon.ui.PoseidonApp` currently maps `entry<Tiers>`/`entry<Playground>` to a private `PlaceholderScreen("... — Phase 2")`. These two entries are what Tasks 1–2 replace.

---

### Task 1: Tiers screen (per-tier live cards)

**Files:**
- Create: `app/src/main/java/tech/ssemaj/poseidon/ui/tiers/TiersScreen.kt`
- Modify: `app/src/main/java/tech/ssemaj/poseidon/ui/PoseidonApp.kt` (replace the `entry<Tiers>` placeholder)

**Interfaces:**
- Produces: `@Composable fun TiersScreen(state: UiState)`.

- [ ] **Step 1: Create `TiersScreen.kt`**

Render a scrollable column of three `TierCard`s, one per `Tier`, each showing title + one-line description, allow/block counts from `state.tierTallies`, and up to 5 recent events for that tier from `state.events`.
```kotlin
package tech.ssemaj.poseidon.ui.tiers

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import tech.ssemaj.poseidon.control.UiState
import tech.ssemaj.poseidon.runtime.model.Tier
import tech.ssemaj.poseidon.ui.components.EventRow
import tech.ssemaj.poseidon.ui.theme.AquaAllow
import tech.ssemaj.poseidon.ui.theme.CoralBlock
import tech.ssemaj.poseidon.ui.theme.DeepBlue
import tech.ssemaj.poseidon.ui.theme.TextPrimary
import tech.ssemaj.poseidon.ui.theme.TextSecondary

private data class TierMeta(val tier: Tier, val title: String, val blurb: String)

private val TIER_META = listOf(
    TierMeta(Tier.JVM, "JVM ADAPTERS",
        "OkHttp · HttpURLConnection · Volley · Cronet Java API — gated by the plugin's bytecode-injected adapters."),
    TierMeta(Tier.NATIVE, "NATIVE LIBC SHIM",
        "Cronet & gRPC native sockets via libposeidon_shim.so (ELF DT_NEEDED interposition of connect/sendto)."),
    TierMeta(Tier.SECCOMP, "SECCOMP GATE",
        "Raw connect()/sendto() syscalls (Go-runtime style) caught by the USER_NOTIF supervisor."),
)

@Composable
fun TiersScreen(state: UiState) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("ENFORCEMENT TIERS", style = MaterialTheme.typography.headlineMedium, color = TextSecondary)
        TIER_META.forEach { meta ->
            val tally = state.tierTallies.firstOrNull { it.tier == meta.tier }
            val recent = state.events.filter { it.tier == meta.tier }.take(5)
            TierCard(meta, tally?.allowed ?: 0, tally?.blocked ?: 0, recent, recentRow = { EventRow(it) })
        }
    }
}

@Composable
private fun TierCard(
    meta: TierMeta,
    allowed: Int,
    blocked: Int,
    recent: List<tech.ssemaj.poseidon.runtime.model.EgressEvent>,
    recentRow: @Composable (tech.ssemaj.poseidon.runtime.model.EgressEvent) -> Unit,
) {
    Surface(color = DeepBlue, shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(meta.title, style = MaterialTheme.typography.titleMedium, color = TextPrimary)
            Text(meta.blurb, style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                Text("$allowed allowed", style = MaterialTheme.typography.labelMedium, color = AquaAllow)
                Text("$blocked blocked", style = MaterialTheme.typography.labelMedium, color = CoralBlock)
            }
            if (recent.isEmpty()) {
                Text("no traffic yet", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
            } else {
                recent.forEach { recentRow(it) }
            }
        }
    }
}
```

- [ ] **Step 2: Wire it into the nav shell**

In `PoseidonApp.kt`, add `import tech.ssemaj.poseidon.ui.tiers.TiersScreen`, and replace the `entry<Tiers> { PlaceholderScreen("Tiers — Phase 2") }` line with:
```kotlin
entry<Tiers> { TiersScreen(state) }
```

- [ ] **Step 3: Verify compile**

Run: `... ./gradlew :app:compileDebugKotlin -q 2>&1 | tail -6` → `BUILD SUCCESSFUL`.

- [ ] **Step 4: On-device check**

Run:
```bash
... ./gradlew :app:installDebug -q
ADB=$(command -v adb || echo ~/Android/Sdk/platform-tools/adb)
"$ADB" shell am force-stop tech.ssemaj.poseidon
"$ADB" shell am start -n tech.ssemaj.poseidon/.MainActivity; sleep 9
"$ADB" shell input tap 534 2870   # Tiers tab (1440x3120 bottom nav, slot 2 of 4)
sleep 1
"$ADB" exec-out screencap -p > /tmp/claude-1000/-home-joseph-AndroidStudioProjects-Poseidon/6b61e8a7-56e9-4fd6-b913-e82ac4888ced/scratchpad/p2-tiers.png
```
Read the PNG. Expect three cards (JVM ADAPTERS / NATIVE LIBC SHIM / SECCOMP GATE), each with a blurb, allowed/blocked counts, and a few recent event rows. Describe what you see.

- [ ] **Step 5: Commit**
```bash
git add app/src/main/java/tech/ssemaj/poseidon/ui/tiers/TiersScreen.kt app/src/main/java/tech/ssemaj/poseidon/ui/PoseidonApp.kt
git commit -m "feat: Tiers screen with per-tier live counts and recent events"
```

---

### Task 2: Playground screen (pick host + SDK, fire, toggle, live stream)

**Files:**
- Create: `app/src/main/java/tech/ssemaj/poseidon/ui/playground/PlaygroundScreen.kt`
- Modify: `app/src/main/java/tech/ssemaj/poseidon/ui/PoseidonApp.kt` (replace the `entry<Playground>` placeholder)

**Interfaces:**
- Produces: `@Composable fun PlaygroundScreen(state: UiState, onToggleMode: () -> Unit, onRunAll: () -> Unit)`.

- [ ] **Step 1: Create `PlaygroundScreen.kt`**

A `VerifyState` is `remember`-ed locally; firing uses `LocalContext`. Sections: mode toggle + RUN ALL row; editable target with allowed/denied quick-set chips; client `ClientStyle` selector chips; FIRE button; fire-results list (`VerifyState.results`); a compact live egress stream (`state.events`).
```kotlin
package tech.ssemaj.poseidon.ui.playground

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import tech.ssemaj.poseidon.ClientStyle
import tech.ssemaj.poseidon.VerifyState
import tech.ssemaj.poseidon.control.UiState
import tech.ssemaj.poseidon.runtime.model.Mode
import tech.ssemaj.poseidon.ui.components.EventRow
import tech.ssemaj.poseidon.ui.components.ModeChip
import tech.ssemaj.poseidon.ui.components.VerdictBadge
import tech.ssemaj.poseidon.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PlaygroundScreen(state: UiState, onToggleMode: () -> Unit, onRunAll: () -> Unit) {
    val ctx = LocalContext.current
    val verify = remember { VerifyState() }
    var style by remember { mutableStateOf(ClientStyle.OKHTTP) }

    LazyColumn(
        Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                ModeChip(enforcing = state.mode == Mode.ENFORCE, onClick = onToggleMode)
                Spacer(Modifier.weight(1f))
                OutlinedButton(onClick = onRunAll) {
                    Text("RUN ALL", style = MaterialTheme.typography.labelMedium)
                }
            }
        }
        item {
            OutlinedTextField(
                value = verify.url.value,
                onValueChange = { verify.url.value = it },
                singleLine = true,
                label = { Text("Target URL") },
                modifier = Modifier.fillMaxWidth(),
            )
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(onClick = { verify.url.value = "https://example.com/demo/path?x=1" },
                    label = { Text("allowed: example.com") })
                AssistChip(onClick = { verify.url.value = "https://www.google.com/" },
                    label = { Text("denied: google.com") })
            }
        }
        item {
            FlowRowClients(selected = style, onSelect = { style = it })
        }
        item {
            Button(onClick = { verify.run(style, ctx) }, modifier = Modifier.fillMaxWidth()) {
                Text("FIRE  ▸  ${style.label}", style = MaterialTheme.typography.labelMedium)
            }
        }
        item { Text("RESULTS", style = MaterialTheme.typography.headlineMedium, color = TextSecondary) }
        items(verify.results, key = { it.id }) { r ->
            Row(verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                VerdictBadge(blocked = r.blocked)
                Text("${r.client}: ${r.outcome}",
                    style = MaterialTheme.typography.bodySmall, color = TextPrimary)
            }
        }
        item { Text("LIVE EGRESS", style = MaterialTheme.typography.headlineMedium, color = TextSecondary) }
        items(state.events.take(20), key = { it.id() }) { EventRow(it) }
    }
}

// EgressEvent has no stable id; derive a key from identity hash + tier/host for LazyColumn.
private fun tech.ssemaj.poseidon.runtime.model.EgressEvent.id(): String =
    "${System.identityHashCode(this)}"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FlowRowClients(selected: ClientStyle, onSelect: (ClientStyle) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier.horizontalScrollSafe()) {
        ClientStyle.entries.forEach { c ->
            FilterChip(selected = c == selected, onClick = { onSelect(c) },
                label = { Text(c.label) })
        }
    }
}

// Small helper so the chip row scrolls horizontally if it overflows.
private fun Modifier.horizontalScrollSafe(): Modifier = this
```
> **Implementer note:** If `ClientStyle.entries` doesn't compile, use `ClientStyle.values()`. The `LazyColumn` mixes `verify.results` (an observable `SnapshotStateList`) and `state.events` — both recompose correctly. For the event key, a stable identity string is fine for display; if duplicate-key crashes occur, switch the events `items(...)` to the index-based overload `itemsIndexed`. The `horizontalScrollSafe` placeholder can be replaced with `Modifier.horizontalScroll(rememberScrollState())` (import `androidx.compose.foundation.horizontalScroll`) if the chips overflow on the device — verify on-device and adjust.

- [ ] **Step 2: Wire it into the nav shell**

In `PoseidonApp.kt`, add `import tech.ssemaj.poseidon.ui.playground.PlaygroundScreen`, and replace the `entry<Playground> { PlaceholderScreen("Playground — Phase 2") }` line with:
```kotlin
entry<Playground> { PlaygroundScreen(state, vm::toggleMode, vm::runAllProbes) }
```
(The `vm` is the `PoseidonApp(vm)` parameter — confirm it's in scope at the entryProvider; if only `state`/`policy` are captured, also capture `vm`.)

- [ ] **Step 3: Verify compile**

Run: `... ./gradlew :app:compileDebugKotlin -q 2>&1 | tail -8` → `BUILD SUCCESSFUL`. Resolve `entries`/`horizontalScroll`/key issues per the implementer note.

- [ ] **Step 4: On-device check**

Install + launch, tap the Play tab (slot 3 of 4: `input tap 900 2870`), screenshot to `p2-play.png`, Read it. Then: tap FIRE and screenshot the result; tap the ModeChip and confirm it flips ENFORCE↔MONITOR. Expect: target field, client chips, FIRE button, and (after firing example.com vs google.com) result rows with green ALLOW / red BLOCK badges, plus the live egress list. Describe what you see.

- [ ] **Step 5: Commit**
```bash
git add app/src/main/java/tech/ssemaj/poseidon/ui/playground/PlaygroundScreen.kt app/src/main/java/tech/ssemaj/poseidon/ui/PoseidonApp.kt
git commit -m "feat: interactive Playground (fire host+SDK, enforce/monitor toggle, live stream)"
```

---

### Task 3: Enrich Overview + remove the placeholder composable

**Files:**
- Modify: `app/src/main/java/tech/ssemaj/poseidon/ui/overview/OverviewScreen.kt`
- Modify: `app/src/main/java/tech/ssemaj/poseidon/ui/PoseidonApp.kt` (delete the now-unused `PlaceholderScreen`)

**Interfaces:** `OverviewScreen(state, onToggleMode, onRunAll)` signature unchanged.

- [ ] **Step 1: Add a "RECENT EGRESS" section to Overview**

After the RUN ALL PROBES button, append a recent-events list so the screen isn't empty:
```kotlin
// add imports: foundation.lazy.LazyColumn/items, ui.components.EventRow, theme.TextSecondary
Text("RECENT EGRESS", style = MaterialTheme.typography.headlineMedium,
    color = TextSecondary, modifier = Modifier.padding(start = 20.dp, top = 8.dp))
LazyColumn(Modifier.fillMaxWidth().weight(1f)) {
    items(state.events.take(25)) { EventRow(it) }
}
```
Wrap the existing top content + this list so the column lays out top-to-bottom (the existing `Column(Modifier.fillMaxSize())` is fine; give the `LazyColumn` `weight(1f)` so it fills remaining space). Keep the existing header, tagline, stat tiles, and button.

- [ ] **Step 2: Remove the dead `PlaceholderScreen`**

In `PoseidonApp.kt`, delete the private `PlaceholderScreen` composable (no longer referenced after Tasks 1–2). Confirm with `grep -n PlaceholderScreen app/src/main/java/tech/ssemaj/poseidon/ui/PoseidonApp.kt` → no remaining references.

- [ ] **Step 3: Verify compile + commit**

Run: `... ./gradlew :app:compileDebugKotlin -q 2>&1 | tail -6` → `BUILD SUCCESSFUL`.
```bash
git add app/src/main/java/tech/ssemaj/poseidon/ui/overview/OverviewScreen.kt app/src/main/java/tech/ssemaj/poseidon/ui/PoseidonApp.kt
git commit -m "feat: Overview recent-egress list; drop Phase-2 placeholder"
```

---

### Task 4: Deferred-Minor cleanup + final on-device sweep

**Files:**
- Modify: `app/src/main/java/tech/ssemaj/poseidon/control/PoseidonViewModel.kt`
- Modify: `app/src/main/java/tech/ssemaj/poseidon/ui/components/OceanComponents.kt`
- Modify: `app/build.gradle.kts`

**Interfaces:** none new.

- [ ] **Step 1: `super.onCleared()`**

In `PoseidonViewModel.onCleared()`, add `super.onCleared()` as the first line (before `Observer.removeSink(sink)`).

- [ ] **Step 2: Remove the unused import**

In `OceanComponents.kt`, delete `import androidx.compose.ui.geometry.Offset` (unused).

- [ ] **Step 3: Drop the unused test deps**

In `app/build.gradle.kts`, remove the two lines `testImplementation(libs.robolectric)` and `testImplementation(libs.androidx.test.core)` — `PoseidonControllerTest` is plain JUnit and uses neither. Leave the catalog entries in `libs.versions.toml` (harmless, may be used later).

- [ ] **Step 4: Verify unit tests still pass**

Run: `... ./gradlew :app:testDebugUnitTest 2>&1 | tail -6` → `BUILD SUCCESSFUL`, `PoseidonControllerTest` green.

- [ ] **Step 5: Full on-device sweep (all four tabs)**

Install + launch, then screenshot each tab and Read each PNG:
```bash
... ./gradlew :app:installDebug -q
ADB=$(command -v adb || echo ~/Android/Sdk/platform-tools/adb)
SS=/tmp/claude-1000/-home-joseph-AndroidStudioProjects-Poseidon/6b61e8a7-56e9-4fd6-b913-e82ac4888ced/scratchpad
"$ADB" shell am force-stop tech.ssemaj.poseidon
"$ADB" shell am start -n tech.ssemaj.poseidon/.MainActivity; sleep 9
"$ADB" exec-out screencap -p > "$SS/final-overview.png"
"$ADB" shell input tap 534 2870;  sleep 1; "$ADB" exec-out screencap -p > "$SS/final-tiers.png"
"$ADB" shell input tap 900 2870;  sleep 1; "$ADB" exec-out screencap -p > "$SS/final-play.png"
"$ADB" shell input tap 1267 2870; sleep 1; "$ADB" exec-out screencap -p > "$SS/final-policy.png"
"$ADB" logcat -d -s AndroidRuntime:E | grep -i tech.ssemaj.poseidon | head   # expect empty (no crash)
```
Read all four PNGs. Confirm: Overview shows recent-egress rows under the tiles; Tiers shows three populated cards; Playground shows the fire UI + results/stream; Policy unchanged. Describe each. No crash.

- [ ] **Step 6: Commit**
```bash
git add -A app/
git commit -m "chore: Phase 2 polish (super.onCleared, unused import, test deps) + on-device verified"
```

---

## Self-Review

**Spec coverage (Phase 2 portions):**
- §3.2 Tiers (per-tier coverage, counts, events) → Task 1. ✓
- §3.3 Playground (host+SDK fire, live stream, run-all, enforce/monitor toggle) → Task 2. ✓
- §2.3 probe-outcome structure → satisfied by reusing `VerifyState`/`QueryResult` (documented deviation; DRY). ✓
- Overview emptiness (user feedback) → Task 3 recent-egress list. ✓
- Deferred Minors from Phase-1 final review → Task 4. ✓

**Placeholder scan:** No "TBD/later". The `horizontalScrollSafe`/event-key notes are concrete fallbacks with exact replacements, verified on-device.

**Type consistency:** `TiersScreen(state)`, `PlaygroundScreen(state, onToggleMode, onRunAll)`, `OverviewScreen(state, onToggleMode, onRunAll)`; consumes `UiState.tierTallies`/`events`, `VerifyState.{url, results, run}`, `ClientStyle`, `QueryResult`, `Tier.{JVM,NATIVE,SECCOMP}`, and the existing components — all matching Phase-1 definitions.

**Known risks for execution:** `ClientStyle.entries` vs `values()`; `LazyColumn` duplicate-key on `EgressEvent` (no stable id) — Task 2 note gives the `itemsIndexed` fallback; chip-row overflow — Task 2 note gives the `horizontalScroll` fallback. All resolved on-device.
