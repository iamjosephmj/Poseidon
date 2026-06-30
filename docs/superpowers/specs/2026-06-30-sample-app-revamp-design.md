# Poseidon Sample App Revamp — Design

**Date:** 2026-06-30
**Status:** Approved (pending spec review)
**Scope:** The `:app` sample module only. No changes to `poseidon-core`, `poseidon-native`,
`poseidon-seccomp`, `poseidon-all`, or `poseidon-gradle-plugin`. The app consumes the
published `poseidon-all` JitPack artifact and only uses its **public** runtime APIs.

## 1. Goal & Audience

Revamp the Poseidon sample app into a **showpiece for prospective evaluators** — people
deciding whether to adopt Poseidon. It must, at a glance, make the thesis obvious and
provable: *Poseidon blocks network egress by default across three independent enforcement
tiers, and you can watch it happen live.*

Four motivations, all in scope:
1. **Visual/UX overhaul** — deep-ocean "Poseidon" brand, showpiece quality.
2. **Restructure the code** — break the 693-line `MainActivity` into focused screens/components.
3. **Showcase the tiers/probes** — JVM adapters, native libc shim, seccomp gate, and every
   probe (including the new MMKV zero-egress control and gRPC-over-Cronet native block).
4. **Interactive playground** — pick host + SDK and fire, a live event stream, a run-all
   "attack" button, and a runtime enforce/monitor toggle.

## 2. Architecture

**Navigation 3 + a single `PoseidonController` + ViewModel/StateFlow, stateless screens.**

The `PoseidonController` is the one seam to the Poseidon runtime. Screens render `StateFlow`
and call the ViewModel; they never touch runtime internals directly.

```
Probe fire ─▶ real network attempt ─▶ Poseidon enforces at its tier
                                          │
                              EgressEvent recorded
                                          │
                                  Observer sink (Observer.addSink)
                                          │
                          PoseidonController  ──StateFlow──▶  PoseidonViewModel ──▶ all screens
                                          ▲                                         (stream, tallies,
                          Mode.current / NativeBridge.apply                          fired-request verdict)
```

### 2.1 `control/PoseidonController.kt`
A process singleton holding the live runtime state and the seam to Poseidon.
- **Reads** compiled policy from `assets/poseidon/policy.json` (reuse existing `PolicyInfo.load`)
  → mode, allowed hosts, denied paths, CIDRs.
- **Registers** an `Observer` sink → maintains a capped, newest-first `List<EgressEvent>`
  and per-`Tier` allow/block tallies, exposed as `StateFlow`.
- **`setMode(Mode)`** — flips enforcement at runtime using **public** APIs:
  - `Mode.current = ENFORCE|MONITOR` (JVM tier gate, `ModeGate.shouldBlock`).
  - `NativeBridge.apply(allowedHosts, enforce = mode == ENFORCE)` (native libc shim tier).
  - Seccomp: re-evaluate `NativeBridge.installSeccompGate(...)`; the gate may remain installed
    under monitor for DNS correlation — surface the *truthful* behavior, do not overclaim.
- **`fire(target, client): ProbeOutcome`** — runs one probe via `ProbeCatalog`, returns the
  probe's raw outcome (HTTP code / exception / errno) for an exact verdict card.
- **`runAll()`** — fires the full target×client matrix.

### 2.2 `control/PoseidonViewModel.kt` + `control/UiState.kt`
Exposes immutable `UiState` (`StateFlow`) to Compose: effective mode, totals (allowed/blocked),
per-tier tallies, the live event list, and the last fire result. Stateless screens observe it.

### 2.3 `probes/` refactor → `ProbeCatalog` + `ProbeOutcome`
Today's probes log to Logcat only. Refactor each into a `Probe` that performs the same network
call but **returns a structured `ProbeOutcome`** (verdict, tier, reason, raw result, latency).
Preserve all current network logic and the MMKV / gRPC-Cronet work. `ProbeCatalog` enumerates
the available `{target × client}` combinations the Playground offers. The existing
`DemoProbes.runAll` becomes a thin wrapper over `ProbeCatalog`.

## 3. Screens (bottom nav, Navigation 3)

### 3.1 Overview — the pitch
Trident hero over a deep-navy→teal gradient with live `WaveBackground` motion. A **ModeChip**
(tap → toggle Enforce/Monitor). A large "Egress Guarded" stat: **allowed (AquaAllow/cyan) vs
blocked (CoralBlock/coral)** totals. A one-tap **"Run all probes"** CTA that animates the
blocked tally climbing — the "everything got stopped" moment. Three tier chips deep-link to Tiers.

### 3.2 Tiers
Three cards — **JVM adapters · Native libc shim · Seccomp gate**. Each shows: what it covers,
which SDKs/probes feed it (incl. MMKV zero-egress control + gRPC-Cronet native block), live
allow/block counts, and that tier's recent events.

### 3.3 Playground
- **Target** selector: allow-listed `example.com` vs denied hosts (`grpc.googleapis.com`,
  `www.google.com`, custom entry).
- **Client** selector: OkHttp · HttpURLConnection · Volley · Cronet · gRPC-Cronet · raw syscall.
- **Fire** → `VerdictBadge` card: ALLOWED/BLOCKED, **which tier**, reason, latency.
- Prominent **Enforce/Monitor toggle**, a **Run-all "attack"** button.
- Live **event stream** below (newest first), ocean-themed `EventRow`s.

### 3.4 Policy
The active compiled policy (mode, allow-hosts, deny-paths, CIDRs) from `policy.json`, with the
honest note that **deny-path is JVM/HTTP-only** (TLS hides paths from the native/Go tiers).

## 4. Theme (deep-ocean Poseidon brand)
Extend the existing `ui/theme/Color.kt` tokens (`AbyssalNavy`, `BioluminescentTeal`,
`TridentGold`, `AquaAllow`, `CoralBlock`, `TextPrimary/Secondary`). Dark-first showcase.
New reusable components in `ui/components/`: `WaveBackground`, `TridentHeader`, `ModeChip`,
`VerdictBadge`, `StatTile`, `EventRow`, `TierCard`. Material 3 `colorScheme` driven by the tokens.

## 5. File Layout (after restructure)
```
app/src/main/java/tech/ssemaj/poseidon/
  MainActivity.kt                 (~30 lines: theme + PoseidonApp())
  ui/
    PoseidonApp.kt                (Scaffold + bottom nav + gradient/wave backdrop)
    theme/                        (Color.kt extended, Theme.kt, Type.kt)
    overview/OverviewScreen.kt
    tiers/TiersScreen.kt
    playground/PlaygroundScreen.kt
    policy/PolicyScreen.kt
    components/                   (WaveBackground, TridentHeader, ModeChip, VerdictBadge,
                                   StatTile, EventRow, TierCard)
  control/
    PoseidonController.kt
    PoseidonViewModel.kt
    UiState.kt
  probes/
    ProbeCatalog.kt               (enumerates target×client combos)
    ProbeOutcome.kt
    ... existing probes refactored to return ProbeOutcome
```

## 6. Mode Toggle — feasibility & honesty
Verified feasible against the **published** artifact with **no library change**:
- `Mode.current` — public `@JvmStatic @Volatile var` (JVM tier).
- `NativeBridge.apply(hosts, enforce)` and `NativeBridge.installSeccompGate(...)` — public
  (`object NativeBridge`), drive the native + seccomp tiers.

Honesty rules carried into the UI (consistent with the project's stated guarantee limits):
- Monitor = "would-block, logged only"; re-fire shows the same request recorded but not blocked.
- The UI never claims an absolute egress guarantee. It states it is a strict default-deny
  posture with known holes (exfil-via-allowed-host, TLS payload, adversarial evasion).
- Deny-path enforcement is labeled JVM/HTTP-only.

## 7. Phasing
- **Phase 1 (visual + structure):** theme + `PoseidonApp` nav shell + Overview + Policy +
  the full restructure (controller/ViewModel/probe refactor scaffolding). Independently
  runnable on-device.
- **Phase 2 (interactivity):** Tiers + Playground + live enforce/monitor toggle + run-all.

Each phase ends with an on-device run on the connected device.

## 8. Testing
- **Keep** the existing on-device probe tests: `MmkvInterpositionTest`, `GrpcCronetBlockTest`.
- **Add** `PoseidonController`/ViewModel unit tests with a fake runtime seam: mode-toggle
  transitions, tally/aggregation logic, event-stream capping, fired-request→verdict correlation.
- Screenshot tests of the new screens — optional stretch (via the `testing-setup` skill).

## 9. New Dependency
Navigation 3 libraries (wired via the `navigation-3` skill). No other new runtime deps;
MMKV and gRPC-Cronet from prior work remain.

## 10. Out of Scope / YAGNI
- No changes to Poseidon library/plugin modules.
- No persistence/history beyond the in-memory capped event list.
- No remote config or networked telemetry from the demo itself.
- MVI/reducer frameworks — plain ViewModel + StateFlow only.
