# Poseidon — Re-architecture Design (2026-06-25)

A clean re-foundation of Poseidon: a build-time + runtime library that constrains the
network egress of integrated third-party SDKs to a declared host allow-list (+ path
deny-list), with audit (monitor) and enforcement as co-equal modes.

This spec supersedes the organic prototype design
(`2026-06-24-poseidon-network-guard-design.md`). The prototype proved every mechanism
on-device; this re-architecture keeps the proven mechanisms but re-founds them on a
clean, decoupled pipeline with a manifest-first configuration surface.

---

## 1. Purpose & goals

**Purpose:** let an app author declare which hosts its third-party SDKs may reach, see
exactly what each SDK actually reaches (per-library), and optionally block anything
off the list — across JVM, native, and Go/raw-syscall code, in-process, no VPN, no
root.

**Goals (in priority order):**
1. **Audit and enforce are co-equal first-class modes.** Monitor produces a per-SDK
   egress map; enforce additionally blocks. Same pipeline.
2. **Manifest-first configuration** — the allow-list is declared in the manifest
   (app-authoritative), libraries may *propose* their needs, the build compiles and
   reports. Credible, reviewable, mergeable.
3. **Layered packaging** — a safe JVM-only core, with native and Go/seccomp coverage as
   opt-in modules carrying their own cost/risk.
4. **Clean separation** — interceptors capture, one engine decides, one sink audits,
   one enforcer blocks. Each unit small and independently testable.

**Non-goals (explicit):**
- Not a security boundary against a *hostile* SDK at the same privilege (it can tamper
  with in-process state; see §9). Poseidon constrains *non-adversarial* SDKs + audits.
- No TLS payload inspection (no MITM). Destination control only — cannot stop
  exfiltration *through* an allow-listed host.
- Does not make the OS enforce anything. The manifest declaration is **Poseidon-enforced,
  not platform-enforced**; must never be presented as extending the INTERNET permission.

---

## 2. Module architecture (core + opt-in tiers)

| Module | Contents | Risk/cost | Required? |
|---|---|---|---|
| **`poseidon-core`** | manifest policy loader, `PolicyEngine`, `EgressEvent`, `Observer`, `Enforcer`, **JVM bytecode interception** | none (no binary mod) | yes |
| **`poseidon-native`** | ELF `DT_NEEDED` injector (Gradle) + libc shim (`connect`/`sendto`/…) + per-`.so` attribution | binary modification → licensing/Play posture | opt-in |
| **`poseidon-seccomp`** | kernel `USER_NOTIF` gate for Go/raw-syscall + raw-DNS correlation | per-connection/datagram cost; kernel ≥5.0 | opt-in |
| **`poseidon-gradle-plugin`** | manifest→compiled-policy, bytecode transform registration, native-inject task wiring | — | yes |
| **`poseidon-all`** | umbrella artifact depending on core+native+seccomp | — | convenience |

Rationale: native and seccomp are the parts with cost, Play uncertainty, and licensing
questions. The credible, universal JVM+manifest story must stand alone and Play-clean;
power users layer up.

---

## 3. Core pipeline

```
manifest (+ merged library proposals)
    │  poseidon-gradle-plugin compiles (app-authoritative; lib decls = proposals)
    ▼
compiled policy ──startup──► PolicyEngine (canonical) ──mirror(JNI)──► native evaluator (opt-in)

Interceptor ─emit→ EgressEvent ─→ PolicyEngine.evaluate ─→ Decision
                                            ├─ ALWAYS ───────────────→ Observer.record   (AUDIT, both modes)
                                            └─ if BLOCK & ENFORCE ───→ Enforcer.block
```

**Units & single responsibilities:**
- **Interceptors** — observe traffic, emit a normalized `EgressEvent`, apply the
  returned action. Know nothing about policy rules or sinks. (Dumb producers — this is
  the fix for the prototype's per-adapter policy sprawl.)
- **PolicyEngine** — the only decision-maker: `evaluate(event) → Decision`.
- **Observer** — the only audit output: `record(event, decision)`. Async, never blocks.
- **Enforcer** — apply a BLOCK per transport. Knows nothing about why.
- **PolicyLoader** — compiled policy → PolicyEngine (+ push mirror to native).

**Invariants:**
1. Interceptors never decide; PolicyEngine never captures; Observer never blocks;
   Enforcer never explains.
2. Observer is async/lock-free (drained off the hot path).
3. Path enforcement is JVM-only (only tier above TLS with the URL); host enforcement is
   every tier.
4. One policy object; JVM and native evaluators are proven equivalent by shared test
   vectors.
5. Audit runs in **both** modes; enforce only *adds* the block. Monitor = enforce minus
   the final action.

---

## 4. `EgressEvent` (the keystone — source-agnostic)

```
EgressEvent {
  ts: long, tid: int                     // ordering + thread (cheap)
  host: String?                          // hostname if known (DNS correlation; null for raw IP)
  ip: String?                            // peer IP if known
  port: int
  transport: TCP | UDP | DNS
  path: String?                          // request path — JVM tier ONLY (above TLS)
  tier: JVM | NATIVE | SECCOMP
  originToken: long|Object               // RAW + cheap: native return-address OR lightweight Java stack ref
  decision: Decision?                    // filled by PolicyEngine
}

Decision { action: ALLOW | BLOCK, matchedRule: String?, reason: String }
```

- **`originToken` is captured cheaply and symbolized off-thread** by the Observer drain
  (dladdr for native → `libcronet.so`; stack walk for JVM → `com.foo.Sdk`). No
  symbolization on the connection hot path.
- The engine, sink, and enforcer never branch on `tier` — fully decoupled.

---

## 5. PolicyEngine — one policy, two equivalent evaluators

- Holds compiled policy: `allowedHosts` (globs, **default-deny**), `deniedPaths`
  (globs, **default-allow**), `mode` (MONITOR | ENFORCE).
- **Host:** allow iff `host` matches an allow glob, or `ip` maps (via the correlation
  cache) to an allowed host. Otherwise BLOCK (enforce) / record-violation (monitor).
- **Path:** BLOCK iff `path` matches a deny glob (JVM tier only).
- **Canonical in JVM; mirrored into native.** Native tiers cannot call back into the
  JVM on the hot path (JNI-per-connect + reentrancy). They get a compiled mirror + a C
  evaluator with **identical glob semantics**, guaranteed by a shared test-vector suite
  run against both evaluators in CI.

---

## 6. Native ↔ JVM bridge

- **Policy mirror:** JVM serializes the compiled policy and pushes via JNI
  `configure(blob)`; native parses into mirror structs behind a **double-buffer +
  atomic swap** (lock-free hot-path reads; atomic policy updates).
- **Enforcement is native-local** — `connect`/`sendto`/seccomp evaluate the mirror and
  block inline. No JNI/callback on the hot path.
- **Audit is async** — interceptors push compact events into a **lock-free ring in
  native memory**; a JVM drain thread reads, symbolizes `originToken`, and feeds the one
  `Observer`. Native + JVM events land in the same unified audit map.
- One line: **native owns fast local enforcement (mirror); JVM owns canonical policy +
  unified audit.**

---

## 7. Configuration — manifest-first, app-authoritative

**App declares the authoritative policy** (NSC-style, merger-safe `<meta-data>` →
XML resource):
```xml
<meta-data android:name="tech.ssemaj.poseidon.policy"
           android:resource="@xml/poseidon_policy"/>
```
```xml
<poseidon mode="enforce">          <!-- or "monitor" -->
  <allow host="example.com"/>
  <allow host="*.api.foo.com"/>
  <deny-path pattern="/internal/*"/>
</poseidon>
```

**Libraries propose** their needs in *their* manifests:
```xml
<meta-data android:name="tech.ssemaj.poseidon.proposes"
           android:resource="@xml/poseidon_proposes"/>   <!-- carried up by manifest merge -->
```

**Plugin compiles the merged manifest →**
- app-authoritative allow-list = **enforced**;
- library proposals = **recorded with package attribution, NOT granted** unless the app
  explicitly approves (`<approve library="…"/>` or a plugin `acceptProposals` opt-in,
  default false);
- output: compiled policy blob in `assets/poseidon/policy.bin` **+ a human-readable
  build report** (effective allow-list + every proposal) — the audit/CI artifact.

**CI gate knob:** unapproved proposals → `warn` (default) or `error` (fail the build) —
the "enforce the audit" lever.

**DSL override (optional):** a thin Gradle DSL may override/augment for
CI-injected/per-flavor/computed allow-lists. Manifest is canonical; DSL is the escape
hatch.

---

## 8. Enforcement & startup

- **Startup:** `PoseidonInitializer` (androidx.startup, in core's manifest — zero app
  code) loads `assets/poseidon/policy.bin` → builds PolicyEngine → if native/seccomp
  present, pushes the mirror and installs the gate as early as possible.
- **JVM enforcement:** bytecode adapters (OkHttp interceptor entry-inject; HttpURLConnection
  /Cronet call-site rewrite; Volley) build an `EgressEvent` (host+path+Java caller) →
  evaluate → block (cancel/`IOException`) on BLOCK+ENFORCE; always record.
- **Native enforcement (opt-in):** libc shim wrappers + DNS deny by name; strict
  default-deny; per-`.so` attribution via return address.
- **Seccomp enforcement (opt-in):** TOCTOU-safe `connect` (emulate, no CONTINUE),
  connectionless UDP (`sendto`/`sendmsg`/`sendmmsg`), `io_uring_setup` denied,
  raw-DNS correlation. Kernel ≥5.0; graceful degradation otherwise.
- **Pre-package, no re-sign:** native injection runs post-strip / pre-package on both
  APK and AAB paths; AGP signs once afterward.

---

## 9. Honest limits (carried forward, by design)

- **Exfiltration through an allow-listed host** — destination-based control cannot stop
  it; no payload inspection.
- **Hostile same-privilege SDK** — can tamper with in-process state (overwrite the
  mirror/flag), or spawn threads before the filter installs. In-process is **not a
  security boundary** against adversarial code — only kernel/MDM/network is. (Specific
  tricks closed: io_uring denied, connect TOCTOU-safe.)
- **Kernels < 5.0** — no seccomp `USER_NOTIF`; Go/raw ungated there (libc+DNS still
  enforce for libc code).
- **DoH/DoT** — hides the name from correlation/logs; the connect to the resolved IP is
  still gated. ECH will hide SNI.
- **Strict-by-IP CDN over-block** — mitigated by JVM cache-seeding; residual on rotating
  CDNs for platform-resolver clients.

Positioning: **strong default-deny egress control + per-SDK audit for non-adversarial
SDKs.** Not a guarantee against a hostile SDK or exfil via permitted destinations.

---

## 10. Testing strategy

- **Policy equivalence:** shared glob test-vector suite run against both the JVM and
  native evaluators (CI-enforced equivalence).
- **Per-tier interception:** on-device instrumented tests per client family
  (OkHttp/HUC/Volley/Cronet/native/Go-raw) asserting allow + block + audit-record, in
  both modes.
- **Manifest compile:** plugin unit tests for app-authoritative + library-proposal
  merge, approval gating, and the warn/error CI knob.
- **Bridge:** native event ring → JVM Observer round-trip; atomic policy swap under load.
- **Reuse the prototype's proven probes** as the on-device acceptance suite.

---

## 11. Migration from the prototype

Keep the proven mechanisms (ELF injector, libc shim, seccomp gate, DNS correlation,
`.so` attribution); re-home them behind the clean interfaces above (interceptors emit
`EgressEvent`; all policy logic moves into `PolicyEngine`; all output into `Observer`).
Split the single `poseidon-runtime` into `poseidon-core` / `poseidon-native` /
`poseidon-seccomp`. Replace DSL-primary config with manifest-primary. The current code
stays as reference until each piece is re-homed and re-verified on-device.
