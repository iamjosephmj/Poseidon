# Poseidon — Network Safeguard for Integrated SDKs

**Status:** Design (validated via spike)
**Date:** 2026-06-24
**Owner:** iamjosephmj

## 1. Overview

Poseidon is a **reusable Gradle plugin + runtime** that enforces a network allow-list/deny-list over the traffic that integrated third-party SDKs send to servers. It lets an app team **observe, allow, block, or reroute** outbound connections — including those originating from **native (C/C++) SDK code** such as Cronet or WebRTC — using **build-time transformation**, with no runtime hooking and no VPN.

The headline capability, validated on real hardware: a third-party SDK's native `.so` is rewritten at build time so its libc network calls route through a Poseidon policy gate at runtime.

## 2. Goals / Non-Goals

**Goals**
- Global host-level enforcement (allow / block / reroute) across JVM *and* native SDK code.
- Path-level deny-list for JVM HTTP clients (plaintext, above TLS).
- Per-host rules (allow-list semantics); per-path rules (deny-list semantics).
- `MONITOR` mode (log what *would* happen) and `ENFORCE` mode, selectable per build type.
- Play-safe: no runtime PLT/inline hooking of system libraries, no VPN consent prompt, no TLS MITM.
- Reusable across apps: a plugin other teams apply, configured via DSL + optional YAML.

**Non-Goals**
- Decrypting HTTPS payloads (no MITM).
- Catching traffic from code that bypasses libc (Go runtimes, raw `syscall()`), or path-level visibility for statically-linked native TLS — see §9.
- Per-SDK attribution at the socket level (global host rules only; the build-time origin is known per native lib but rules are host/path keyed).

## 3. Architecture

Three modules:

| Module | Type | Responsibility |
|--------|------|----------------|
| `:poseidon-gradle-plugin` | AGP plugin (JVM) | Read DSL + YAML → compiled policy; **ELF-interpose every native `.so`** (merged native libs transform); inject the JVM socket gate + path interceptor; static-audit native libs; wire auto-init |
| `:poseidon-runtime` | Android library | The native shim (`libposeidon_shim.so`), JVM socket gate, path interceptor, policy engine, async observability sink, auto-init |
| `:app` | existing app | Proving ground / demo |

## 4. Native interposition (primary mechanism — validated)

### 4.1 How
At build time, for **every** native `.so` in the merged native libs (configurable include/exclude), inject `libposeidon_shim.so` as the **first `DT_NEEDED`** entry (ELF edit via LIEF or equivalent). The bionic dynamic linker then resolves that lib's libc network imports to the shim. The shim runs host policy, then:
- **allow** → tail-call the real libc function (`dlsym(RTLD_NEXT, …)`),
- **reroute** → rewrite the `sockaddr` before calling real,
- **block** → return `-1` / `errno = ECONNREFUSED`.

This is build-time assembly of the app's own binaries — no runtime memory patching, no system-lib modification, no LD_PRELOAD.

### 4.2 Interposed entry points (full libc network surface)
`connect`, `sendto`, `sendmsg`, `sendmmsg`, `getaddrinfo`, `android_getaddrinfofornet` — covering TCP, UDP/QUIC, and DNS. All exported at version node **`LIBC`** (via version script) so they satisfy SDKs' versioned imports (e.g. Cronet's `connect@LIBC`).

### 4.3 Mandatory safety rules (discovered during the spike — non-negotiable)
1. **Reentrancy guard:** a thread-local flag; if already inside an interceptor, pass straight through. Without it, the shim's own logging path (liblog → `sendto`/`connect` to logd) recurses infinitely → stack overflow.
2. **Log-free / lock-free / allocation-free hot path:** the interceptor must NOT call `__android_log_print` (or anything that takes a lock / does I/O) synchronously. On some Android versions liblog's init connects to logd under a lock and **deadlocks** when re-entered from the connect path. Observability must be pushed to an **off-hot-path async sink** (lock-free ring buffer drained by a dedicated thread, or a pipe to a logger thread).

### 4.4 Init
Ship the prebuilt shim per ABI. The shim needs no explicit init for interposition (it activates via the injected `DT_NEEDED`). Policy table + observer config are loaded by the runtime's auto-initializer (androidx.startup / ContentProvider) early in process start.

## 5. Path layer — at the HTTP-client *API*, not the native/libc layer

Path/URL for HTTPS exists in plaintext only *above* TLS. The libc/native layer sees only ciphertext (verified: `SSL_write` is internal with no `.symtab`; `SSLKEYLOGFILE` is ignored by Cronet embedded). The correct place for path is therefore the **HTTP client's Java/Kotlin API**, where the URL is a plain argument *before* it reaches TLS.

- **Path deny-list (build-time bytecode transform):** inject an interceptor at each HTTP client's API surface — OkHttp (`Interceptor`), `HttpURLConnection`, Ktor (engine plugin), Volley, and **Cronet** (`newUrlRequestBuilder(url, …)` / `RequestFinishedInfo` / NetLog — *verified: full plaintext URL+path captured*). Evaluate the path deny-list (capture path, strip query), block denied endpoints. Crucially, **Cronet is native underneath but driven from Java, so it folds into this layer** — its URL is visible at the API boundary.
- **Host socket gate (runtime, optional):** native interposition already covers JVM sockets at libc, so a JVM `SSLSocketFactory` gate is at most a secondary path — see Open Questions.

## 6. Policy engine & configuration

- **Host rules = allow-list** (default deny; only sanctioned hosts reachable). Actions: `allow` / `block` / `reroute(host,port)`. Wildcards (`*.example.com`).
- **Path rules = deny-list** (default allow; block listed endpoints on otherwise-allowed hosts).
- **Modes:** `ENFORCE` / `MONITOR`, per build type via DSL.
- **Config:** primary Gradle DSL (`poseidon { … }`); optional checked-in `poseidon-policy.yml` merged at build time. Compiled into a policy table the native shim and JVM layer both read.

## 7. Observability

Every decision emits an event `{ timestamp, host/ip, port, sni?, transport, path?, action, mode, originating-lib }` to a pluggable sink. Default sink logs (off the hot path); apps can register a callback. Native events cross to the runtime via the async ring buffer.

## 8. Static audit (build-time)

Scan every native `.so` for embedded domains/URLs and report which dependencies ship native net code (`libcronet`, `libjingle_peerconnection_so`, bundled BoringSSL, etc.). This makes even un-enforceable code (Go/raw-syscall, static TLS) **visible** rather than silent.

## 9. Coverage envelope & documented gaps

**Covered:** host allow/block/reroute for any native or JVM code that reaches the network through libc (TCP/UDP/QUIC + DNS); path deny-list for JVM HTTP clients.

**Not covered (inherent, must be documented + surfaced by the audit):**
- **Go runtimes / raw `syscall()`** — bypass libc entirely (demonstrated). Not interposable.
- **Native HTTP path for bare-native clients** — an HTTP client implemented *and driven* entirely in native code (no Java API) over statically-linked BoringSSL. Path exists only at internal `SSL_write` (verified internal, stripped from `.symtab`; `SSLKEYLOGFILE` ignored by Cronet). The *only* route is signature-located `SSL_write` inline-hooking (runtime, fragile per BoringSSL version, Play-risk) — offered as an opt-in module, not core. NOTE: native HTTP stacks with a Java API (Cronet) are NOT in this gap — their path is captured at the API layer (§5).
- **`dlsym`-resolved imports** — a lib resolving `connect` via `dlsym` at runtime would need `dlsym` interposition too (not observed in Cronet/WebRTC).
- **HTTPS payload** — never (no MITM by design).

## 10. Build pipeline

1. Resolve DSL + YAML → validate → generate compiled policy.
2. AGP transform over **merged native libs**: for each `.so` (minus excludes), inject the shim `DT_NEEDED`; bundle the per-ABI shim.
3. Bytecode transform: inject the JVM path interceptor.
4. Static audit task: emit native-domain report.
5. Auto-init wiring (manifest/startup provider).

(Spike used a manual APK rewrite: unzip → LIEF inject → `zipalign` → `apksigner`. Productizing as an AGP artifact transform over `MERGED_NATIVE_LIBS` is implementation task #1.)

## 11. Testing

- **Policy engine:** JVM unit tests (wildcard match, rule order, default action, reroute).
- **Shim:** native tests for reentrancy guard, versioned-symbol export, each interposed call; on-device instrumented test (allow/block/reroute).
- **Plugin:** Gradle TestKit — DSL+YAML → policy correct, every native `.so` injected, manifest wired.
- **App:** instrumented tests asserting allowed host connects, blocked host fails, reroute lands on substitute, monitor never blocks — across a JVM client and a native lib.

## 12. Validation evidence (spike, 2026-06-24, Pixel 6 Pro + x86_64 emulator)

- ELF `DT_NEEDED` interposition beats globally-loaded bionic libc; survives AGP packaging; works inside a real Zygote-loaded app.
- **Real Cronet 143** (versioned `@LIBC`, full RELRO): `connect` + `getaddrinfo` + `sendmsg` intercepted; **block** → `net::ERR_CONNECTION_REFUSED`.
- **Real WebRTC 144** (different vendor): `getaddrinfo(stun…)` + `sendto`(STUN UDP) intercepted. Two unrelated stacks, generic by-file injection.
- Versioned shim (`connect@@LIBC` …) binds SDK versioned imports.
- Raw-`syscall()` target bypasses (gap confirmed).
- Reentrancy guard + log-free hot path required (root-caused a liblog deadlock on Android 9 x86_64; mechanism itself ABI-portable).

## 13. Open questions

- Whether to keep the JVM socket gate (host) at all, given native interposition already covers JVM sockets at libc — or use the native layer for all host enforcement and JVM only for path.
- Async sink design (ring buffer vs pipe) and event schema for crossing native→JVM.
- Exact AGP API for transforming merged native libs in AGP 9 (artifact type / task wiring).
- Versioned-symbol binding validated on Android 16 + API 28; sample a mid-range OS version.

## 14. Implementation milestones

1. AGP transform over merged native libs (replace manual APK rewrite) + per-ABI shim packaging.
2. Production shim: full syscall set, reentrancy guard, lock-free async event ring buffer (no liblog on hot path).
3. Policy engine + compiled policy generation (DSL + YAML).
4. JVM path-deny bytecode transform (OkHttp/HttpURLConnection/Ktor).
5. Static native-domain audit task.
6. Observability sink + app-facing callback API.
7. End-to-end tests across JVM + native.
