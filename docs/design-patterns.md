# Design Patterns in Poseidon

An honest map of the [GoF patterns](https://github.com/iamjosephmj/kotlin-design-patterns)
onto Poseidon. The guiding rule is **YAGNI**: Poseidon uses the patterns its domain
naturally calls for and deliberately *avoids* the rest — adding patterns for their own
sake would fight the single-responsibility/readability goals of the codebase.

Each pattern-bearing class carries a one-line `Pattern: …` KDoc so the architecture is
self-documenting at the source.

## Already embodied (the architecture *is* these)

| Pattern | Where | Notes |
|---|---|---|
| **Adapter** | `PoseidonOkHttp`, `PoseidonInterceptor`, `PoseidonHttpUrl`, `PoseidonVolley`, `PoseidonCronet`; `NativeShimBackend` | Each HTTP client (and the native shim) is adapted to one uniform gate. The core architectural idea. |
| **Bridge** | `NativeBridge` (+ `NativeBridge.Backend`) | Decouples core's policy push from its implementation (`NativeShimBackend` real / no-op default), swapped via `register()`. Keeps core Play-clean without native code. |
| **Observer** | `Observer` (`record`/`addSink`/`setSink`/`removeSink`) | The audit subject; observers receive a normalized `EgressEvent`. Native events arrive via the ring drain. Multi-observer, copy-on-write, per-observer try/catch. |
| **Facade** | `PoseidonGate` (`shouldBlock`); `PolicyInstaller`; `PoseidonAll`/`PoseidonSeccomp` | One entry point hides the `PolicyEngine` + `Observer` + `ModeGate` + `HostIpCacheSeeder` pipeline. |
| **Proxy** | the native shim (`interpose.c` libc wrappers, seccomp connect emulation); `PoseidonHttpUrl.open` | Protection proxy: check policy, then forward (`RTLD_NEXT` / `URL.openConnection`). |
| **Decorator** | `PoseidonInterceptor` (OkHttp `Interceptor`) | Wraps the call chain, short-circuiting denied requests with a 403. |
| **Visitor** | `PoseidonClassVisitorFactory` + `NetworkAdapterRules` (ASM) | ASM's ClassVisitor/MethodVisitor are the Visitor pattern applied to bytecode; the registry is the visit table. |
| **Singleton** | Kotlin `object`: `PolicyEngine`, `Observer`, `ModeGate`, `Glob`, `NativeBridge`, `HostIpCacheSeeder`, the adapters, `DemoUrls` | Idiomatic. Caveat: a few hold global mutable config (`PolicyEngine.configure`, `Mode.current`) — mitigated by `resetForTest` hooks. |

## Deliberately skipped — would over-engineer this domain

| Pattern | Why not |
|---|---|
| **Composite** | No tree/recursive structures; allow-list, deny-paths and CIDRs are flat lists. |
| **Memento** | No undo/snapshot need; `resetForTest()` is a trivial reset, not a memento. |
| **Mediator** | `PoseidonGate` already coordinates as a *facade*; a mediator would add indirection with no decoupling gain. |
| **AbstractFactory** | No families of related products to vary. |
| **Factory (class)** | Object creation is trivial (`object`/data classes). `build_bpf_program(dnsCorrelation)` in C is already a lightweight factory *method*. |
| **State** | `Mode` (MONITOR/ENFORCE) is a 2-value flag read by `ModeGate`; State objects would be heavier than the `enum` check. |
| **Builder (new)** | Already *consumed* (OkHttp `Builder`) and emulated by `data class .copy()` + the Gradle DSL (`PoseidonExtension`). |
| **Chain of Responsibility** | The policy checks (host → path → CIDR) and the seccomp `handle_*_notif` dispatch are conceptually chains, but are already clear linear checks / a dispatch table. A CoR handler chain would add indirection. Revisit only if the rule set grows substantially. |

## The one upgrade we made
`Observer` previously held a single sink. It now supports multiple registered observers
(log + metrics + UI + …) — the one place the pattern's intent earns the extra structure.
See `Observer.addSink` / `removeSink`.
