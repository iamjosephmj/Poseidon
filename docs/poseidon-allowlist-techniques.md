# Poseidon — Allow-list Enforcement Techniques

How Poseidon constrains the network egress of integrated third-party SDKs to a
host allow-list (+ path deny-list). Every technique below was built and verified
on-device (Pixel 6 Pro, Android 16, arm64; native shim compiles for arm64/armeabi-v7a/x86/x86_64).

**Policy model:** Host = allow-list (default-deny). Path = deny-list (default-allow).
Modes: `MONITOR` (log only) / `ENFORCE` (block). One compiled policy drives every layer.

Enforcement happens at **two choke points**: **name resolution** (refuse to resolve
non-allow-listed names) and **connection** (refuse to connect to non-allow-listed
destinations). A request must pass both.

---

## 1. Policy pipeline (DSL + YAML → compiled policy → startup load)

- **DSL** (`poseidon { allowedHosts; deniedPaths; mode; policyFile; nativeDnsCorrelation }`)
  and an optional checked-in `poseidon-policy.yml` are merged at build time by
  `GeneratePolicyTask` into `assets/poseidon/policy.json`.
- Wired into the variant's assets via the AGP `Sources` API
  (`variant.sources.assets.addGeneratedSourceDirectory`).
- At process start, `PoseidonInitializer` (androidx.startup, registered in the
  runtime library's manifest — zero app code) loads the asset and configures the
  JVM `PolicyEngine`, the native shim (via JNI), and installs the seccomp gate.

## 2. JVM bytecode instrumentation (path + host at the client API, pre-R8)

AGP **Instrumentation API** (`AsmClassVisitorFactory`, scope `ALL`) rewrites HTTP
clients' bytecode. Runs **before R8**, so we match original (un-obfuscated) class
names and R8 renames our injected calls consistently. Extensible registry of two
rule kinds in `PoseidonClassVisitorFactory`:

- **Entry rules** — inject a static call at a library method's entry:
  - **OkHttp** (covers Retrofit, Ktor-OkHttp engine): `OkHttpClient$Builder.build()`
    → `PoseidonOkHttp.install(this)` adds an `Interceptor`.
  - **Volley**: `RequestQueue.add(Request)` → `PoseidonVolley.onAdd(request)` cancels
    a denied request before dispatch.
- **Call-site rules** — rewrite a call site to a Poseidon static (for platform classes
  you can't instrument directly):
  - **HttpURLConnection** (covers Volley HurlStack, Ktor-Android engine):
    `URL.openConnection()/openStream()` → `PoseidonHttpUrl`.
  - **Cronet**: `CronetEngine.newUrlRequestBuilder(url,…)` → `PoseidonCronet`
    (path visibility at the Java API; host blocked by the native layer).

All adapters call the shared `PoseidonGate.shouldBlock(host, path)` → host allow-list
then path deny-list. This is the only layer with the **full URL**, so it does
**path** filtering (HTTPS path is plaintext here, above TLS). R8-safe via consumer
keep rules shipped in the runtime AAR (`consumer-rules.pro`).

## 3. Build-time native ELF interposition (host, for native SDK code)

Native SDK code (Cronet, gRPC-core, etc.) doesn't go through JVM clients. To gate it:

- **`PoseidonNativeInjectTask`** runs after `strip…Symbols` and before `package…`
  / `build…PreBundle` (covers APK and AAB), injecting the shim into every bundled
  native `.so` **in place** — so AGP signs normally afterward (**no re-sign, nothing
  after R8**). (AGP exposes native libs only as internal Replaceable artifacts, so a
  task-graph hook is used rather than the Artifacts API.)
- **`ElfDtNeededInjector`** (pure JVM, ELF32/64 LE — no LIEF/python) adds the shim as
  the **first `DT_NEEDED`** of each `.so`: appends one `PT_LOAD` segment containing a
  relocated program-header table, a copied+extended `.dynstr` (soname appended), and
  a relocated `.dynamic` (our entry first so the shim wins symbol resolution).
  Verified loading a 12 MB stripped Chromium `libcronet.so`.

## 4. libc symbol interposition (the shim's host enforcement)

`libposeidon_shim.so` (the injected lib) exports versioned (`@@LIBC`) wrappers for the
full libc network surface; the SDK's calls resolve to these:

- `connect`, `sendto`, `sendmsg`, `sendmmsg` — TCP/UDP/QUIC connection points.
- `getaddrinfo`, `android_getaddrinfofornet`, `gethostbyname` — DNS, both to **build
  the IP→host cache** and to **deny resolution** of non-allow-listed names.
- Each wrapper: resolve peer IP → host (via the cache) → glob-match the allow-list →
  allow / block (`ECONNREFUSED`). Loopback, AF_UNIX (netd/logd), and DNS (port 53) are
  exempt. IPv4-mapped IPv6 normalized. A **thread-local reentrancy guard** prevents
  recursion via our own logging; the policy mutex is never held while logging.

## 5. seccomp `USER_NOTIF` kernel gate (host, for Go / raw-syscall)

Go and other raw-syscall code bypass libc entirely (no symbol to interpose). The shim
installs a **seccomp-bpf filter on its own process** that traps `connect` (always) and
`sendto`/`recvfrom` (when DNS correlation is enabled) at the **kernel syscall boundary
— below libc** — so it sees *all* connection attempts regardless of language/runtime.

- A **supervisor thread** (created *before* the filter, so it stays unfiltered) reads
  each trapped syscall (`SECCOMP_IOCTL_NOTIF_RECV`), evaluates the allow-list, and
  blocks (`-EACCES`) or allows. For `connect` it is **TOCTOU-safe**: it copies the
  sockaddr into its own buffer and, for allowed connects, performs the `connect`
  itself with the trusted copy (never `CONTINUE`, so the destination can't be swapped
  after the check).
- Traps cover every way to start an outbound flow: `connect` (TCP + connected UDP),
  and — when DNS correlation/ENFORCE is on — `sendto`/`sendmsg`/`sendmmsg`
  (**connectionless UDP**, e.g. Go's `WriteToUDP`; a NULL `msg_name` means a connected
  socket already gated by `connect`). `io_uring_setup` is denied outright
  (`EACCES`) — defense-in-depth; Android's platform seccomp already blocks io_uring
  for apps.
- Enabled on all ABIs with a direct `connect` syscall. Requires kernel ≥ 5.0
  (`USER_NOTIF`); on older kernels it declines gracefully and the libc + DNS layers
  still enforce for libc-based code.
- Proven: raw `syscall(__NR_connect)` (TCP) and raw `syscall(__NR_sendto)`
  connectionless UDP to a denied host are both blocked (`errno 13`).

## 6. In-process DNS correlation (so the host gate works by name, not just IP)

The connect gate sees an IP; the allow-list is by name. Three in-process sources keep
the IP→host cache complete (no external resolver, no VPN):

- **libc resolvers** — the shim's `getaddrinfo`/`android_getaddrinfofornet` hooks cache
  every returned A/AAAA → queried name.
- **Raw/Go DNS** — the seccomp supervisor parses `sendto` (query QNAME) and emulates
  `recvfrom` (parses A/AAAA answers) on UDP:53 sockets → caches IP→host. (Opt-in via
  `nativeDnsCorrelation`; auto-enabled in ENFORCE mode. ~160 µs/datagram cost.)
- **Platform/JVM resolution** — platform clients (HttpURLConnection/OkHttp) resolve via
  the platform resolver, invisible to our libc hook. So `PoseidonGate`, when it allows
  a host, resolves it (`InetAddress.getAllByName`) once and **seeds those IPs into the
  native cache** (`NativeBridge.cacheHost` → JNI). This closes the strict-mode
  over-block for JVM clients (e.g. CDN/IPv6 hosts).

## 7. DNS-layer allow-list enforcement (default-deny by name)

Beyond gating connections, Poseidon refuses to **resolve** non-allow-listed names:

- libc `getaddrinfo`/`android_getaddrinfofornet` return `EAI_FAIL` for denied names.
- The seccomp supervisor blocks raw DNS queries (`sendto` :53) for denied names.

This denies denied hosts at resolution (cleanest block — the client never gets an IP;
e.g. Cronet → `ERR_NAME_NOT_RESOLVED`) and shuts down DNS-tunnelling to arbitrary
names. The resolver connection itself (port 53) stays allowed so legitimate
resolution works; the *resolved destination* is gated at connect.

## 8. Per-`.so` attribution (which library made the call — audit primitive)

At the libc-shim layer the wrapper runs in the *caller's* thread, so the return
address points into the library that called `connect`/`sendto`. The wrappers resolve
it with `dladdr(__builtin_return_address(0))` and log the originating `.so` (basename)
for every call — allowed and blocked.

- Proven: `connect() BLOCK [from libcronet.143.0.7445.0.so] ... 2001:4860:4860::8888`
  — names the exact (versioned) native library that attempted a non-allow-listed
  destination.
- Resolves the *immediate* caller (an SDK calling through an intermediate networking
  lib attributes to that lib; deeper stack unwinding can pin the ultimate caller).
- Scope: native injected libs only. JVM/platform clients are attributed at the
  bytecode layer (Java caller class/package); Go/raw-syscall via seccomp has no cheap
  `.so` (the supervisor is a separate thread from the trapped one).

## 9. Cost / opt-in tiers

- **connect-gate** (host enforce, incl. Go): ~160 µs/connect — negligible vs network
  RTT; on by default in ENFORCE.
- **DNS correlation + UDP enforcement** (`sendto`/`recvfrom`/`sendmsg`/`sendmmsg`
  trapping): ~160 µs/datagram — opt-in via `nativeDnsCorrelation`, auto-enabled in
  ENFORCE. Brutal for UDP/QUIC-heavy apps, so a deliberate flag.
- **Synchronous logging** is used here for validation; production should route the
  `Observer` sink to an async lock-free ring.

---

## Coverage summary

| Client / runtime | Host enforce | Path enforce | Via |
|---|---|---|---|
| OkHttp / Retrofit / Ktor-OkHttp | ✅ | ✅ | bytecode interceptor + DNS + connect |
| HttpURLConnection / Volley / Ktor-Android | ✅ | ✅ | call-site rewrite + DNS + connect |
| Cronet | ✅ | path observed at Java API | bytecode + ELF shim + DNS + connect |
| Native via libc (gRPC-core, etc.) | ✅ | ✗ (TLS) | ELF shim + DNS + connect |
| Go / raw-syscall | ✅ | ✗ | seccomp gate + raw-DNS correlation |

Enforced at **two points** for all of the above: name resolution (deny) and connect (deny).

## Honest limits (documented, not bugs)

These are not closeable in-process and are recorded for accuracy:

- **Exfiltration *through* an allow-listed host** (the SDK's own permitted server, a
  shared CDN IP, your backend relaying). The allow-list is by destination; we do not
  inspect TLS payload. No egress filter can stop this without content inspection.
- **TLS payload content** — invisible by design (no MITM).
- **A hostile SDK at the same privilege** — runs in our address space and can tamper
  with the enforcement itself: overwrite the in-memory allow-list / disable the flag /
  patch the supervisor, or spawn threads *before* our filter installs (a seccomp filter
  doesn't apply to pre-existing threads, and TSYNC can't combine with `USER_NOTIF`).
  In-process enforcement is **not a security boundary against an adversarial SDK** —
  only the kernel / a managed-network (MDM) / a system-enforced firewall is. (Note:
  several *specific* adversarial tricks are closed — `io_uring` is denied + OS-blocked,
  and `connect` is TOCTOU-safe via emulation — but the same-address-space class is not
  closeable in-process.)
- **Kernels < 5.0** — no seccomp `USER_NOTIF`; Go/raw-syscall on those devices is
  ungated (libc + DNS layers still enforce for libc-based code).
- **DoH/DoT** — encrypted DNS hides the name from correlation (the *connect* to the
  resolved IP is still gated by strict default-deny). **ECH** will eventually hide SNI.

**In one line:** strong, default-deny egress control across JVM + native + Go for
**non-adversarial** SDKs (over-collection, undisclosed endpoints), plus a full audit
trail — *not* a guarantee against a hostile SDK or against exfiltration via permitted
destinations. For a hard guarantee, enforce egress outside the process (MDM / network).
