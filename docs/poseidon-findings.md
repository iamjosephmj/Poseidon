# Poseidon — Egress Allow-list: Findings

A consolidated record of what Poseidon's in-process allow-list enforcement covers,
what was verified on-device, and the open issues that remain. Companion to
`poseidon-allowlist-techniques.md` (the *how*); this doc is the *findings* (the *what
holds*).

**Test device:** Pixel 6 Pro, Android 16, arm64 (native shim also compiles for
armeabi-v7a / x86 / x86_64). **Policy under test:** `allowedHosts = [example.com]`,
`mode = enforce`, DNS correlation on.

---

## Core finding

Under **normal (non-adversarial) conditions**, every technique an SDK can use to
start an outbound network flow is gated, and a destination not on the allow-list is
blocked — across JVM, native libc, and Go/raw-syscall code, on all ABIs.

Enforcement happens at two choke points a flow cannot avoid: **name resolution**
(non-allow-listed names refuse to resolve) and **the connection/send syscall**
(non-allow-listed destinations are refused).

## Coverage by call technique (all verified on-device)

| Technique to reach the network | Blocked? | Mechanism | Evidence |
|---|---|---|---|
| TCP via `connect()` — JVM clients | ✅ | bytecode adapter + DNS deny + connect gate | huc/okhttp/volley → blocked for google |
| TCP via `connect()` — native libc (Cronet, gRPC-core) | ✅ | ELF shim + DNS deny + connect gate | cronet google → `ERR_NAME_NOT_RESOLVED` |
| TCP via `connect()` — **Go / raw syscall** | ✅ | seccomp connect gate (TOCTOU-safe) | `raw-syscall google:443 → errno 13` |
| Connected UDP / QUIC (`connect` on UDP socket) | ✅ | same connect gate | (covered by connect trap) |
| **Connectionless UDP** `sendto` (no connect) — raw/Go | ✅ | seccomp sendto enforcement (non-53) | `raw-sendto 8.8.8.8:443 → errno 13` |
| **Connectionless UDP** `sendmsg`/`sendmmsg` — raw/Go | ✅ | seccomp sendmsg/sendmmsg enforcement | filter + supervisor (msg_name check) |
| Connectionless UDP via libc | ✅ | libc shim (`sendto`/`sendmsg`/`sendmmsg`) | shim wrappers enforce |
| Name resolution (libc `getaddrinfo`) | ✅ | denied names → `EAI_FAIL` | `getaddrinfo() BLOCK www.google.com` |
| Name resolution (raw/Go DNS, UDP:53) | ✅ | supervisor blocks denied queries | `dns [seccomp] BLOCK www.google.com` |
| `io_uring` (connect/send without the syscall) | ✅ | OS blocks it for apps + we deny `io_uring_setup` | Android platform seccomp + our filter |

**Allowed traffic intact:** `example.com` works on Cronet/HUC/OkHttp/Volley
(404/200) while every google path is blocked. Path deny-list (`/blocked`) enforced at
the JVM layer (403/cancel).

## Hardening applied (this investigation)

- **Strict default-deny** at the connect gate (blocks un-mapped IPs, not just
  positively-identified denials).
- **DNS default-deny by name** (libc + raw) — also stops DNS-tunnelling to arbitrary
  names.
- **TOCTOU fix for connect** — supervisor emulates the connect with a trusted sockaddr
  copy instead of `CONTINUE` (kernel docs: `CONTINUE` is racy / not a security
  mechanism).
- **All ABIs** — seccomp gate enabled wherever a direct `connect` syscall exists.
- **Connectionless-UDP gap closed** — `sendto` (non-53) + `sendmsg`/`sendmmsg`
  enforced.
- **io_uring** denied as defense-in-depth.
- **JVM cache-seeding bridge** — allowed hosts' IPs seeded into the native cache so the
  strict gate recognizes platform-resolver clients' connections (reduces CDN/IPv6
  over-block).
- **Per-`.so` attribution (native)** — the libc-shim wrapper resolves the calling
  library via `dladdr(__builtin_return_address(0))`, logging which `.so` made each
  connect/send (allowed and blocked). Proven: `connect() BLOCK [from
  libcronet.143.0.7445.0.so] ... 2001:4860:4860::8888` — names the exact (versioned)
  library that attempted a non-allow-listed destination. This is the core audit
  primitive ("which SDK lib contacted what"). Limits: works for injected native libs;
  resolves the *immediate* caller (an SDK calling through an intermediate networking
  lib attributes to that lib — deeper unwinding possible); JVM/platform clients are
  attributed at the bytecode layer (Java caller) not here; Go/raw-syscall via seccomp
  has no easy `.so` (separate supervisor thread).

---

## Open issues (to be addressed)

These are the items NOT covered by the in-process design as it stands. The user will
direct how each is achieved.

1. **Adversarial same-privilege tampering.** A *hostile* SDK runs in the same address
   space and can overwrite the in-memory allow-list / enforce flag or patch the
   supervisor. Kernel docs confirm the seccomp notifier "cannot be used to implement a
   security policy" for same-process self-supervision. *(User: separate issue —
   "requiring is a different issue.")*

2. **Kernels < 5.0.** No seccomp `USER_NOTIF`; the gate declines to install. Go/raw
   on those devices is ungated (libc + DNS layers still enforce for libc code).
   Potential path: TSYNC'd `RET_TRAP` + SIGSYS-handler fallback.

3. **Threads created before the filter installs.** A seccomp filter doesn't apply to
   threads that already existed (and TSYNC can't combine with `USER_NOTIF`). An SDK
   whose `ContentProvider`/static-init runs before Poseidon could spawn an unfiltered
   thread. Mitigation today: install as early as possible.

4. **Exfiltration through an allow-listed host.** The allow-list is by destination;
   payload is encrypted (no MITM). Data sent to a *permitted* host (the SDK's own
   server, a shared CDN IP, a relaying backend) cannot be distinguished from
   legitimate traffic. Not closeable by destination-based egress control.

5. **CDN/IPv6 over-block (correctness, not a leak).** Strict default-deny can still
   intermittently over-block rotating-CDN hosts for platform-resolver clients
   (HttpURLConnection/OkHttp), because our seed-resolve and the client's resolution
   return different rotating IPs. Cronet (hooked resolution) is reliable.

6. **DoH/DoT visibility.** Encrypted DNS hides the queried name from correlation/logs
   (enforcement still holds — the connect to the resolved IP is gated by strict
   default-deny). ECH will eventually hide SNI too.

---

## Status line

- **Non-adversarial SDK, any call technique:** blocked unless allow-listed —
  demonstrated across TCP, connected UDP, connectionless UDP, raw syscalls, and DNS.
- **Hostile SDK / pre-5.0 / pre-init threads / exfil-via-allowed-host:** open — see
  above; awaiting direction.
