# poseidon-native

**Opt-in** native-tier enforcement — adds host enforcement for native SDKs (Cronet's
internal net stack, any `.so` that calls libc directly) that the JVM interceptors cannot
reach. Implements a libc DT_NEEDED shim that interposes `connect`, `sendto`, `sendmsg`,
`sendmmsg`, and `getaddrinfo`; the `poseidon-gradle-plugin` injects the shim as a
DT_NEEDED entry into each targeted `.so` at build time (post-strip, pre-package, no
re-sign). Attribution is per-library: the shim captures the native return address and
symbolizes it off-thread via `dladdr` to identify the calling `.so`. A lock-free async
event ring forwards native events to the JVM `Observer`, so native and JVM egress land in
the same unified audit map.

**Opt-in cost/risk:** ELF binary modification raises licensing questions for any SDK
whose EULA prohibits modification; it also shifts Play policy posture (modification of
third-party binaries). Evaluate before enabling. To opt in, depend on `:poseidon-native`
or `:poseidon-all` and enable native injection in the plugin DSL.

**Honest limits (from spec §9):** In addition to the core limits, note that
**kernels < 5.0** have no seccomp `USER_NOTIF`, so Go/raw-syscall traffic is ungated
there (libc + DNS calls are still enforced via the shim for libc-using code). **DoH/DoT**
hides the DNS name from correlation; the `connect` to the resolved IP is still gated.
**Strict-by-IP CDN over-block** residual applies on rotating CDNs. A **hostile
same-privilege SDK** can overwrite the native policy mirror or bypass interposition
entirely — Poseidon constrains non-adversarial SDKs; it is not an in-process security
boundary.
