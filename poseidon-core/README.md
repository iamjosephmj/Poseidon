# poseidon-core

Play-clean JVM core — required by every Poseidon configuration. Owns the full
egress-control pipeline: the manifest-first `PolicyEngine` (loaded from
`assets/poseidon/policy.bin` compiled by `poseidon-gradle-plugin`), the `EgressEvent`
keystone type that all interceptors emit, and the `Observer`/`Enforcer` sinks. JVM HTTP
adapters cover OkHttp (entry-point interceptor inject), `HttpURLConnection`, Volley, and
the JVM-path of Cronet — all rewired at build time by the Gradle plugin, zero app-code
changes required. `PoseidonInitializer` (androidx.startup) installs the engine at
process start before any SDK touches the network. No binary modification; no native
toolchain required; no Play policy exposure.

**Honest limits (from spec §9):** Poseidon provides strong default-deny egress control
and per-SDK audit for *non-adversarial* SDKs — it is not an absolute guarantee. Four
irreducible holes remain regardless of tier: (1) **Exfiltration through an allow-listed
host** — destination-only control cannot inspect TLS payloads; a permitted host can relay
anything. (2) **Hostile same-privilege SDK** — adversarial code running in-process can
tamper with policy mirrors or spawn threads before the filter installs; Poseidon is not a
security boundary against adversarial code at the same privilege level (only
kernel/MDM/network is). (3) **DoH/DoT** — hides the DNS name from correlation logs; the
`connect` to the resolved IP is still gated at the native/seccomp tier, but the name is
invisible to the JVM tier. (4) **Strict-by-IP CDN over-block** — mitigated by JVM
DNS-cache seeding; residual on rotating CDNs for platform-resolver clients.
