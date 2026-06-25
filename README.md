# Poseidon

Build-time + runtime network egress control for Android: declare which hosts your
third-party SDKs may reach, audit exactly what each SDK actually reaches (per-library),
and optionally block anything off the list — across JVM, native, and Go/raw-syscall code,
in-process, no VPN, no root.

---

## Module architecture

| Module | Contents | Risk/cost | Required? |
|---|---|---|---|
| **`poseidon-core`** | manifest policy loader, `PolicyEngine`, `EgressEvent`, `Observer`, `Enforcer`, JVM bytecode interception (OkHttp / HttpURLConnection / Volley / Cronet-path) | none (no binary mod) | yes |
| **`poseidon-native`** | ELF `DT_NEEDED` injector (Gradle) + libc shim (`connect`/`sendto`/`sendmsg`/`sendmmsg`/`getaddrinfo`) + per-`.so` attribution | binary modification → licensing/Play posture | opt-in |
| **`poseidon-seccomp`** | kernel `USER_NOTIF` gate for Go/raw-syscall + raw-DNS correlation | per-connection/datagram cost; kernel ≥ 5.0; gated by `nativeDnsCorrelation` flag | opt-in |
| **`poseidon-gradle-plugin`** | manifest → compiled policy, bytecode transform registration, native-inject task wiring | — | yes |
| **`poseidon-all`** | umbrella artifact depending on core + native + seccomp | — | convenience |

The JVM+manifest story (core + plugin) is **Play-clean and stands alone** — no binary
modification occurs and `injectNative` defaults to `false`. Native and seccomp layer on
top for power users who need coverage below the JVM. To enable libc-level host enforcement
(e.g. Cronet, other native SDKs), depend on `:poseidon-native` or `:poseidon-all` and set
`poseidon { injectNative = true }` in your app's `build.gradle.kts`.

> **Note:** The seccomp Go/raw-syscall gate ships inside `libposeidon_shim.so`; depending
> on `:poseidon-native` (or `:poseidon-all`) already includes it. `:poseidon-seccomp` is
> a marker module for the opt-in native tier and is not a separate runtime artifact.

---

## Configuration — manifest-first

The allow-list is declared as an XML resource in your app manifest (NSC-style,
merger-safe). The Gradle plugin compiles it into `assets/poseidon/policy.json` at build
time and produces a human-readable build report of the effective allow-list plus every
SDK proposal.

**Step 1 — declare the policy resource in `AndroidManifest.xml`:**
```xml
<meta-data
    android:name="tech.ssemaj.poseidon.policy"
    android:resource="@xml/poseidon_policy"/>
```

**Step 2 — write `res/xml/poseidon_policy.xml`:**
```xml
<poseidon mode="enforce">          <!-- or "monitor" -->
  <allow host="example.com"/>
  <allow host="*.api.foo.com"/>
  <deny-path pattern="/internal/*"/>
</poseidon>
```

**Libraries propose** their needs in their own manifests (carried up by manifest merge);
proposals are recorded with package attribution but are NOT granted unless the app
explicitly approves them:
```xml
<!-- in a library's AndroidManifest.xml -->
<meta-data
    android:name="tech.ssemaj.poseidon.proposes"
    android:resource="@xml/poseidon_proposes"/>
```

`PoseidonInitializer` (androidx.startup, in core's merged manifest) loads the compiled
policy and installs the engine at process start with zero app code changes.

---

## Honest limits

Poseidon provides **strong default-deny egress control + per-SDK audit for
non-adversarial SDKs.** It is NOT a guarantee against a hostile SDK or exfiltration via
permitted destinations. Five irreducible limits:

1. **Exfiltration through an allow-listed host** — destination-only control; no TLS
   payload inspection. A permitted host can relay anything.
2. **Hostile same-privilege SDK** — adversarial in-process code can tamper with policy
   mirrors or spawn threads before the filter installs. In-process is not a security
   boundary; only kernel/MDM/network is.
3. **Kernels < 5.0** — no `seccomp USER_NOTIF`; Go/raw-syscall traffic is ungated
   (libc + DNS still enforced via the native shim for libc-using code).
4. **DoH/DoT** — hides the DNS name from correlation logs; the `connect` to the resolved
   IP is still gated at native/seccomp tier.
5. **Strict-by-IP CDN over-block** — mitigated by JVM DNS-cache seeding; residual on
   rotating CDNs for platform-resolver clients.

Specific tricks closed: `io_uring_setup` denied; `connect` TOCTOU-safe (emulate, not
CONTINUE).
