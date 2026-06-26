# Contributing to Poseidon

Thanks for taking a look. Poseidon spans JVM bytecode instrumentation, native libc
interposition, and a kernel seccomp gate, so a few things in this repo are **load‑bearing in
non‑obvious ways**. This guide covers how to build and test, and — more importantly — the
constraints that silently break things if you miss them.

## Getting set up

- **JDK 17** (Android Studio's bundled JBR works). Export `JAVA_HOME` before any Gradle call.
- **Android SDK** + **NDK 28.2.13676358** (AGP auto‑provisions it).
- The Gradle plugin builds **standalone** and is consumed from `mavenLocal`:

```bash
export JAVA_HOME=/path/to/jbr
./gradlew -p poseidon-gradle-plugin publishToMavenLocal   # after any plugin change
./gradlew :app:assembleDebug
```

Module layout, namespaces, and source packages are documented at the top of
[`settings.gradle.kts`](settings.gradle.kts); the architecture is in [ARCH.md](ARCH.md).

## Run the checks

```bash
./gradlew -p poseidon-gradle-plugin test          # plugin unit tests
./gradlew :poseidon-core:testDebugUnitTest        # core unit tests + JVM glob equivalence
./gradlew :poseidon-native:assembleDebug          # builds libposeidon_shim.so (4 ABIs)
./gradlew :app:assembleDebug                       # runs the ASM transform + ELF inject end-to-end

# Native host tests (need a host C toolchain + cmake):
cmake -S poseidon-native/src/main/cpp/test -B /tmp/pcmake && cmake --build /tmp/pcmake
/tmp/pcmake/glob_test poseidon-native/src/main/cpp/test/glob_vectors.txt   # JVM↔native glob equivalence
/tmp/pcmake/ring_test                                                       # lock-free ring concurrency
```

CI (`.github/workflows/poseidon-ci.yml`) runs all of the above on every push. The on‑device
acceptance suite is gated behind a self‑hosted Pixel runner.

**For anything touching the native shim, the plugin's injection, or R8 keeps, also verify a
minified build on a real device** — those failures are invisible to a normal debug build
(the app's debug build is intentionally R8‑minified for exactly this reason).

## ⚠️ Load‑bearing constraints (read before refactoring)

The runtime package **`tech.ssemaj.poseidon.runtime` is frozen**. Renaming or moving its
classes/packages breaks, often **silently**:

- **JNI symbols** — `Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_*` in `jni/jni_bridge.c`
  and `linker/poseidon.ver`. Renaming the class/package ⇒ `UnsatisfiedLinkError` at runtime.
  Don't change the externals' names/signatures. The `.ver` node name `LIBC` is also
  load‑bearing (satisfies versioned imports like `connect@LIBC`).
- **Plugin ASM injection literals** — `NetworkAdapterRules` hard‑codes the runtime FQNs
  (`…/adapter/PoseidonOkHttp`, etc.) as strings. If a literal and the real class diverge,
  instrumentation **silently no‑ops** — no build error, no log. Keep them in lockstep.
- **Injected‑target method signatures** — `PoseidonOkHttp.install`, `PoseidonVolley.onAdd`,
  `PoseidonHttpUrl.open/openStream`, `PoseidonCronet.newUrlRequestBuilder` are called by
  injected bytecode. Keep their owner/name/`@JvmStatic`/params/return type exactly.
- **`consumer-rules.pro`**, the **manifest** `InitializationProvider` meta‑data, and the
  reflective `Class.forName("…NativeShimBackend")` all reference FQNs — update in lockstep.

When you do need to reorganize, you can group files into folders **without** changing the
`package` declaration (Kotlin allows dir ≠ package) — that's zero‑risk. True sub‑packaging
means updating every coupled site above and re‑verifying on device.

### Native hot path
Nothing in the interposed wrappers or the seccomp supervisor's decision path may **log
synchronously, take a lock, or allocate** — emit via the lock‑free ring instead. Keep the
drain loop's `InterruptedException` branch as a structured `try/catch` (it does control‑flow
+ re‑raises the interrupt). After any C change, confirm the exported symbol set is unchanged
(`llvm-nm -D`) and the ELF injector's output bytes are identical.

## Style

- **Idiomatic Kotlin** — expression bodies, scope functions, collection ops, null‑safety.
  Use `runCatching` for *swallow‑and‑continue* `try/catch`, but **not** where it does
  control flow (break/continue/return) or catches a specific type to act on it.
- **No magic numbers/strings** — extract to named constants with a one‑line comment.
- **Single responsibility** — small, focused files; sub‑package by responsibility.
- Match the surrounding code.

## Commits & PRs

- **Conventional commits**: `feat:` `fix:` `refactor:` `docs:` `chore:` `test:`, optional
  scope (`refactor(native): …`). Small, focused commits.
- Keep the build green and add/adjust tests for behavior changes.
- Open a PR against `master` with a clear description of what and why; note if you verified
  on a device.

By contributing you agree your work is licensed under the project's [MIT License](LICENSE).
