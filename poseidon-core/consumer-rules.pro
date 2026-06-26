# Poseidon consumer R8/ProGuard rules — applied automatically to any app that
# depends on :poseidon-core, so enabling minification doesn't break Poseidon.

# NativeBridge seam: no native methods in core, but keep class + members intact
# so poseidon-native can register a Backend at runtime.
-keep class tech.ssemaj.poseidon.runtime.internal.NativeBridge { *; }

# Startup initializer referenced by fully-qualified name in the merged manifest.
-keep class tech.ssemaj.poseidon.runtime.config.PoseidonInitializer { *; }

# Entry points referenced from the bytecode the Gradle plugin injects.
-keep class tech.ssemaj.poseidon.runtime.adapter.PoseidonOkHttp { *; }
-keep class tech.ssemaj.poseidon.runtime.adapter.PoseidonInterceptor { *; }
-keep class tech.ssemaj.poseidon.runtime.adapter.PoseidonHttpUrl { *; }
-keep class tech.ssemaj.poseidon.runtime.pipeline.PoseidonGate { *; }
-keep class tech.ssemaj.poseidon.runtime.adapter.PoseidonVolley { *; }
-keep class tech.ssemaj.poseidon.runtime.adapter.PoseidonCronet { *; }
