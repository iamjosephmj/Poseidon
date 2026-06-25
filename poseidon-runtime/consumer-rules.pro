# Poseidon consumer R8/ProGuard rules — applied automatically to any app that
# depends on :poseidon-runtime, so enabling minification doesn't break Poseidon.

# JNI bridge: the native shim looks up Java_..._NativeBridge_configure by name,
# so the class + native method names must NOT be renamed.
-keep,includedescriptorclasses class tech.ssemaj.poseidon.runtime.NativeBridge {
    native <methods>;
}
-keep class tech.ssemaj.poseidon.runtime.NativeBridge { *; }

# Startup initializer referenced by fully-qualified name in the merged manifest.
-keep class tech.ssemaj.poseidon.runtime.PoseidonInitializer { <init>(...); }

# Entry points referenced from the bytecode the Gradle plugin injects.
-keep class tech.ssemaj.poseidon.runtime.PoseidonOkHttp { *; }
-keep class tech.ssemaj.poseidon.runtime.PoseidonInterceptor { *; }
-keep class tech.ssemaj.poseidon.runtime.PoseidonHttpUrl { *; }
-keep class tech.ssemaj.poseidon.runtime.PoseidonGate { *; }
-keep class tech.ssemaj.poseidon.runtime.PoseidonVolley { *; }
-keep class tech.ssemaj.poseidon.runtime.PoseidonCronet { *; }
