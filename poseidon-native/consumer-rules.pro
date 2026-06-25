# Keep NativeShimBackend so R8 cannot rename the class or its native methods.
# The JNI symbol names (Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_*)
# are hard-coded in libposeidon_shim.so and must match exactly.
-keep,includedescriptorclasses class tech.ssemaj.poseidon.runtime.NativeShimBackend {
    native <methods>;
}
-keep class tech.ssemaj.poseidon.runtime.NativeShimBackend { *; }
