cmake_minimum_required(VERSION 3.22.1)
project(poseidon_shim C)

# The shim is split into focused translation units by subsystem, each in its own
# folder; all compile into the same libposeidon_shim.so so symbol visibility is
# unchanged. Shared headers live in include/ (added to the include path below).
#
#   interpose/  — libc DT_NEEDED wrappers (connect/sendto/getaddrinfo…) + reentrancy guard
#   policy/     — allow-list + CIDR evaluation, verdict (owns g_lock)
#   dns/        — IP<->host correlation cache + DNS packet parsing
#   seccomp/    — USER_NOTIF gate, BPF program, notif handlers
#   audit/      — lock-free MPSC event ring
#   jni/        — the Java_* JNI exports
#   include/    — cross-TU headers (shim_internal.h, event_ring.h, host_match.h)
#   linker/     — version script
add_library(poseidon_shim SHARED
    policy/policy_eval.c
    dns/dns_cache.c
    interpose/interpose.c
    seccomp/seccomp_supervisor.c
    jni/jni_bridge.c
    audit/event_ring.c
)

# Shared headers are #include "…"d by basename across translation units.
target_include_directories(poseidon_shim PRIVATE include)

# Export connect/sendto/… at version node LIBC so they satisfy SDKs' versioned
# imports (e.g. Cronet's connect@LIBC).
target_link_options(poseidon_shim PRIVATE
    "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/linker/poseidon.ver")

target_link_libraries(poseidon_shim log dl)
