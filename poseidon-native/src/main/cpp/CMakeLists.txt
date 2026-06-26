cmake_minimum_required(VERSION 3.22.1)
project(poseidon_shim C)

# shim.c has been split into focused translation units; all are compiled into
# the same libposeidon_shim.so so symbol visibility is unchanged.
add_library(poseidon_shim SHARED
    policy_eval.c
    dns_cache.c
    interpose.c
    seccomp_supervisor.c
    jni_bridge.c
    event_ring.c
)

# Export connect/sendto/… at version node LIBC so they satisfy SDKs' versioned
# imports (e.g. Cronet's connect@LIBC).
target_link_options(poseidon_shim PRIVATE
    "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/poseidon.ver")

target_link_libraries(poseidon_shim log dl)
