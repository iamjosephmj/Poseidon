/* shim.c — split into focused translation units (CC-4 refactor).
 *
 * Content has been moved to:
 *   policy_eval.c       — allow-list/CIDR policy, poseidon_check
 *   dns_cache.c         — IP->hostname cache, DNS parsers
 *   interpose.c         — libc wrappers (connect/sendto/…)
 *   seccomp_supervisor.c — seccomp USER_NOTIF supervisor
 *   jni_bridge.c        — Java_* JNI exports
 *
 * This file is intentionally empty and is NOT listed in CMakeLists.txt.
 */
