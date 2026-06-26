#ifndef POSEIDON_HOST_MATCH_H
#define POSEIDON_HOST_MATCH_H
#include <fnmatch.h>
#ifndef FNM_CASEFOLD
#define FNM_CASEFOLD 0x10
#endif
/* The shim's host glob: POSIX fnmatch, case-insensitive. Shared by shim.c and the
   equivalence test so JVM and native evaluators are pinned to one definition. */
static inline int poseidon_host_match(const char* pattern, const char* value) {
    return fnmatch(pattern, value, FNM_CASEFOLD) == 0;
}
#endif
