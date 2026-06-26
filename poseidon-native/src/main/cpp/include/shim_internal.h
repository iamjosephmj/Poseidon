/* shim_internal.h — shared types and cross-TU declarations for libposeidon_shim.
 *
 * All non-JNI, non-libc symbols declared here are hidden from external callers
 * by the "local: *;" catch-all in poseidon.ver.
 *
 * Translation-unit layout:
 *   policy_eval.c       — g_lock definition, allow-list/CIDR policy, poseidon_check
 *   dns_cache.c         — IP->hostname ring cache and raw DNS parsers
 *   interpose.c         — libc wrapper stubs (connect/sendto/sendmsg/…)
 *   seccomp_supervisor.c — in-process seccomp USER_NOTIF supervisor
 *   jni_bridge.c        — Java_* JNI exports (configure/cacheHost/drain/symbolize/…)
 */
#pragma once
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include "event_ring.h"   /* ring_push, POSEIDON_TRANSPORT_*, POSEIDON_TIER_* */

/* ---- Verdict returned by poseidon_check() ---- */
typedef enum {
    P_NA           = 0,  /* exempt: loopback / AF_UNIX / DNS port / unconfigured */
    P_ALLOW        = 1,  /* host is on the allow-list                             */
    P_BLOCK        = 2,  /* denied (enforce mode)                                 */
    P_MONITOR_VIOL = 3,  /* would-block in monitor mode                           */
} poseidon_verdict_t;

/* ---- Shared mutex (defined in policy_eval.c) ----
 * Protects g_cache (dns_cache.c) AND g_hosts/g_cidrs/g_enforce (policy_eval.c).
 * Always acquire g_lock before g_dnsmap_lock if both are needed.            */
extern pthread_mutex_t g_lock;

/* ---- Monotonic timestamp — vDSO, hot-path safe ---- */
static inline uint64_t mono_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ---- Interpose helpers (defined in interpose.c) ----
 * get_port: destination port from a sockaddr; 0 for unknown family or NULL.
 * host_from_desc: extract the hostname from "hostname (ipstr)" desc built by
 *   poseidon_check(). Output is truncated to sz bytes (NUL-terminated).    */
int  get_port(const struct sockaddr *sa);
void host_from_desc(const char *desc, char *out, size_t sz);

/* ---- Shared policy limits ---- */
#define POSEIDON_DNS_PORT  53   /* destination port exempted as resolver traffic */
#define POSEIDON_MAX_CIDRS 64   /* maximum CIDR entries accepted via configureCidrs() */

/* ---- DNS cache types (defined in dns_cache.c) ---- */
#define CACHE_CAP 4096
typedef struct {
    int family;
    unsigned char addr[16];
    char host[256];
} dns_entry;
extern dns_entry g_cache[CACHE_CAP];
extern int       g_cache_next;
extern int       g_cache_size;

/* ---- Cache API (defined in dns_cache.c) ---- */
void cache_put(int family, const void *addr, const char *host);
void cache_addrinfo(const char *node, const struct addrinfo *res);

/* ---- DNS parser API (defined in dns_cache.c) ---- */
/* Parse QNAME from a DNS query into a dotted hostname. Returns 1 on success. */
int  dns_qname(const unsigned char *p, size_t n, char *out, size_t outsz);
/* Skip a DNS name (labels or compression pointer) starting at *i. */
void dns_skip_name(const unsigned char *p, size_t n, size_t *i);
/* Parse A/AAAA answers from a DNS response and cache each IP->host mapping. */
void dns_answers(const unsigned char *p, size_t n, const char *host);
/* Extract the first A-record IP string from a DNS response into out[outsz].
 * Returns 1 on success (shares walk logic with dns_answers). */
int  dns_first_a(const unsigned char *p, size_t n, char *out, size_t outsz);

/* ---- Policy API (defined in policy_eval.c) ---- */
/**
 * Check whether the peer described by sa is allowed, blocked, or exempt.
 *
 * @param identified    Out: 1 if the peer IP is positively mapped to a cached
 *                      hostname via the DNS-correlation cache; 0 otherwise.
 * @param has_cidrs_out Out: (g_cidr_count > 0) sampled inside g_lock, so the
 *                      supervisor's do_block decision needs no extra global read.
 *                      Either param may be NULL if not needed.
 */
poseidon_verdict_t poseidon_check(const struct sockaddr *sa,
                                   char *desc, size_t dlen,
                                   int *identified, int *has_cidrs_out);

/* True if name must be denied (allow-list configured + enforce + not allowed). */
int host_denied(const char *name);

/* ---- Policy setters (called from jni_bridge.c) ---- */
typedef struct { int family; unsigned char net[16]; int prefix; } poseidon_cidr_t;

/* Takes ownership of arr (char** of strdup'd strings, length n). */
void policy_set_hosts(char **arr, int n, int enforce);
/* Copies up to 64 entries from cidrs[0..n-1]. */
void policy_set_cidrs(const poseidon_cidr_t *cidrs, int n);
