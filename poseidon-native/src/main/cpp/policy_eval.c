/* policy_eval.c — host allow-list / CIDR policy for libposeidon_shim.
 *
 * Owns: g_lock (shared mutex), allow-list (g_hosts/g_enforce), CIDR list (g_cidrs).
 * Exports: poseidon_check(), host_denied().
 *
 * poseidon_check() is decomposed into three internal helpers:
 *   normalize_peer()   — extract (family, ip, iplen, port) from a sockaddr,
 *                        handling IPv4-mapped IPv6; returns -1 for exempt peers.
 *   evaluate_locked()  — pure policy evaluation + desc formatting (g_lock held).
 *   poseidon_check()   — thin coordinator: normalize → lock → evaluate → unlock.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "host_match.h"
#include "shim_internal.h"

/* ---- Shared mutex (protects g_cache in dns_cache.c + g_hosts/g_cidrs here) ---- */
pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---- Allow-list (pushed via JNI configure()) ---- */
static char **g_hosts      = NULL;
static int    g_host_count = 0;
static int    g_enforce    = 0;   /* 0 = monitor mode, 1 = enforce */

/* ---- Opt-in CIDR allow-list (pushed via JNI configureCidrs()) ---- */
static struct { int family; unsigned char net[16]; int prefix; } g_cidrs[64];
static int g_cidr_count = 0;

/* ---- Internal helpers ---- */

/* Caller MUST hold g_lock. */
static int host_allowed_locked(const char *name) {
    for (int i = 0; i < g_host_count; i++)
        if (poseidon_host_match(g_hosts[i], name)) return 1;
    return 0;
}

/* Check if ip (raw bytes, AF_INET or AF_INET6) falls within any declared CIDR.
 * Caller MUST hold g_lock.  Returns 1 on match.
 * A CIDR match is an address-range grant, NOT positive identity — it does not
 * set the `identified` flag in poseidon_check(). */
static int ip_in_allowed_cidr(int family, const void *ip) {
    int iplen = (family == AF_INET) ? 4 : 16;
    for (int i = 0; i < g_cidr_count; i++) {
        if (g_cidrs[i].family != family) continue;
        int prefix     = g_cidrs[i].prefix;
        int full_bytes = prefix / 8;
        int rem_bits   = prefix % 8;
        const unsigned char *a = (const unsigned char *) ip;
        const unsigned char *b = g_cidrs[i].net;
        if (full_bytes > iplen) full_bytes = iplen;
        if (memcmp(a, b, (size_t) full_bytes) != 0) continue;
        if (rem_bits > 0 && full_bytes < iplen) {
            unsigned char mask = (unsigned char)(0xFF << (8 - rem_bits));
            if ((a[full_bytes] & mask) != (b[full_bytes] & mask)) continue;
        }
        return 1;
    }
    return 0;
}

/* Normalise sa to (family, ip, iplen, port) with IPv4-mapped IPv6 unwrapped.
 * v4buf[4] is used as storage for the unwrapped IPv4 address.
 * Returns 0 = proceed; -1 = peer is exempt (P_NA). */
static int normalize_peer(const struct sockaddr *sa,
                           int *out_family, const void **out_ip,
                           int *out_iplen, int *out_port,
                           unsigned char v4buf[4]) {
    if (!sa) return -1;
    int family = sa->sa_family;
    if (family != AF_INET && family != AF_INET6) return -1; /* AF_UNIX etc. */

    int dport;
    const void *ip;
    int iplen;

    if (family == AF_INET) {
        dport = (int) ntohs(((const struct sockaddr_in *) sa)->sin_port);
        if (dport == 53) return -1;   /* DNS resolver traffic: exempt */
        ip    = &((const struct sockaddr_in *) sa)->sin_addr;
        iplen = 4;
        if (((const unsigned char *) ip)[0] == 127) return -1; /* loopback */
    } else {
        dport = (int) ntohs(((const struct sockaddr_in6 *) sa)->sin6_port);
        if (dport == 53) return -1;
        const struct in6_addr *a6 = &((const struct sockaddr_in6 *) sa)->sin6_addr;
        if (IN6_IS_ADDR_V4MAPPED(a6)) {
            /* ::ffff:a.b.c.d — match against the IPv4 DNS cache. */
            memcpy(v4buf, &a6->s6_addr[12], 4);
            family = AF_INET;
            ip     = v4buf;
            iplen  = 4;
            if (v4buf[0] == 127) return -1;
        } else if (IN6_IS_ADDR_LOOPBACK(a6)) {
            return -1;
        } else {
            ip    = a6;
            iplen = 16;
        }
    }

    *out_family = family;
    *out_ip     = ip;
    *out_iplen  = iplen;
    *out_port   = dport;
    return 0;
}

/* Pure policy evaluation.  Caller MUST hold g_lock.
 * Single pass over the DNS cache: finds both the first hostname (for desc) and
 * whether any cached hostname for this IP is on the allow-list.
 * Sets *identified if any cache entry positively maps ip.
 * Sets *has_cidrs to (g_cidr_count > 0) sampled under the lock. */
static poseidon_verdict_t evaluate_locked(
    const void *ip, int family, int iplen,
    const char *ipstr,
    char *desc, size_t dlen,
    int *identified, int *has_cidrs) {

    if (g_host_count == 0) return P_NA; /* not configured */

    int allowed          = 0;
    const char *hostname = ipstr;
    *identified          = 0;

    for (int i = 0; i < g_cache_size; i++) {
        if (g_cache[i].family != family) continue;
        if (memcmp(g_cache[i].addr, ip, (size_t) iplen) != 0) continue;
        /* First matching entry gives us the canonical hostname. */
        if (!(*identified)) {
            hostname    = g_cache[i].host;
            *identified = 1;
        }
        if (!allowed && host_allowed_locked(g_cache[i].host)) allowed = 1;
    }
    if (!allowed && host_allowed_locked(ipstr))       allowed = 1; /* IP literal */
    if (!allowed) allowed = ip_in_allowed_cidr(family, ip);        /* CIDR range */

    *has_cidrs = (g_cidr_count > 0);
    snprintf(desc, dlen, "%s (%s)", hostname, ipstr);

    if (allowed) return P_ALLOW;
    return g_enforce ? P_BLOCK : P_MONITOR_VIOL;
}

/* ---- Public API ---- */

int host_denied(const char *name) {
    if (!name || !name[0]) return 0;
    int denied = 0;
    pthread_mutex_lock(&g_lock);
    if (g_host_count > 0 && g_enforce && !host_allowed_locked(name)) denied = 1;
    pthread_mutex_unlock(&g_lock);
    return denied;
}

poseidon_verdict_t poseidon_check(const struct sockaddr *sa,
                                   char *desc, size_t dlen,
                                   int *identified, int *has_cidrs_out) {
    int id_local = 0, cidrs_local = 0;
    if (!identified)    identified    = &id_local;
    if (!has_cidrs_out) has_cidrs_out = &cidrs_local;
    *identified    = 0;
    *has_cidrs_out = 0;

    int family, iplen, port;
    const void *ip;
    unsigned char v4buf[4];
    if (normalize_peer(sa, &family, &ip, &iplen, &port, v4buf) != 0) return P_NA;

    char ipstr[INET6_ADDRSTRLEN] = {0};
    inet_ntop(family, ip, ipstr, sizeof(ipstr));

    pthread_mutex_lock(&g_lock);
    poseidon_verdict_t v = evaluate_locked(ip, family, iplen, ipstr,
                                           desc, dlen, identified, has_cidrs_out);
    pthread_mutex_unlock(&g_lock);
    return v;
}

/* ---- Policy setters called from jni_bridge.c ---- */

void policy_set_hosts(char **arr, int n, int enforce) {
    pthread_mutex_lock(&g_lock);
    if (g_hosts) {
        for (int i = 0; i < g_host_count; i++) free(g_hosts[i]);
        free(g_hosts);
    }
    g_hosts      = arr;
    g_host_count = n;
    g_enforce    = enforce;
    pthread_mutex_unlock(&g_lock);
}

void policy_set_cidrs(const poseidon_cidr_t *cidrs, int n) {
    if (n > 64) n = 64;
    pthread_mutex_lock(&g_lock);
    g_cidr_count = n;
    for (int i = 0; i < n; i++) {
        g_cidrs[i].family = cidrs[i].family;
        memcpy(g_cidrs[i].net, cidrs[i].net, 16);
        g_cidrs[i].prefix = cidrs[i].prefix;
    }
    pthread_mutex_unlock(&g_lock);
}
