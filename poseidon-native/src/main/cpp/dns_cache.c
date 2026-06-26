/* dns_cache.c — IP->hostname ring cache and raw DNS parsers for libposeidon_shim.
 *
 * cache_put / cache_addrinfo: populate the cache when libc resolvers return.
 * dns_qname / dns_skip_name / dns_answers / dns_first_a: parse raw DNS packets
 *   (used by the seccomp supervisor and rawResolve JNI test helper).
 *
 * g_lock (defined in policy_eval.c) is acquired around every cache write.
 * Reads under g_lock happen in poseidon_check() (policy_eval.c) which holds
 * the same lock, so there is no race on g_cache/g_cache_size.
 */
#define _GNU_SOURCE
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "shim_internal.h"

/* ---- IP -> hostname ring cache ---- */
dns_entry g_cache[CACHE_CAP];
int       g_cache_next = 0;
int       g_cache_size = 0;

void cache_put(int family, const void *addr, const char *host) {
    if (!host || !host[0]) return;
    int len = (family == AF_INET6) ? 16 : 4;
    pthread_mutex_lock(&g_lock);
    dns_entry *e = &g_cache[g_cache_next];
    e->family = family;
    memset(e->addr, 0, sizeof(e->addr));
    memcpy(e->addr, addr, (size_t) len);
    strncpy(e->host, host, sizeof(e->host) - 1);
    e->host[sizeof(e->host) - 1] = '\0';
    g_cache_next = (g_cache_next + 1) % CACHE_CAP;
    if (g_cache_size < CACHE_CAP) g_cache_size++;
    pthread_mutex_unlock(&g_lock);
}

void cache_addrinfo(const char *node, const struct addrinfo *res) {
    if (!node) return;
    for (const struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET)
            cache_put(AF_INET, &((struct sockaddr_in *) ai->ai_addr)->sin_addr, node);
        else if (ai->ai_family == AF_INET6)
            cache_put(AF_INET6, &((struct sockaddr_in6 *) ai->ai_addr)->sin6_addr, node);
    }
}

/* ---- Raw DNS packet parsers ---- */

int dns_qname(const unsigned char *p, size_t n, char *out, size_t outsz) {
    if (n < 13) return 0;
    size_t i = 12, o = 0;
    while (i < n) {
        unsigned char l = p[i++];
        if (l == 0) break;
        if (l & 0xC0) return 0; /* compression pointer in QNAME: bail */
        if (i + l > n) return 0;
        if (o && o < outsz - 1) out[o++] = '.';
        for (unsigned k = 0; k < l && o < outsz - 1; k++) out[o++] = (char) p[i + k];
        i += l;
    }
    out[o] = '\0';
    return o > 0;
}

void dns_skip_name(const unsigned char *p, size_t n, size_t *i) {
    while (*i < n) {
        unsigned char l = p[*i];
        if ((l & 0xC0) == 0xC0) { *i += 2; return; }
        if (l == 0)              { *i += 1; return; }
        *i += 1 + l;
    }
}

/* Walk the answer section of a DNS response; cache every A/AAAA record. */
void dns_answers(const unsigned char *p, size_t n, const char *host) {
    if (n < 12) return;
    unsigned qd = (p[4] << 8) | p[5];
    unsigned an = (p[6] << 8) | p[7];
    size_t i = 12;
    for (unsigned q = 0; q < qd && i < n; q++) { dns_skip_name(p, n, &i); i += 4; }
    for (unsigned a = 0; a < an && i + 10 <= n; a++) {
        dns_skip_name(p, n, &i);
        if (i + 10 > n) break;
        unsigned type  = (p[i] << 8) | p[i + 1];
        unsigned rdlen = (p[i + 8] << 8) | p[i + 9];
        i += 10;
        if (i + rdlen > n) break;
        if      (type == 1  && rdlen == 4)  cache_put(AF_INET,  &p[i], host);
        else if (type == 28 && rdlen == 16) cache_put(AF_INET6, &p[i], host);
        i += rdlen;
    }
}

/* Extract the first A-record IP from a DNS response into out[outsz].
 * Shares the answer-walk with dns_answers (deduplication of rawResolve). */
int dns_first_a(const unsigned char *p, size_t n, char *out, size_t outsz) {
    if (n < 12) return 0;
    unsigned qd = (p[4] << 8) | p[5];
    unsigned an = (p[6] << 8) | p[7];
    size_t i = 12;
    for (unsigned q = 0; q < qd && i < n; q++) { dns_skip_name(p, n, &i); i += 4; }
    for (unsigned a = 0; a < an && i + 10 <= n; a++) {
        dns_skip_name(p, n, &i);
        if (i + 10 > n) break;
        unsigned type  = (p[i] << 8) | p[i + 1];
        unsigned rdlen = (p[i + 8] << 8) | p[i + 9];
        i += 10;
        if (i + rdlen > n) break;
        if (type == 1 && rdlen == 4) {
            inet_ntop(AF_INET, &p[i], out, (socklen_t) outsz);
            return 1;
        }
        i += rdlen;
    }
    return 0;
}
