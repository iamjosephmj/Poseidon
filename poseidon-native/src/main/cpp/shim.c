// Poseidon native shim. Injected as the first DT_NEEDED of guarded native libs so
// their libc network calls resolve here. Enforces the compiled HOST ALLOW-LIST
// (default-deny) pushed in via JNI from PolicyEngine.
//
// How host enforcement works at the socket layer: getaddrinfo/android_getaddrinfofornet/
// gethostbyname hooks build an IP->hostname cache; connect/sendto/sendmsg resolve the
// peer IP back to hostname(s) and glob-match against the allow-list. Loopback and
// non-INET (AF_UNIX: netd/logd) traffic always passes. IP literals are matched too.
//
// DESIGN RULE (hot path): nothing in the interceptor path may log synchronously,
// take a lock, or allocate. connect/sendto/sendmsg/getaddrinfo decisions are pushed
// into the lock-free event ring (event_ring.h); the JVM drain thread reads them
// every ~250 ms and calls Observer.record().
//
// The thread-local reentrancy guard (in_poseidon) is kept as defence-in-depth
// even though ring_push no longer calls liblog or any socket function.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <fnmatch.h>
#include <unistd.h>
#include "host_match.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <jni.h>
#include <android/log.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "event_ring.h"

/* LOG is used ONLY for one-time init paths and fatal errors — NEVER on the
 * hot path (connect/sendto/getaddrinfo decision sites use ring_push instead). */
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "POSEIDON", __VA_ARGS__)

/* ---- hot-path helpers ---- */

/* Monotonic timestamp in nanoseconds for ring events (vDSO, very cheap). */
static uint64_t mono_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Destination port from a sockaddr (0 if unknown family). */
static int get_port(const struct sockaddr *sa) {
    if (!sa) return 0;
    if (sa->sa_family == AF_INET)
        return (int)ntohs(((const struct sockaddr_in *)sa)->sin_port);
    if (sa->sa_family == AF_INET6)
        return (int)ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
    return 0;
}

/* Extract the hostname from the "hostname (ipstr)" desc format that
 * poseidon_check() builds.  Output is truncated to fit ring_event.host[64]. */
static void desc_host(const char *desc, char *out, size_t sz) {
    if (!desc || !desc[0]) { out[0] = '\0'; return; }
    strncpy(out, desc, sz - 1u);
    out[sz - 1u] = '\0';
    char *paren = strstr(out, " (");
    if (paren) *paren = '\0';
}

// Resolve the calling .so via the wrapper's return address. MUST be expanded inside
// the interposed wrapper itself (connect/sendto/...) so the return address points
// into the SDK library that made the call. Returns a basename ("libcronet.so") or "?".
#define CALLER_SO() ({                                                  \
    Dl_info _di; void *_ra = __builtin_return_address(0);               \
    const char *_p = (dladdr(_ra, &_di) && _di.dli_fname) ? _di.dli_fname : "?"; \
    const char *_s = strrchr(_p, '/'); _s ? _s + 1 : _p;                \
})
static __thread int in_poseidon = 0;

// ---- policy (set via JNI) ----
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char **g_hosts = NULL;   // allow-list globs (hostnames and/or IP literals)
static int g_host_count = 0;
static int g_enforce = 0;       // 0 = monitor, 1 = enforce

// ---- IP -> hostname cache (ring buffer) ----
#define CACHE_CAP 4096
typedef struct {
    int family;
    unsigned char addr[16];
    char host[256];
} dns_entry;
static dns_entry g_cache[CACHE_CAP];
static int g_cache_next = 0, g_cache_size = 0;

static void cache_put(int family, const void *addr, const char *host) {
    if (!host || !host[0]) return;
    int len = (family == AF_INET6) ? 16 : 4;
    pthread_mutex_lock(&g_lock);
    dns_entry *e = &g_cache[g_cache_next];
    e->family = family;
    memset(e->addr, 0, sizeof(e->addr));
    memcpy(e->addr, addr, len);
    strncpy(e->host, host, sizeof(e->host) - 1);
    e->host[sizeof(e->host) - 1] = 0;
    g_cache_next = (g_cache_next + 1) % CACHE_CAP;
    if (g_cache_size < CACHE_CAP) g_cache_size++;
    pthread_mutex_unlock(&g_lock);
}

static int host_allowed_locked(const char *name) {
    for (int i = 0; i < g_host_count; i++)
        if (poseidon_host_match(g_hosts[i], name)) return 1;
    return 0;
}

// True if this hostname must be denied (configured allow-list, enforcing, not allowed).
// Used to block resolution of non-allow-listed names (default-deny at the DNS layer,
// which also shuts down DNS-tunnelling exfil to arbitrary names).
static int host_denied(const char *name) {
    if (!name || !name[0]) return 0;
    int denied = 0;
    pthread_mutex_lock(&g_lock);
    if (g_host_count > 0 && g_enforce && !host_allowed_locked(name)) denied = 1;
    pthread_mutex_unlock(&g_lock);
    return denied;
}

// Verdicts.
enum { P_NA = 0, P_ALLOW = 1, P_BLOCK = 2, P_MONITOR_VIOL = 3 };

// identified (optional out): set to 1 if the IP was positively mapped to a cached
// hostname (so callers can choose to block only positively-identified denials).
static int poseidon_check(const struct sockaddr *sa, char *desc, size_t dlen, int *identified) {
    if (identified) *identified = 0;
    if (!sa) return P_NA;
    int family = sa->sa_family;
    if (family != AF_INET && family != AF_INET6) return P_NA; // AF_UNIX etc.

    // DNS (port 53) is exempt: we gate the RESOLVED destination at connect, not the
    // resolver. Blocking DNS would break resolution (and our correlation).
    int dport = (family == AF_INET)
        ? ntohs(((const struct sockaddr_in *) sa)->sin_port)
        : ntohs(((const struct sockaddr_in6 *) sa)->sin6_port);
    if (dport == 53) return P_NA;

    const void *ip;
    int iplen;
    unsigned char v4buf[4];
    if (family == AF_INET) {
        ip = &((const struct sockaddr_in *) sa)->sin_addr;
        iplen = 4;
        if (((const unsigned char *) ip)[0] == 127) return P_NA; // loopback
    } else {
        const struct in6_addr *a6 = &((const struct sockaddr_in6 *) sa)->sin6_addr;
        if (IN6_IS_ADDR_V4MAPPED(a6)) {
            // ::ffff:a.b.c.d — match against the IPv4 DNS cache.
            memcpy(v4buf, &a6->s6_addr[12], 4);
            family = AF_INET;
            ip = v4buf;
            iplen = 4;
            if (v4buf[0] == 127) return P_NA;
        } else if (IN6_IS_ADDR_LOOPBACK(a6)) {
            return P_NA;
        } else {
            ip = a6;
            iplen = 16;
        }
    }
    char ipstr[INET6_ADDRSTRLEN] = {0};
    inet_ntop(family, ip, ipstr, sizeof(ipstr));

    pthread_mutex_lock(&g_lock);
    if (g_host_count == 0) { pthread_mutex_unlock(&g_lock); return P_NA; } // not configured

    int allowed = 0;
    const char *matched = ipstr;
    for (int i = 0; i < g_cache_size && !allowed; i++) {
        if (g_cache[i].family == family && memcmp(g_cache[i].addr, ip, iplen) == 0) {
            if (host_allowed_locked(g_cache[i].host)) { allowed = 1; matched = g_cache[i].host; }
        }
    }
    if (!allowed && host_allowed_locked(ipstr)) allowed = 1; // IP literal in allow-list
    // build desc (best-effort hostname)
    const char *hostname = ipstr;
    for (int i = 0; i < g_cache_size; i++) {
        if (g_cache[i].family == family && memcmp(g_cache[i].addr, ip, iplen) == 0) {
            hostname = g_cache[i].host;
            if (identified) *identified = 1; // positively mapped IP -> host
            break;
        }
    }
    int enforce = g_enforce;
    snprintf(desc, dlen, "%s (%s)", hostname, ipstr);
    pthread_mutex_unlock(&g_lock);
    (void) matched;

    if (allowed) return P_ALLOW;
    return enforce ? P_BLOCK : P_MONITOR_VIOL;
}

// Record verdict via the async ring (HOT PATH — no LOG, no lock, no alloc).
// `transport`: 0=TCP/unknown  1=UDP  2=DNS.  `tier`: 0=libc  1=seccomp.
// `origin`: return address into the calling SDK .so (symbolised off-path).
// Returns 1 if the call must be blocked, 0 otherwise.
static int act(int verdict, const char *desc, int port, int transport, int tier,
               uint64_t origin) {
    if (verdict == P_NA) return 0; // loopback/AF_UNIX/DNS-resolver/unconfigured: silent

    char host[64];
    desc_host(desc, host, sizeof host);
    int blocked = (verdict == P_BLOCK) ? 1 : 0;
    ring_push(mono_ns(), host, port, transport, tier, blocked, origin);
    return blocked;
}

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    int (*real)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "connect");
    if (in_poseidon) return real(fd, addr, len);
    in_poseidon = 1;
    char desc[320];
    uint64_t origin = (uint64_t)(uintptr_t)__builtin_return_address(0);
    int blk = act(poseidon_check(addr, desc, sizeof desc, NULL), desc,
                  get_port(addr), 0 /*TCP*/, 0 /*libc*/, origin);
    in_poseidon = 0;
    if (blk) { errno = ECONNREFUSED; return -1; }
    return real(fd, addr, len);
}

ssize_t sendto(int fd, const void *buf, size_t n, int flags,
               const struct sockaddr *to, socklen_t tolen) {
    ssize_t (*real)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) =
        dlsym(RTLD_NEXT, "sendto");
    if (in_poseidon || !to) return real(fd, buf, n, flags, to, tolen);
    in_poseidon = 1;
    char desc[320];
    uint64_t origin = (uint64_t)(uintptr_t)__builtin_return_address(0);
    int blk = act(poseidon_check(to, desc, sizeof desc, NULL), desc,
                  get_port(to), 1 /*UDP*/, 0 /*libc*/, origin);
    in_poseidon = 0;
    if (blk) { errno = ECONNREFUSED; return -1; }
    return real(fd, buf, n, flags, to, tolen);
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
    ssize_t (*real)(int, const struct msghdr *, int) = dlsym(RTLD_NEXT, "sendmsg");
    if (in_poseidon || !msg || !msg->msg_name) return real(fd, msg, flags);
    in_poseidon = 1;
    char desc[320];
    const struct sockaddr *dst = (const struct sockaddr *)msg->msg_name;
    uint64_t origin = (uint64_t)(uintptr_t)__builtin_return_address(0);
    int blk = act(poseidon_check(dst, desc, sizeof desc, NULL), desc,
                  get_port(dst), 1 /*UDP*/, 0 /*libc*/, origin);
    in_poseidon = 0;
    if (blk) { errno = ECONNREFUSED; return -1; }
    return real(fd, msg, flags);
}

int sendmmsg(int fd, const struct mmsghdr *msgvec, unsigned int vlen, int flags) {
    int (*real)(int, const struct mmsghdr *, unsigned int, int) = dlsym(RTLD_NEXT, "sendmmsg");
    if (in_poseidon || !msgvec || vlen == 0 || !msgvec[0].msg_hdr.msg_name)
        return real(fd, msgvec, vlen, flags);
    in_poseidon = 1;
    char desc[320];
    const struct sockaddr *dst = (const struct sockaddr *)msgvec[0].msg_hdr.msg_name;
    uint64_t origin = (uint64_t)(uintptr_t)__builtin_return_address(0);
    int blk = act(poseidon_check(dst, desc, sizeof desc, NULL), desc,
                  get_port(dst), 1 /*UDP*/, 0 /*libc*/, origin);
    in_poseidon = 0;
    if (blk) { errno = ECONNREFUSED; return -1; }
    return real(fd, msgvec, vlen, flags);
}

static void cache_addrinfo(const char *node, const struct addrinfo *res) {
    if (!node) return;
    for (const struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET)
            cache_put(AF_INET, &((struct sockaddr_in *) ai->ai_addr)->sin_addr, node);
        else if (ai->ai_family == AF_INET6)
            cache_put(AF_INET6, &((struct sockaddr_in6 *) ai->ai_addr)->sin6_addr, node);
    }
}

int getaddrinfo(const char *node, const char *svc,
                const struct addrinfo *hints, struct addrinfo **res) {
    int (*real)(const char *, const char *, const struct addrinfo *, struct addrinfo **) =
        dlsym(RTLD_NEXT, "getaddrinfo");
    if (in_poseidon) return real(node, svc, hints, res);
    if (host_denied(node)) {  // default-deny: refuse to resolve non-allow-listed names
        ring_push(mono_ns(), node, 0, 2 /*DNS*/, 0 /*libc*/, 1 /*blocked*/, 0);
        return EAI_FAIL;
    }
    int r = real(node, svc, hints, res);
    if (r == 0 && res && *res) {
        in_poseidon = 1;
        cache_addrinfo(node, *res);
        in_poseidon = 0;
    }
    return r;
}

extern int android_getaddrinfofornet(const char *, const char *, const struct addrinfo *,
                                     unsigned, unsigned, struct addrinfo **);
int android_getaddrinfofornet(const char *node, const char *svc, const struct addrinfo *hints,
                              unsigned netid, unsigned mark, struct addrinfo **res) {
    int (*real)(const char *, const char *, const struct addrinfo *, unsigned, unsigned, struct addrinfo **) =
        dlsym(RTLD_NEXT, "android_getaddrinfofornet");
    if (!real) {
        int (*ga)(const char *, const char *, const struct addrinfo *, struct addrinfo **) =
            dlsym(RTLD_NEXT, "getaddrinfo");
        return ga(node, svc, hints, res);
    }
    if (in_poseidon) return real(node, svc, hints, netid, mark, res);
    if (host_denied(node)) {
        ring_push(mono_ns(), node, 0, 2 /*DNS*/, 0 /*libc*/, 1 /*blocked*/, 0);
        return EAI_FAIL;
    }
    int r = real(node, svc, hints, netid, mark, res);
    if (r == 0 && res && *res) {
        in_poseidon = 1;
        cache_addrinfo(node, *res);
        in_poseidon = 0;
    }
    return r;
}

struct hostent *gethostbyname(const char *name) {
    struct hostent *(*real)(const char *) = dlsym(RTLD_NEXT, "gethostbyname");
    struct hostent *he = real(name);
    if (he && he->h_addr_list && name) {
        for (char **p = he->h_addr_list; *p; p++)
            cache_put(he->h_addrtype, *p, name);
    }
    return he;
}

// ---- JNI: feasibility probe for in-process seccomp (to cover Go/raw-syscall) ----
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
JNIEXPORT void JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_seccompProbe(JNIEnv *env, jobject thiz) {
    LOG("seccomp probe: start (app domain)");
    int nnp = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    LOG("seccomp: PR_SET_NO_NEW_PRIVS=%d errno=%d", nnp, errno);

    struct sock_filter allow[] = { BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW) };
    struct sock_fprog ap = { .len = 1, .filter = allow };

    errno = 0;
    int pr = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &ap, 0, 0);
    LOG("seccomp: prctl(PR_SET_SECCOMP allow-all)=%d errno=%d (%s)",
        pr, errno, pr < 0 ? strerror(errno) : "OK");

    errno = 0;
    long lf = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &ap);
    LOG("seccomp: USER_NOTIF fd=%ld errno=%d (%s)",
        lf, errno, lf < 0 ? strerror(errno) : "OK");
    if (lf >= 0) close((int) lf);
    LOG("seccomp probe: done");
}

// ---- seccomp USER_NOTIF gate: covers Go/raw-syscall by trapping connect() at
// the kernel syscall boundary (below libc). Supervisor thread is created BEFORE
// the filter is installed, so it stays UNFILTERED (its own syscalls never trap).
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOCTL_NOTIF_RECV _IOWR('!', 0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND _IOWR('!', 1, struct seccomp_notif_resp)
#define SECCOMP_IOCTL_NOTIF_ID_VALID _IOW('!', 2, __u64)
#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425 // same NR across arm64/arm/x86_64/x86
#endif

static int g_notif_fd = -1;
static pthread_t g_supervisor;

// ---- in-process DNS correlation: parse raw DNS (UDP:53) to learn IP->host for
// resolvers that bypass libc getaddrinfo (e.g. Go's pure resolver). ----
#define DNSMAP_CAP 256
typedef struct { int fd; char host[256]; } dns_fd_entry;
static dns_fd_entry g_dnsmap[DNSMAP_CAP];
static int g_dnsmap_next = 0;
static pthread_mutex_t g_dnsmap_lock = PTHREAD_MUTEX_INITIALIZER;

static void dnsmap_put(int fd, const char *host) {
    pthread_mutex_lock(&g_dnsmap_lock);
    g_dnsmap[g_dnsmap_next].fd = fd;
    strncpy(g_dnsmap[g_dnsmap_next].host, host, 255);
    g_dnsmap[g_dnsmap_next].host[255] = 0;
    g_dnsmap_next = (g_dnsmap_next + 1) % DNSMAP_CAP;
    pthread_mutex_unlock(&g_dnsmap_lock);
}
static int dnsmap_get(int fd, char *out, size_t outsz) {
    int found = 0;
    pthread_mutex_lock(&g_dnsmap_lock);
    for (int i = 0; i < DNSMAP_CAP; i++) {
        if (g_dnsmap[i].fd == fd && g_dnsmap[i].host[0]) {
            strncpy(out, g_dnsmap[i].host, outsz - 1);
            out[outsz - 1] = 0;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_dnsmap_lock);
    return found;
}

// Parse the QNAME from a DNS query packet -> dotted hostname.
static int dns_qname(const unsigned char *p, size_t n, char *out, size_t outsz) {
    if (n < 13) return 0;
    size_t i = 12, o = 0;
    while (i < n) {
        unsigned char l = p[i++];
        if (l == 0) break;
        if (l & 0xC0) return 0;
        if (i + l > n) return 0;
        if (o && o < outsz - 1) out[o++] = '.';
        for (unsigned k = 0; k < l && o < outsz - 1; k++) out[o++] = (char) p[i + k];
        i += l;
    }
    out[o] = 0;
    return o > 0;
}

// skip a DNS name (labels or compression pointer) starting at *i.
static void dns_skip_name(const unsigned char *p, size_t n, size_t *i) {
    while (*i < n) {
        unsigned char l = p[*i];
        if ((l & 0xC0) == 0xC0) { *i += 2; return; }
        if (l == 0) { *i += 1; return; }
        *i += 1 + l;
    }
}

// Parse A/AAAA answers from a DNS response and cache each IP -> host.
static void dns_answers(const unsigned char *p, size_t n, const char *host) {
    if (n < 12) return;
    unsigned qd = (p[4] << 8) | p[5];
    unsigned an = (p[6] << 8) | p[7];
    size_t i = 12;
    for (unsigned q = 0; q < qd && i < n; q++) { dns_skip_name(p, n, &i); i += 4; }
    for (unsigned a = 0; a < an && i + 10 <= n; a++) {
        dns_skip_name(p, n, &i);
        if (i + 10 > n) break;
        unsigned type = (p[i] << 8) | p[i + 1];
        unsigned rdlen = (p[i + 8] << 8) | p[i + 9];
        i += 10;
        if (i + rdlen > n) break;
        if (type == 1 && rdlen == 4) cache_put(AF_INET, &p[i], host);
        else if (type == 28 && rdlen == 16) cache_put(AF_INET6, &p[i], host);
        i += rdlen;
    }
}

static int sockaddr_port(const struct sockaddr *sa) {
    if (!sa) return -1;
    if (sa->sa_family == AF_INET) return ntohs(((const struct sockaddr_in *) sa)->sin_port);
    if (sa->sa_family == AF_INET6) return ntohs(((const struct sockaddr_in6 *) sa)->sin6_port);
    return -1;
}

static void *seccomp_supervisor(void *arg) {
    (void) arg;
    // Wait until the main thread publishes the listener fd.
    while (__atomic_load_n(&g_notif_fd, __ATOMIC_ACQUIRE) < 0) usleep(1000);
    int fd = g_notif_fd;
    for (;;) {
        struct seccomp_notif req;
        memset(&req, 0, sizeof(req));
        if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &req) != 0) {
            if (errno == EINTR) continue;
            break; // listener gone
        }
        struct seccomp_notif_resp resp;
        memset(&resp, 0, sizeof(resp));
        resp.id = req.id;
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; // default: let it proceed
        __u64 id = req.id;
        int valid = (ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0);
        long nr = req.data.nr;

        if (valid && nr == __NR_connect) {
            // TOCTOU-safe: copy the sockaddr into our own buffer and decide on THAT.
            // The trapped thread is suspended; we never let the kernel re-read the
            // (swappable) user pointer — for allowed connects we perform the connect
            // ourselves with the trusted copy instead of using CONTINUE.
            socklen_t alen = (socklen_t) req.data.args[2];
            const void *uaddr = (const void *) (uintptr_t) req.data.args[1];
            if (uaddr && alen > 0) {
                struct sockaddr_storage ss;
                memset(&ss, 0, sizeof ss);
                if (alen > (socklen_t) sizeof ss) alen = (socklen_t) sizeof ss;
                memcpy(&ss, uaddr, alen);
                char desc[320];
                // Positive-identity enforcement: block only when the destination IP is
                // positively mapped (via the DNS-correlation cache) to a DENIED host. A
                // cache-miss / unidentified IP CONTINUEs instead of being default-denied —
                // this avoids the strict-by-IP CDN over-block for platform-resolver (JVM)
                // clients on rotating CDNs (e.g. example.com on Cloudflare), at the cost of
                // letting an un-correlated raw/Go connect to a bare IP through (the
                // sendto/recvfrom DNS-correlation layer is what turns those into identified
                // denials). JVM clients are still gated by the bytecode adapters at the
                // Java layer; this tier covers native/Go traffic by positive identity.
                int identified = 0;
                int v = poseidon_check((const struct sockaddr *) &ss, desc, sizeof desc, &identified);
                int do_block = (v == P_BLOCK && identified);
                if (do_block || v == P_MONITOR_VIOL) {
                    /* emit to ring (HOT PATH — no LOG) */
                    char shost[64];
                    desc_host(desc, shost, sizeof shost);
                    ring_push(mono_ns(), shost,
                              get_port((const struct sockaddr *)&ss),
                              0 /*TCP*/, 1 /*seccomp*/,
                              do_block ? 1 : 0, 0);
                }
                if (do_block) {
                    resp.flags = 0;
                    resp.error = -EACCES;
                } else if (v == P_MONITOR_VIOL || v == P_BLOCK) {
                    // CONTINUE: monitor-mode would-block, OR an unidentified (cache-miss)
                    // deny — let the kernel re-execute the real connect. resp.flags keeps
                    // the default SECCOMP_USER_NOTIF_FLAG_CONTINUE set before the dispatch.
                } else {
                    // P_ALLOW / P_NA: emulate the connect with the trusted copy (no CONTINUE,
                    // so the destination can't be swapped after the check).
                    int cfd = (int) req.data.args[0];
                    int r = connect(cfd, (struct sockaddr *) &ss, alen);
                    resp.flags = 0;
                    resp.val = (r == 0) ? 0 : -1;
                    resp.error = (r == 0) ? 0 : -errno;
                }
            }
        } else if (valid && nr == __NR_sendto) {
            const struct sockaddr *dst = (const struct sockaddr *) (uintptr_t) req.data.args[4];
            if (sockaddr_port(dst) == 53) {
                // DNS query: record fd -> hostname (or deny non-allow-listed name).
                const unsigned char *buf = (const unsigned char *) (uintptr_t) req.data.args[1];
                size_t len = (size_t) req.data.args[2];
                char host[256];
                if (buf && len >= 13 && dns_qname(buf, len, host, sizeof host)) {
                    if (host_denied(host)) {
                        ring_push(mono_ns(), host, 53, 2 /*DNS*/, 1 /*seccomp*/, 1 /*blocked*/, 0);
                        resp.flags = 0;
                        resp.error = -EACCES;
                    } else {
                        dnsmap_put((int) req.data.args[0], host);
                        ring_push(mono_ns(), host, 53, 2 /*DNS*/, 1 /*seccomp*/, 0 /*allowed*/, 0);
                    }
                }
            } else if (dst) {
                // Connectionless UDP (no connect()) to an arbitrary host — enforce the
                // allow-list, like connect(). Covers raw-syscall WriteToUDP etc.
                char desc[320];
                if (poseidon_check(dst, desc, sizeof desc, NULL) == P_BLOCK) {
                    char shost[64]; desc_host(desc, shost, sizeof shost);
                    ring_push(mono_ns(), shost, get_port(dst),
                              1 /*UDP*/, 1 /*seccomp*/, 1 /*blocked*/, 0);
                    resp.flags = 0;
                    resp.error = -EACCES;
                }
            }
        } else if (valid && (nr == __NR_sendmsg || nr == __NR_sendmmsg)) {
            // Connectionless UDP via sendmsg/sendmmsg: enforce each msg's destination
            // (msg_name). A NULL msg_name means a connected socket (connect() already
            // gated it). sendmmsg carries an array of messages.
            unsigned vlen = (nr == __NR_sendmmsg) ? (unsigned) req.data.args[2] : 1;
            if (vlen > 64) vlen = 64;
            for (unsigned k = 0; k < vlen; k++) {
                const struct msghdr *m;
                if (nr == __NR_sendmmsg)
                    m = &((const struct mmsghdr *) (uintptr_t) req.data.args[1])[k].msg_hdr;
                else
                    m = (const struct msghdr *) (uintptr_t) req.data.args[1];
                if (!m || !m->msg_name) continue;
                const struct sockaddr *dst = (const struct sockaddr *) m->msg_name;
                if (sockaddr_port(dst) == 53) continue; // resolver handled elsewhere
                char desc[320];
                if (poseidon_check(dst, desc, sizeof desc, NULL) == P_BLOCK) {
                    char shost[64]; desc_host(desc, shost, sizeof shost);
                    ring_push(mono_ns(), shost, get_port(dst),
                              1 /*UDP*/, 1 /*seccomp*/, 1 /*blocked*/, 0);
                    resp.flags = 0;
                    resp.error = -EACCES;
                    break;
                }
            }
        } else if (valid && nr == __NR_recvfrom) {
            int rfd = (int) req.data.args[0];
            int flags = (int) req.data.args[3];
            char host[256];
            if (!(flags & MSG_PEEK) && dnsmap_get(rfd, host, sizeof host)) {
                // Emulate the recvfrom in-process: read the DNS response, parse answers
                // into the IP->host cache, copy the data back to the caller's buffer.
                unsigned char tmp[2048];
                size_t want = (size_t) req.data.args[2];
                if (want > sizeof tmp) want = sizeof tmp;
                struct sockaddr_storage src;
                socklen_t srclen = sizeof src;
                ssize_t got = recvfrom(rfd, tmp, want, flags, (struct sockaddr *) &src, &srclen);
                if (got > 0) {
                    dns_answers(tmp, (size_t) got, host);
                    void *ubuf = (void *) (uintptr_t) req.data.args[1];
                    if (ubuf) memcpy(ubuf, tmp, (size_t) got);
                    void *usrc = (void *) (uintptr_t) req.data.args[4];
                    if (usrc) memcpy(usrc, &src, srclen);
                }
                resp.flags = 0; // we performed the syscall
                resp.val = got;
                resp.error = (got < 0) ? -errno : 0;
            }
        }
        ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
    }
    return NULL;
}

JNIEXPORT jint JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_installSeccomp(JNIEnv *env, jobject thiz, jint dnsCorrelation) {
// Enabled on every ABI with a direct connect syscall (arm64, arm32, x86_64, x86).
#if defined(__NR_connect)
    LOG("seccomp gate: starting supervisor"); // also warms up liblog before the filter
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        LOG("seccomp gate: NO_NEW_PRIVS failed errno=%d", errno);
        return -1;
    }
    // Create the supervisor BEFORE installing the filter, so it is not itself filtered.
    if (pthread_create(&g_supervisor, NULL, seccomp_supervisor, NULL) != 0) {
        LOG("seccomp gate: supervisor thread create failed");
        return -1;
    }
    // Always trap connect (cheap host enforcement). Trap sendto/recvfrom ONLY when DNS
    // correlation is opted in (per-datagram ~160us cost — off by default).
    // io_uring is already blocked for apps by Android's platform seccomp; we deny
    // io_uring_setup here too as defense-in-depth (it can perform connect/send
    // without the connect syscall, bypassing the gate).
    const __u32 RET_DENY = SECCOMP_RET_ERRNO | (EACCES & SECCOMP_RET_DATA);
    struct sock_filter conn_only[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 2, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, RET_DENY),
    };
    struct sock_filter with_dns[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 6, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto, 5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvfrom, 4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmmsg, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 2, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, RET_DENY),
    };
    struct sock_fprog prog;
    if (dnsCorrelation) { prog.len = 10; prog.filter = with_dns; }
    else { prog.len = 6; prog.filter = conn_only; }
    long fd = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (fd < 0) {
        LOG("seccomp gate: install failed errno=%d (%s)", errno, strerror(errno));
        return -1;
    }
    __atomic_store_n(&g_notif_fd, (int) fd, __ATOMIC_RELEASE);
    LOG("seccomp gate: ACTIVE on connect()%s (fd=%ld)",
        dnsCorrelation ? " + sendto/recvfrom (DNS correlation)" : "", fd);
    return 0;
#else
    (void) env; (void) thiz; (void) dnsCorrelation;
    LOG("seccomp gate: no direct connect syscall on this ABI, skipped");
    return -2;
#endif
}

// Test helper: issue connect() as a RAW syscall (bypasses the libc connect symbol,
// like Go) so we can verify the seccomp gate catches it. Returns errno (0 on success).
JNIEXPORT jint JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_rawConnect(
    JNIEnv *env, jobject thiz, jstring jip, jint port) {
    const char *ip = (*env)->GetStringUTFChars(env, jip, NULL);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t) port);
    inet_pton(AF_INET, ip, &a.sin_addr);
    errno = 0;
    long r = syscall(__NR_connect, s, (struct sockaddr *) &a, (socklen_t) sizeof(a));
    int e = (r < 0) ? errno : 0;
    (*env)->ReleaseStringUTFChars(env, jip, ip);
    close(s);
    return e;
}

// Test helper: RAW-syscall connectionless UDP sendto (no connect), like Go's
// WriteToUDP. Returns errno (13/EACCES if the seccomp gate blocked it).
JNIEXPORT jint JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_rawSendto(JNIEnv *env, jobject thiz, jstring jip, jint jport) {
    const char *ip = (*env)->GetStringUTFChars(env, jip, NULL);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short) jport);
    inet_pton(AF_INET, ip, &a.sin_addr);
    const char *msg = "x";
    errno = 0;
    long r = syscall(__NR_sendto, s, msg, 1, 0, (struct sockaddr *) &a, (socklen_t) sizeof a);
    int e = (r < 0) ? errno : 0;
    (*env)->ReleaseStringUTFChars(env, jip, ip);
    close(s);
    return e;
}

// Test helper: resolve a host via RAW DNS (sendto/recvfrom to 8.8.8.8:53, like Go's
// pure resolver). The seccomp supervisor records the query + parses the answer into
// the IP->host cache. Returns the first A-record IP (or null).
JNIEXPORT jstring JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_rawResolve(JNIEnv *env, jobject thiz, jstring jhost) {
    const char *host = (*env)->GetStringUTFChars(env, jhost, NULL);
    unsigned char q[300];
    int ql = 0;
    q[ql++] = 0x12; q[ql++] = 0x34; q[ql++] = 0x01; q[ql++] = 0x00;
    q[ql++] = 0; q[ql++] = 1; q[ql++] = 0; q[ql++] = 0;
    q[ql++] = 0; q[ql++] = 0; q[ql++] = 0; q[ql++] = 0;
    const char *p = host;
    while (*p && ql < 280) {
        const char *dot = strchr(p, '.');
        int len = dot ? (int) (dot - p) : (int) strlen(p);
        if (len <= 0 || len > 63) break;
        q[ql++] = (unsigned char) len;
        memcpy(&q[ql], p, len); ql += len;
        p += len; if (*p == '.') p++;
    }
    q[ql++] = 0; q[ql++] = 0; q[ql++] = 1; q[ql++] = 0; q[ql++] = 1;

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct timeval tv = { 3, 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct sockaddr_in dns;
    memset(&dns, 0, sizeof dns);
    dns.sin_family = AF_INET; dns.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &dns.sin_addr);
    sendto(s, q, ql, 0, (struct sockaddr *) &dns, sizeof dns);
    unsigned char r[1500];
    ssize_t n = recvfrom(s, r, sizeof r, 0, NULL, NULL);
    close(s);
    (*env)->ReleaseStringUTFChars(env, jhost, host);

    char ipout[64];
    ipout[0] = 0;
    if (n > 12) {
        unsigned qd = (r[4] << 8) | r[5], an = (r[6] << 8) | r[7];
        size_t i = 12;
        for (unsigned k = 0; k < qd && i < (size_t) n; k++) { dns_skip_name(r, n, &i); i += 4; }
        for (unsigned k = 0; k < an && i + 10 <= (size_t) n; k++) {
            dns_skip_name(r, n, &i);
            if (i + 10 > (size_t) n) break;
            unsigned type = (r[i] << 8) | r[i + 1];
            unsigned rdlen = (r[i + 8] << 8) | r[i + 9];
            i += 10;
            if (type == 1 && rdlen == 4) { inet_ntop(AF_INET, &r[i], ipout, sizeof ipout); break; }
            i += rdlen;
        }
    }
    return ipout[0] ? (*env)->NewStringUTF(env, ipout) : NULL;
}

// JNI: the JVM layer pushes resolved IPs for an ALLOWED host into the cache, so the
// seccomp connect gate recognizes the host's IPs (platform/JVM resolution bypasses
// our libc getaddrinfo hook — this closes the strict-mode over-block for JVM clients).
JNIEXPORT void JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_cacheHost(
    JNIEnv *env, jobject thiz, jstring jhost, jobjectArray jips) {
    const char *host = (*env)->GetStringUTFChars(env, jhost, NULL);
    int n = (*env)->GetArrayLength(env, jips);
    for (int i = 0; i < n; i++) {
        jstring s = (jstring) (*env)->GetObjectArrayElement(env, jips, i);
        const char *ip = (*env)->GetStringUTFChars(env, s, NULL);
        char clean[64];
        strncpy(clean, ip, sizeof clean - 1);
        clean[sizeof clean - 1] = 0;
        char *pct = strchr(clean, '%'); // strip IPv6 zone id
        if (pct) *pct = 0;
        struct in_addr a4;
        struct in6_addr a6;
        if (inet_pton(AF_INET, clean, &a4) == 1) cache_put(AF_INET, &a4, host);
        else if (inet_pton(AF_INET6, clean, &a6) == 1) cache_put(AF_INET6, &a6, host);
        (*env)->ReleaseStringUTFChars(env, s, ip);
        (*env)->DeleteLocalRef(env, s);
    }
    (*env)->ReleaseStringUTFChars(env, jhost, host);
}

// ---- JNI: PolicyEngine pushes the compiled policy here at startup ----
JNIEXPORT void JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_configure(
    JNIEnv *env, jobject thiz, jobjectArray hosts, jint enforce) {
    int n = (*env)->GetArrayLength(env, hosts);
    char **arr = (char **) calloc(n > 0 ? n : 1, sizeof(char *));
    for (int i = 0; i < n; i++) {
        jstring s = (jstring) (*env)->GetObjectArrayElement(env, hosts, i);
        const char *c = (*env)->GetStringUTFChars(env, s, NULL);
        arr[i] = strdup(c);
        (*env)->ReleaseStringUTFChars(env, s, c);
        (*env)->DeleteLocalRef(env, s);
    }
    pthread_mutex_lock(&g_lock);
    if (g_hosts) { for (int i = 0; i < g_host_count; i++) free(g_hosts[i]); free(g_hosts); }
    g_hosts = arr;
    g_host_count = n;
    g_enforce = enforce;
    pthread_mutex_unlock(&g_lock);
    LOG("native policy: %d allowed host(s), enforce=%d", n, enforce);
}

// ---- JNI: async ring drain (Task 5.1) ----
// Drains up to 64 ring events per call; returns them as an array of compact
// strings: "ts|host|port|transport|tier|blocked|origin_addr". The Kotlin drain
// thread calls this every ~250 ms and parses each string into an EgressEvent.
// Marshalling with String[] is cheap for 0..64 events per call.
#define DRAIN_BATCH 64
JNIEXPORT jobjectArray JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_drainEvents(JNIEnv *env, jobject thiz) {
    (void) thiz;
    struct ring_event buf[DRAIN_BATCH];
    int n = ring_drain(buf, DRAIN_BATCH);

    jclass str_class = (*env)->FindClass(env, "java/lang/String");
    jobjectArray arr = (*env)->NewObjectArray(env, (jsize) n, str_class, NULL);
    char tmp[256];
    for (int i = 0; i < n; i++) {
        snprintf(tmp, sizeof tmp, "%llu|%s|%d|%d|%d|%d|%llu",
                 (unsigned long long) buf[i].ts,
                 buf[i].host,
                 buf[i].port,
                 buf[i].transport,
                 buf[i].tier,
                 buf[i].blocked,
                 (unsigned long long) buf[i].origin_addr);
        jstring js = (*env)->NewStringUTF(env, tmp);
        (*env)->SetObjectArrayElement(env, arr, (jsize) i, js);
        (*env)->DeleteLocalRef(env, js);
    }
    return arr;
}

// ---- JNI: dladdr-backed symbolizer (Task 5.1) ----
// Returns the .so path (dli_fname) that contains `addr`, or null. Called
// off the hot path by the Kotlin drain thread to attribute events to SDKs.
JNIEXPORT jstring JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_symbolize(JNIEnv *env, jobject thiz, jlong addr) {
    (void) thiz;
    Dl_info info;
    if (addr != 0 && dladdr((void *)(uintptr_t)(uint64_t) addr, &info) && info.dli_fname)
        return (*env)->NewStringUTF(env, info.dli_fname);
    return NULL;
}
