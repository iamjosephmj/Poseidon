/* interpose.c — libc network call interceptors for libposeidon_shim.
 *
 * This TU is injected as the FIRST DT_NEEDED of every guarded native lib, so its
 * libc symbols resolve ahead of the real libc.  The interceptors enforce the
 * compiled HOST ALLOW-LIST (default-deny) pushed via JNI from PolicyEngine.
 *
 * HOT PATH RULE: nothing in connect/sendto/sendmsg/sendmmsg may log, take a lock,
 * or allocate.  Decisions are pushed into the lock-free event ring (event_ring.h);
 * the JVM drain thread reads them every ~250 ms.
 *
 * in_poseidon: thread-local reentrancy guard — defence-in-depth so that any
 * internal socket call (e.g. dladdr on some platforms) cannot recurse here.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "shim_internal.h"

/* LOG is used ONLY for one-time init paths and fatal errors. */
#include <android/log.h>
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "POSEIDON", __VA_ARGS__)

/* ---- Reentrancy guard ---- */
static __thread int in_poseidon = 0;

/* ---- Resolve the calling .so via the wrapper's return address.
 * MUST be expanded inside the interposed wrapper itself so the return address
 * points into the SDK library that made the call.  Returns basename or "?". */
#define CALLER_SO() ({                                                           \
    Dl_info _di; void *_ra = __builtin_return_address(0);                        \
    const char *_p = (dladdr(_ra, &_di) && _di.dli_fname) ? _di.dli_fname : "?";\
    const char *_s = strrchr(_p, '/'); _s ? _s + 1 : _p;                        \
})

/* ---- Hot-path helpers ---- */

int get_port(const struct sockaddr *sa) {
    if (!sa) return 0;
    if (sa->sa_family == AF_INET)
        return (int) ntohs(((const struct sockaddr_in *)  sa)->sin_port);
    if (sa->sa_family == AF_INET6)
        return (int) ntohs(((const struct sockaddr_in6 *) sa)->sin6_port);
    return 0;
}

/* Extract the hostname from the "hostname (ipstr)" desc format built by
 * poseidon_check().  Output is truncated to sz bytes (NUL-terminated). */
void host_from_desc(const char *desc, char *out, size_t sz) {
    if (!desc || !desc[0]) { out[0] = '\0'; return; }
    strncpy(out, desc, sz - 1u);
    out[sz - 1u] = '\0';
    char *paren = strstr(out, " (");
    if (paren) *paren = '\0';
}

/* Record a verdict into the async ring (HOT PATH — no LOG, no lock, no alloc).
 * Returns 1 if the call must be blocked, 0 otherwise. */
static int emit_verdict(poseidon_verdict_t verdict, const char *desc, int port,
                        int transport, int tier, uint64_t origin) {
    if (verdict == P_NA) return 0; /* loopback / AF_UNIX / DNS / unconfigured */
    char host[64];
    host_from_desc(desc, host, sizeof host);
    int blocked = (verdict == P_BLOCK) ? 1 : 0;
    ring_push(mono_ns(), host, port, transport, tier, blocked, origin);
    return blocked;
}

/* ---- libc interpose wrappers ---- */

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    int (*real)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "connect");
    if (in_poseidon) return real(fd, addr, len);
    in_poseidon = 1;
    char desc[320];
    uint64_t origin = (uint64_t)(uintptr_t)__builtin_return_address(0);
    int blk = emit_verdict(poseidon_check(addr, desc, sizeof desc, NULL, NULL),
                           desc, get_port(addr),
                           POSEIDON_TRANSPORT_TCP, POSEIDON_TIER_LIBC, origin);
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
    int blk = emit_verdict(poseidon_check(to, desc, sizeof desc, NULL, NULL),
                           desc, get_port(to),
                           POSEIDON_TRANSPORT_UDP, POSEIDON_TIER_LIBC, origin);
    in_poseidon = 0;
    if (blk) { errno = ECONNREFUSED; return -1; }
    return real(fd, buf, n, flags, to, tolen);
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
    ssize_t (*real)(int, const struct msghdr *, int) = dlsym(RTLD_NEXT, "sendmsg");
    if (in_poseidon || !msg || !msg->msg_name) return real(fd, msg, flags);
    in_poseidon = 1;
    char desc[320];
    const struct sockaddr *dst = (const struct sockaddr *) msg->msg_name;
    uint64_t origin = (uint64_t)(uintptr_t)__builtin_return_address(0);
    int blk = emit_verdict(poseidon_check(dst, desc, sizeof desc, NULL, NULL),
                           desc, get_port(dst),
                           POSEIDON_TRANSPORT_UDP, POSEIDON_TIER_LIBC, origin);
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
    const struct sockaddr *dst = (const struct sockaddr *) msgvec[0].msg_hdr.msg_name;
    uint64_t origin = (uint64_t)(uintptr_t)__builtin_return_address(0);
    int blk = emit_verdict(poseidon_check(dst, desc, sizeof desc, NULL, NULL),
                           desc, get_port(dst),
                           POSEIDON_TRANSPORT_UDP, POSEIDON_TIER_LIBC, origin);
    in_poseidon = 0;
    if (blk) { errno = ECONNREFUSED; return -1; }
    return real(fd, msgvec, vlen, flags);
}

int getaddrinfo(const char *node, const char *svc,
                const struct addrinfo *hints, struct addrinfo **res) {
    int (*real)(const char *, const char *, const struct addrinfo *, struct addrinfo **) =
        dlsym(RTLD_NEXT, "getaddrinfo");
    if (in_poseidon) return real(node, svc, hints, res);
    if (host_denied(node)) {
        ring_push(mono_ns(), node, 0,
                  POSEIDON_TRANSPORT_DNS, POSEIDON_TIER_LIBC, 1 /*blocked*/, 0);
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
int android_getaddrinfofornet(const char *node, const char *svc,
                              const struct addrinfo *hints,
                              unsigned netid, unsigned mark, struct addrinfo **res) {
    int (*real)(const char *, const char *, const struct addrinfo *,
                unsigned, unsigned, struct addrinfo **) =
        dlsym(RTLD_NEXT, "android_getaddrinfofornet");
    if (!real) {
        int (*ga)(const char *, const char *, const struct addrinfo *, struct addrinfo **) =
            dlsym(RTLD_NEXT, "getaddrinfo");
        return ga(node, svc, hints, res);
    }
    if (in_poseidon) return real(node, svc, hints, netid, mark, res);
    if (host_denied(node)) {
        ring_push(mono_ns(), node, 0,
                  POSEIDON_TRANSPORT_DNS, POSEIDON_TIER_LIBC, 1 /*blocked*/, 0);
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
