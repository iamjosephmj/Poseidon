/* seccomp_supervisor.c — in-process seccomp USER_NOTIF supervisor for libposeidon_shim.
 *
 * Coverage: the filter is installed with TSYNC + TSYNC_ESRCH (Linux 5.7+) so it
 * applies to EVERY thread in the process — closing the gap where a raw connect on
 * a thread outside the installer's lineage was ungated.  TSYNC also filters the
 * supervisor itself, so when fully covered (g_full_coverage) the supervisor takes
 * the CONTINUE-based allow path and skips its recvfrom emulation — it must not issue
 * a trapped syscall of its own or it would self-trap and deadlock.  On kernels
 * without TSYNC_ESRCH it falls back to NEW_LISTENER-only (installer-lineage coverage,
 * supervisor unfiltered, TOCTOU-safe emulation).  It handles trapped connect(),
 * sendto(), recvfrom(), sendmsg(), and sendmmsg() from native/Go callers.
 *
 * Connect enforcement: STRICT raw default-deny — block anything not positively
 * allowed (an allow-listed host identified via DNS correlation, or an allow-CIDR).
 * A raw connect() has no hostname, so an un-identifiable destination is denied.
 *
 * Exports:
 *   Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_seccompProbe
 *   Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_installSeccomp
 */
#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <jni.h>
#include <android/log.h>
#include "shim_internal.h"

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "POSEIDON", __VA_ARGS__)

/* ---- seccomp API fallback defines (pre-5.0 kernel headers) ---- */
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC         (1UL << 0)
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER  (1UL << 3)
#endif
/* Linux 5.7+: makes TSYNC usable together with NEW_LISTENER (returns the listener
 * fd on success; -ESRCH instead of a TID if a thread can't be synced). */
#ifndef SECCOMP_FILTER_FLAG_TSYNC_ESRCH
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH   (1UL << 4)
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE  (1UL << 0)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOCTL_NOTIF_RECV    _IOWR('!', 0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND    _IOWR('!', 1, struct seccomp_notif_resp)
#define SECCOMP_IOCTL_NOTIF_ID_VALID _IOW('!', 2, __u64)
#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425   /* same NR across arm64/arm/x86_64/x86 */
#endif

/* ---- Module-local constants ---- */

/** Maximum UDP/sendmmsg vector length examined by the supervisor per notification.
 *  Limits the per-notification cost; additional messages in the same call are unchecked. */
#define POSEIDON_SENDMMSG_MAX_VEC 64

/** Receive buffer for in-process DNS response emulation (recvfrom interception).
 *  Must be large enough for a typical DNS response including all A/AAAA records. */
#define POSEIDON_DNS_RESP_BUF 2048

/* ---- Listener fd (published atomically after install) ---- */
static int       g_notif_fd  = -1;
static pthread_t g_supervisor;

/* 1 when the filter was TSYNC'd to every thread (full coverage). In that mode the
 * supervisor is ALSO filtered, so it must NOT issue trapped syscalls (connect /
 * recvfrom) of its own — it CONTINUEs the allow path instead of emulating it. */
static int       g_full_coverage = 0;

/* ---- In-process DNS correlation (fd -> hostname map) ---- */
#define DNSMAP_CAP 256
typedef struct { int fd; char host[256]; } dns_fd_entry;
static dns_fd_entry     g_dnsmap[DNSMAP_CAP];
static int              g_dnsmap_next = 0;
static pthread_mutex_t  g_dnsmap_lock = PTHREAD_MUTEX_INITIALIZER;

static void dnsmap_put(int fd, const char *host) {
    pthread_mutex_lock(&g_dnsmap_lock);
    g_dnsmap[g_dnsmap_next].fd = fd;
    strncpy(g_dnsmap[g_dnsmap_next].host, host, 255);
    g_dnsmap[g_dnsmap_next].host[255] = '\0';
    g_dnsmap_next = (g_dnsmap_next + 1) % DNSMAP_CAP;
    pthread_mutex_unlock(&g_dnsmap_lock);
}

static int dnsmap_get(int fd, char *out, size_t outsz) {
    int found = 0;
    pthread_mutex_lock(&g_dnsmap_lock);
    for (int i = 0; i < DNSMAP_CAP; i++) {
        if (g_dnsmap[i].fd == fd && g_dnsmap[i].host[0]) {
            strncpy(out, g_dnsmap[i].host, outsz - 1);
            out[outsz - 1] = '\0';
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_dnsmap_lock);
    return found;
}

/* ---- BPF program builder ---- */

/* Build the BPF filter program into caller-supplied buffers.
 * conn_only[6] / with_dns[10] must be stack-allocated by the caller and
 * remain valid until the seccomp syscall returns. */
static struct sock_fprog build_bpf_program(int dnsCorrelation,
                                            struct sock_filter conn_only[6],
                                            struct sock_filter with_dns[10]) {
    const __u32 RET_DENY = SECCOMP_RET_ERRNO | (EACCES & SECCOMP_RET_DATA);

    conn_only[0] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                                  (offsetof(struct seccomp_data, nr)));
    conn_only[1] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect,       2, 0);
    conn_only[2] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 2, 0);
    conn_only[3] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    conn_only[4] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
    conn_only[5] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, RET_DENY);

    with_dns[0] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                                 (offsetof(struct seccomp_data, nr)));
    with_dns[1] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect,        6, 0);
    with_dns[2] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto,          5, 0);
    with_dns[3] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvfrom,        4, 0);
    with_dns[4] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg,         3, 0);
    with_dns[5] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmmsg,        2, 0);
    with_dns[6] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup,  2, 0);
    with_dns[7] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    with_dns[8] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
    with_dns[9] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, RET_DENY);

    struct sock_fprog prog;
    if (dnsCorrelation) { prog.len = 10; prog.filter = with_dns; }
    else                { prog.len = 6;  prog.filter = conn_only; }
    return prog;
}

/* ---- Per-syscall notification handlers ---- */

static void handle_connect_notif(int fd,
                                  const struct seccomp_notif *req,
                                  struct seccomp_notif_resp  *resp) {
    socklen_t alen = (socklen_t) req->data.args[2];
    const void *uaddr = (const void *) (uintptr_t) req->data.args[1];
    if (!uaddr || alen == 0) return;

    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    if (alen > (socklen_t) sizeof ss) alen = (socklen_t) sizeof ss;
    memcpy(&ss, uaddr, alen);

    char desc[320];
    poseidon_verdict_t v = poseidon_check((const struct sockaddr *) &ss,
                                          desc, sizeof desc, NULL, NULL);

    /* STRICT raw default-deny: block anything not positively allowed (an
     * allow-listed host identified via DNS correlation, or an allow-CIDR).
     * A raw connect() carries no hostname, so an un-identifiable destination
     * cannot be proven safe — deny it.  Trade-off: a connect to an un-correlated
     * IP of an ALLOWED host is also denied (CDN rotation / fresh IPv6 / hardcoded
     * IP); seed the host's IPs (NativeBridge.cacheHostIps) or declare an allow-CIDR
     * to keep it reachable. */
    int do_block = (v == P_BLOCK);

    if (do_block || v == P_MONITOR_VIOL) {
        char shost[64];
        host_from_desc(desc, shost, sizeof shost);
        ring_push(mono_ns(), shost,
                  get_port((const struct sockaddr *) &ss),
                  POSEIDON_TRANSPORT_TCP, POSEIDON_TIER_SECCOMP,
                  do_block ? 1 : 0, 0);
    }

    if (do_block) {
        resp->flags = 0;
        resp->error = -EACCES;
    } else if (v == P_ALLOW || v == P_NA) {
        if (g_full_coverage) {
            /* Supervisor is itself filtered (TSYNC full coverage): it must NOT issue
             * a connect() of its own — that would self-trap and deadlock. Let the
             * kernel run the original connect in the target thread. (Loses the
             * TOCTOU-swap hardening — an adversarial in-process caller could swap the
             * sockaddr after the check; out of scope for the non-adversarial model.) */
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        } else {
            /* Unfiltered supervisor: emulate connect with the trusted copy (no
             * CONTINUE — prevents TOCTOU swap of the user-space sockaddr). */
            int cfd = (int) req->data.args[0];
            int r   = connect(cfd, (struct sockaddr *) &ss, alen);
            resp->flags = 0;
            resp->val   = (r == 0) ? 0 : -1;
            resp->error = (r == 0) ? 0 : -errno;
        }
    }
    /* else: P_MONITOR_VIOL (monitor mode — log only) → CONTINUE */
    (void) fd;
}

static void handle_sendto_notif(const struct seccomp_notif *req,
                                 struct seccomp_notif_resp  *resp) {
    const struct sockaddr *dst =
        (const struct sockaddr *) (uintptr_t) req->data.args[4];

    if (get_port(dst) == POSEIDON_DNS_PORT) {
        /* DNS query: record fd->hostname, optionally deny. */
        const unsigned char *buf = (const unsigned char *) (uintptr_t) req->data.args[1];
        size_t len = (size_t) req->data.args[2];
        char host[256];
        if (buf && len >= 13 && dns_qname(buf, len, host, sizeof host)) {
            if (host_denied(host)) {
                ring_push(mono_ns(), host, POSEIDON_DNS_PORT,
                          POSEIDON_TRANSPORT_DNS, POSEIDON_TIER_SECCOMP, 1 /*blocked*/, 0);
                resp->flags = 0;
                resp->error = -EACCES;
            } else {
                dnsmap_put((int) req->data.args[0], host);
                ring_push(mono_ns(), host, POSEIDON_DNS_PORT,
                          POSEIDON_TRANSPORT_DNS, POSEIDON_TIER_SECCOMP, 0 /*allowed*/, 0);
            }
        }
    } else if (dst) {
        /* Connectionless UDP to an arbitrary host — enforce the allow-list. */
        char desc[320];
        if (poseidon_check(dst, desc, sizeof desc, NULL, NULL) == P_BLOCK) {
            char shost[64];
            host_from_desc(desc, shost, sizeof shost);
            ring_push(mono_ns(), shost, get_port(dst),
                      POSEIDON_TRANSPORT_UDP, POSEIDON_TIER_SECCOMP, 1 /*blocked*/, 0);
            resp->flags = 0;
            resp->error = -EACCES;
        }
    }
}

static void handle_sendmsg_notif(long nr,
                                  const struct seccomp_notif *req,
                                  struct seccomp_notif_resp  *resp) {
    /* Handles both sendmsg (vlen=1) and sendmmsg (vlen from args[2]). */
    unsigned vlen = (nr == __NR_sendmmsg) ? (unsigned) req->data.args[2] : 1u;
    if (vlen > POSEIDON_SENDMMSG_MAX_VEC) vlen = POSEIDON_SENDMMSG_MAX_VEC;

    for (unsigned k = 0; k < vlen; k++) {
        const struct msghdr *m;
        if (nr == __NR_sendmmsg)
            m = &((const struct mmsghdr *) (uintptr_t) req->data.args[1])[k].msg_hdr;
        else
            m = (const struct msghdr *) (uintptr_t) req->data.args[1];
        if (!m || !m->msg_name) continue;
        const struct sockaddr *dst = (const struct sockaddr *) m->msg_name;
        if (get_port(dst) == POSEIDON_DNS_PORT) continue; /* resolver handled by sendto path */
        char desc[320];
        if (poseidon_check(dst, desc, sizeof desc, NULL, NULL) == P_BLOCK) {
            char shost[64];
            host_from_desc(desc, shost, sizeof shost);
            ring_push(mono_ns(), shost, get_port(dst),
                      POSEIDON_TRANSPORT_UDP, POSEIDON_TIER_SECCOMP, 1 /*blocked*/, 0);
            resp->flags = 0;
            resp->error = -EACCES;
            break;
        }
    }
}

static void handle_recvfrom_notif(const struct seccomp_notif *req,
                                   struct seccomp_notif_resp  *resp) {
    /* Under TSYNC full coverage the supervisor is filtered, so it cannot perform the
     * recvfrom() itself (self-trap → deadlock). CONTINUE — the kernel delivers the DNS
     * response to the caller; we forgo the raw-recvfrom IP->host correlation (the libc
     * getaddrinfo hook, sendto:53 recording, and JVM seeding still correlate). */
    if (g_full_coverage) return;
    int rfd   = (int) req->data.args[0];
    int flags = (int) req->data.args[3];
    char host[256];
    if (flags & MSG_PEEK) return;
    if (!dnsmap_get(rfd, host, sizeof host)) return;

    /* Emulate recvfrom in-process: read the DNS response, parse A/AAAA
     * answers into the IP->host cache, copy data back to the caller. */
    unsigned char tmp[POSEIDON_DNS_RESP_BUF];
    size_t want = (size_t) req->data.args[2];
    if (want > sizeof tmp) want = sizeof tmp;
    struct sockaddr_storage src;
    socklen_t srclen = sizeof src;
    ssize_t got = recvfrom(rfd, tmp, want, flags,
                           (struct sockaddr *) &src, &srclen);
    if (got > 0) {
        dns_answers(tmp, (size_t) got, host);
        void *ubuf = (void *) (uintptr_t) req->data.args[1];
        if (ubuf) memcpy(ubuf, tmp, (size_t) got);
        void *usrc = (void *) (uintptr_t) req->data.args[4];
        if (usrc) memcpy(usrc, &src, srclen);
    }
    resp->flags = 0; /* we performed the syscall */
    resp->val   = got;
    resp->error = (got < 0) ? -errno : 0;
}

/* ---- Supervisor thread: thin NOTIF RECV/SEND loop ---- */

static void *seccomp_supervisor(void *arg) {
    (void) arg;
    while (__atomic_load_n(&g_notif_fd, __ATOMIC_ACQUIRE) < 0) usleep(1000);
    int fd = g_notif_fd;

    for (;;) {
        struct seccomp_notif req;
        memset(&req, 0, sizeof req);
        if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &req) != 0) {
            if (errno == EINTR) continue;
            break; /* listener fd gone */
        }

        struct seccomp_notif_resp resp;
        memset(&resp, 0, sizeof resp);
        resp.id    = req.id;
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; /* default: let it proceed */

        __u64 id    = req.id;
        int   valid = (ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0);
        long  nr    = req.data.nr;

        if (valid && nr == __NR_connect)
            handle_connect_notif(fd, &req, &resp);
        else if (valid && nr == __NR_sendto)
            handle_sendto_notif(&req, &resp);
        else if (valid && (nr == __NR_sendmsg || nr == __NR_sendmmsg))
            handle_sendmsg_notif(nr, &req, &resp);
        else if (valid && nr == __NR_recvfrom)
            handle_recvfrom_notif(&req, &resp);

        ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
    }
    return NULL;
}

/* ---- JNI exports ---- */

JNIEXPORT void JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_seccompProbe(JNIEnv *env, jobject thiz) {
    (void) env; (void) thiz;
    LOG("seccomp probe: start (app domain)");
    int nnp = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    LOG("seccomp: PR_SET_NO_NEW_PRIVS=%d errno=%d", nnp, errno);

    struct sock_filter allow_all[] = { BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW) };
    struct sock_fprog ap = { .len = 1, .filter = allow_all };

    errno = 0;
    int pr = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &ap, 0, 0);
    LOG("seccomp: prctl(PR_SET_SECCOMP allow-all)=%d errno=%d (%s)",
        pr, errno, pr < 0 ? strerror(errno) : "OK");

    errno = 0;
    long lf = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                      SECCOMP_FILTER_FLAG_NEW_LISTENER, &ap);
    LOG("seccomp: USER_NOTIF fd=%ld errno=%d (%s)",
        lf, errno, lf < 0 ? strerror(errno) : "OK");
    if (lf >= 0) close((int) lf);
    LOG("seccomp probe: done");
}

JNIEXPORT jint JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_installSeccomp(
    JNIEnv *env, jobject thiz, jint dnsCorrelation) {
    (void) env; (void) thiz;
#if defined(__NR_connect)
    /* Warm up liblog BEFORE the filter is installed (avoids log-path traps). */
    LOG("seccomp gate: starting supervisor");

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        LOG("seccomp gate: NO_NEW_PRIVS failed errno=%d", errno);
        return -1;
    }
    /* Create the supervisor BEFORE installing the filter so it is not filtered. */
    if (pthread_create(&g_supervisor, NULL, seccomp_supervisor, NULL) != 0) {
        LOG("seccomp gate: supervisor thread create failed");
        return -1;
    }

    struct sock_filter buf_conn[6], buf_dns[10];
    struct sock_fprog prog = build_bpf_program(dnsCorrelation, buf_conn, buf_dns);

    /* Prefer FULL thread coverage: TSYNC syncs the filter to every thread (closing
     * the gap where a raw connect on a thread outside the installer's lineage was
     * ungated); TSYNC_ESRCH (5.7+) lets TSYNC combine with NEW_LISTENER. If the kernel
     * lacks TSYNC_ESRCH (or a thread can't sync), fall back to NEW_LISTENER-only
     * (installer-lineage coverage). TSYNC also filters the supervisor, so g_full_coverage
     * flips it to the CONTINUE-based allow path (see handle_connect/recvfrom). */
    errno = 0;
    long fd = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                      SECCOMP_FILTER_FLAG_NEW_LISTENER
                      | SECCOMP_FILTER_FLAG_TSYNC
                      | SECCOMP_FILTER_FLAG_TSYNC_ESRCH, &prog);
    int full = (fd >= 0);
    if (fd < 0) {
        LOG("seccomp gate: TSYNC install unavailable errno=%d (%s); falling back to per-lineage",
            errno, strerror(errno));
        errno = 0;
        fd = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                     SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    }
    if (fd < 0) {
        LOG("seccomp gate: install failed errno=%d (%s)", errno, strerror(errno));
        return -1;
    }
    g_full_coverage = full;
    __atomic_store_n(&g_notif_fd, (int) fd, __ATOMIC_RELEASE);
    LOG("seccomp gate: ACTIVE on connect()%s — %s coverage (fd=%ld)",
        dnsCorrelation ? " + sendto/recvfrom (DNS correlation)" : "",
        full ? "FULL (all threads, TSYNC)" : "partial (installer lineage)", fd);
    return 0;
#else
    LOG("seccomp gate: no direct connect syscall on this ABI, skipped");
    return -2;
#endif
}
