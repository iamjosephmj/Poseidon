/* jni_bridge.c — Java_* JNI exports for libposeidon_shim (non-seccomp subset).
 *
 * Exports:
 *   Java_…_configure        — push host allow-list + mode
 *   Java_…_configureCidrs   — push opt-in CIDR allow-list
 *   Java_…_cacheHost        — seed IP->host cache from JVM resolved addresses
 *   Java_…_rawConnect       — raw-syscall connect (test: verifies seccomp gate)
 *   Java_…_rawSendto        — raw-syscall sendto  (test: verifies seccomp gate)
 *   Java_…_rawResolve       — raw DNS resolve via sendto/recvfrom (test)
 *   Java_…_drainEvents      — drain up to 64 ring events as String[]
 *   Java_…_symbolize        — dladdr-backed .so attribution
 *
 * seccompProbe and installSeccomp are in seccomp_supervisor.c.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <jni.h>
#include <android/log.h>
#include "shim_internal.h"

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "POSEIDON", __VA_ARGS__)

/* ---- configure: push host allow-list + mode ---- */
JNIEXPORT void JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_configure(
    JNIEnv *env, jobject thiz, jobjectArray hosts, jint enforce) {
    (void) thiz;
    int n = (*env)->GetArrayLength(env, hosts);
    char **arr = (char **) calloc(n > 0 ? n : 1, sizeof(char *));
    for (int i = 0; i < n; i++) {
        jstring s = (jstring) (*env)->GetObjectArrayElement(env, hosts, i);
        const char *c = (*env)->GetStringUTFChars(env, s, NULL);
        arr[i] = strdup(c);
        (*env)->ReleaseStringUTFChars(env, s, c);
        (*env)->DeleteLocalRef(env, s);
    }
    policy_set_hosts(arr, n, (int) enforce);
    LOG("native policy: %d allowed host(s), enforce=%d", n, (int) enforce);
}

/* ---- configureCidrs: push opt-in CIDR allow-list ---- */
JNIEXPORT void JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_configureCidrs(
    JNIEnv *env, jobject thiz, jobjectArray arr) {
    (void) thiz;
    int n = (*env)->GetArrayLength(env, arr);
    if (n > POSEIDON_MAX_CIDRS) n = POSEIDON_MAX_CIDRS;

    poseidon_cidr_t cidrs[POSEIDON_MAX_CIDRS];
    int count = 0;

    for (int i = 0; i < n; i++) {
        jstring js = (jstring) (*env)->GetObjectArrayElement(env, arr, i);
        const char *s = (*env)->GetStringUTFChars(env, js, NULL);

        const char *slash = strchr(s, '/');
        if (!slash) goto next;

        int alen = (int)(slash - s);
        if (alen <= 0 || alen >= 64) goto next;

        char addr_buf[64];
        memcpy(addr_buf, s, (size_t) alen);
        addr_buf[alen] = '\0';
        int prefix = atoi(slash + 1);

        struct in_addr  a4;
        struct in6_addr a6;
        poseidon_cidr_t entry;
        memset(&entry, 0, sizeof entry);

        if (inet_pton(AF_INET, addr_buf, &a4) == 1) {
            entry.family = AF_INET;
            memcpy(entry.net, &a4, 4);
            if (prefix < 0)  prefix = 0;
            if (prefix > 32) prefix = 32;
            entry.prefix = prefix;
            cidrs[count++] = entry;
        } else if (inet_pton(AF_INET6, addr_buf, &a6) == 1) {
            entry.family = AF_INET6;
            memcpy(entry.net, &a6, 16);
            if (prefix < 0)   prefix = 0;
            if (prefix > 128) prefix = 128;
            entry.prefix = prefix;
            cidrs[count++] = entry;
        }

    next:
        (*env)->ReleaseStringUTFChars(env, js, s);
        (*env)->DeleteLocalRef(env, js);
    }

    policy_set_cidrs(cidrs, count);
    LOG("native CIDR allow-list: %d range(s)", count);
}

/* ---- cacheHost: seed IP->host cache from JVM-resolved addresses ---- */
JNIEXPORT void JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_cacheHost(
    JNIEnv *env, jobject thiz, jstring jhost, jobjectArray jips) {
    (void) thiz;
    const char *host = (*env)->GetStringUTFChars(env, jhost, NULL);
    int n = (*env)->GetArrayLength(env, jips);
    for (int i = 0; i < n; i++) {
        jstring s  = (jstring) (*env)->GetObjectArrayElement(env, jips, i);
        const char *ip = (*env)->GetStringUTFChars(env, s, NULL);
        char clean[64];
        strncpy(clean, ip, sizeof clean - 1);
        clean[sizeof clean - 1] = '\0';
        char *pct = strchr(clean, '%'); /* strip IPv6 zone id */
        if (pct) *pct = '\0';
        struct in_addr  a4;
        struct in6_addr a6;
        if      (inet_pton(AF_INET,  clean, &a4) == 1) cache_put(AF_INET,  &a4, host);
        else if (inet_pton(AF_INET6, clean, &a6) == 1) cache_put(AF_INET6, &a6, host);
        (*env)->ReleaseStringUTFChars(env, s, ip);
        (*env)->DeleteLocalRef(env, s);
    }
    (*env)->ReleaseStringUTFChars(env, jhost, host);
}

/* ---- rawConnect: raw-syscall connect (bypasses libc, verifies seccomp gate) ---- */
JNIEXPORT jint JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_rawConnect(
    JNIEnv *env, jobject thiz, jstring jip, jint port) {
    (void) thiz;
    const char *ip = (*env)->GetStringUTFChars(env, jip, NULL);
    int is6 = (strchr(ip, ':') != NULL);
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    int s;
    socklen_t alen;
    if (is6) {
        s = socket(AF_INET6, SOCK_STREAM, 0);
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *) &ss;
        a6->sin6_family = AF_INET6;
        a6->sin6_port   = htons((uint16_t) port);
        inet_pton(AF_INET6, ip, &a6->sin6_addr);
        alen = (socklen_t) sizeof(struct sockaddr_in6);
    } else {
        s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in *a4 = (struct sockaddr_in *) &ss;
        a4->sin_family = AF_INET;
        a4->sin_port   = htons((uint16_t) port);
        inet_pton(AF_INET, ip, &a4->sin_addr);
        alen = (socklen_t) sizeof(struct sockaddr_in);
    }
    errno = 0;
    long r = syscall(__NR_connect, s, (struct sockaddr *) &ss, alen);
    int e = (r < 0) ? errno : 0;
    (*env)->ReleaseStringUTFChars(env, jip, ip);
    if (s >= 0) close(s);
    return e;
}

/* ---- rawSendto: raw-syscall UDP sendto (no connect, verifies seccomp gate) ---- */
JNIEXPORT jint JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_rawSendto(
    JNIEnv *env, jobject thiz, jstring jip, jint jport) {
    (void) thiz;
    const char *ip = (*env)->GetStringUTFChars(env, jip, NULL);
    int is6 = (strchr(ip, ':') != NULL);
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    int s;
    socklen_t alen;
    if (is6) {
        s = socket(AF_INET6, SOCK_DGRAM, 0);
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *) &ss;
        a6->sin6_family = AF_INET6;
        a6->sin6_port   = htons((unsigned short) jport);
        inet_pton(AF_INET6, ip, &a6->sin6_addr);
        alen = (socklen_t) sizeof(struct sockaddr_in6);
    } else {
        s = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in *a4 = (struct sockaddr_in *) &ss;
        a4->sin_family = AF_INET;
        a4->sin_port   = htons((unsigned short) jport);
        inet_pton(AF_INET, ip, &a4->sin_addr);
        alen = (socklen_t) sizeof(struct sockaddr_in);
    }
    const char *msg = "x";
    errno = 0;
    long r = syscall(__NR_sendto, s, msg, 1, 0, (struct sockaddr *) &ss, alen);
    int e = (r < 0) ? errno : 0;
    (*env)->ReleaseStringUTFChars(env, jip, ip);
    if (s >= 0) close(s);
    return e;
}

/* ---- rawResolve: raw DNS resolve via sendto/recvfrom (verifies DNS correlation) ---- */
JNIEXPORT jstring JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_rawResolve(
    JNIEnv *env, jobject thiz, jstring jhost) {
    (void) thiz;
    const char *host = (*env)->GetStringUTFChars(env, jhost, NULL);

    /* Build a minimal DNS A-query for `host`. */
    unsigned char q[300];
    int ql = 0;
    q[ql++] = 0x12; q[ql++] = 0x34; /* txid */
    q[ql++] = 0x01; q[ql++] = 0x00; /* flags: standard query */
    q[ql++] = 0; q[ql++] = 1;       /* QDCOUNT=1 */
    q[ql++] = 0; q[ql++] = 0;       /* ANCOUNT=0 */
    q[ql++] = 0; q[ql++] = 0;       /* NSCOUNT=0 */
    q[ql++] = 0; q[ql++] = 0;       /* ARCOUNT=0 */
    const char *p = host;
    while (*p && ql < 280) {
        const char *dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int) strlen(p);
        if (len <= 0 || len > 63) break;
        q[ql++] = (unsigned char) len;
        memcpy(&q[ql], p, (size_t) len); ql += len;
        p += len; if (*p == '.') p++;
    }
    q[ql++] = 0;    /* root label */
    q[ql++] = 0; q[ql++] = 1; /* QTYPE=A  */
    q[ql++] = 0; q[ql++] = 1; /* QCLASS=IN */

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct timeval tv = { 3, 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct sockaddr_in dns;
    memset(&dns, 0, sizeof dns);
    dns.sin_family = AF_INET;
    dns.sin_port   = htons(POSEIDON_DNS_PORT);
    inet_pton(AF_INET, "8.8.8.8", &dns.sin_addr);
    sendto(s, q, (size_t) ql, 0, (struct sockaddr *) &dns, sizeof dns);

    unsigned char r[1500];
    ssize_t n = recvfrom(s, r, sizeof r, 0, NULL, NULL);
    close(s);
    (*env)->ReleaseStringUTFChars(env, jhost, host);

    char ipout[64];
    ipout[0] = '\0';
    if (n > 12 && dns_first_a(r, (size_t) n, ipout, sizeof ipout)) {
        return (*env)->NewStringUTF(env, ipout);
    }
    return NULL;
}

/* ---- drainEvents: drain up to 64 ring events as String[] ----
 * Wire format per element: "ts|host|port|transport|tier|blocked|origin_addr"
 * transport/tier encoded per POSEIDON_TRANSPORT_x and POSEIDON_TIER_x in event_ring.h.
 * Parsed on the Kotlin side by NativeShimBackend.RingEventParser.           */
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

/* ---- symbolize: dladdr-backed .so attribution ---- */
JNIEXPORT jstring JNICALL
Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_symbolize(
    JNIEnv *env, jobject thiz, jlong addr) {
    (void) thiz;
    Dl_info info;
    if (addr != 0 && dladdr((void *)(uintptr_t)(uint64_t) addr, &info) && info.dli_fname)
        return (*env)->NewStringUTF(env, info.dli_fname);
    return NULL;
}
