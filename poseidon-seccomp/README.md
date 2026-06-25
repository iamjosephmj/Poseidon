# poseidon-seccomp

**Opt-in** seccomp-tier enforcement — closes the remaining gap for Go binaries and any
native code that issues raw syscalls directly (bypassing libc), which the
`poseidon-native` shim cannot intercept. Uses the Linux `seccomp(2)` `USER_NOTIF`
mechanism to gate `connect`, `sendto`, `sendmsg`, and `sendmmsg` at the kernel boundary:
the enforcement decision is TOCTOU-safe (emulate, not CONTINUE), and `io_uring_setup` is
denied to prevent bypass. Also performs raw-DNS correlation to associate resolved
IP→hostname for connectionless UDP traffic. Enable via the policy's `nativeDnsCorrelation`
flag plus opting in to this module.

**Opt-in cost/risk:** Every covered syscall incurs a user-space round-trip cost (the
kernel parks the calling thread, the supervisor evaluates, then emulates the result); this
is measurable per connection and per datagram — profile before enabling in
latency-sensitive paths. Requires **kernel ≥ 5.0** for `USER_NOTIF`; on older kernels
the gate is silently absent (graceful degradation) and Go/raw-syscall traffic is ungated.

**Honest limits (from spec §9):** **Kernels < 5.0** — no `USER_NOTIF`; Go/raw-syscall
traffic is ungated; libc + DNS enforcement from `poseidon-native` still applies for
libc-using code. **Exfiltration through an allow-listed host** — no payload inspection at
any tier. **DoH/DoT** — hides the name from correlation logs; the `connect` to the
resolved IP is still gated. **Hostile same-privilege SDK** — adversarial in-process code
is not constrained by Poseidon; only kernel/MDM/network provides a true security
boundary. **Strict-by-IP CDN over-block** residual on rotating CDNs. Positioning:
seccomp is the deepest interposition tier available in-process without root; it closes
the Go/raw gap for non-adversarial code on supported kernels.
