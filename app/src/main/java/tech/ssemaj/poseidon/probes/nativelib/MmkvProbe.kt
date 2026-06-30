package tech.ssemaj.poseidon.probes.nativelib

import android.content.Context
import android.util.Log
import com.tencent.mmkv.MMKV
import java.util.concurrent.Executors

/**
 * Tier: native libc shim (ELF DT_NEEDED interposition) — robustness, NOT egress.
 *
 * MMKV (Tencent) is a public key-value store backed by a native library
 * (`libmmkv.so`).  The Poseidon plugin injects `libposeidon_shim.so` as the first
 * `DT_NEEDED` of EVERY packaged `.so` — dependency-provided ones included — so this
 * probe verifies the rewrite leaves a foreign native lib loadable and functional:
 * MMKV must initialize (which loads `libmmkv.so` via JNI) and a write→read round-trip
 * through native code must survive.
 *
 * MMKV uses mmap'd file IO and opens NO sockets, so the correct Poseidon outcome is
 * ZERO [tech.ssemaj.poseidon.runtime.model.EgressEvent]s — a negative control proving
 * the native shim stays silent for non-network native code.
 *
 * See [MmkvInterpositionTest] for the asserting on-device test.
 */
object MmkvProbe {
    private const val TAG = "PoseidonDemo"
    private const val KEY = "poseidon_probe_key"
    private const val VALUE = "poseidon-mmkv-roundtrip"

    fun run(ctx: Context) {
        Executors.newSingleThreadExecutor().execute {
            try {
                // Loads libmmkv.so via JNI — throws UnsatisfiedLinkError if Poseidon's
                // DT_NEEDED injection corrupted the .so.
                MMKV.initialize(ctx)
                val kv = MMKV.defaultMMKV()
                kv.encode(KEY, VALUE)
                val readBack = kv.decodeString(KEY)
                val ok = readBack == VALUE
                Log.i(
                    TAG,
                    "mmkv(native-lib) ran under Poseidon -> roundTripOk=$ok " +
                        "read=\"$readBack\" (expect 0 egress events)",
                )
            } catch (t: Throwable) {
                // An UnsatisfiedLinkError here would mean Poseidon's injection corrupted
                // MMKV's .so — exactly the failure this probe guards against.
                Log.e(
                    TAG,
                    "mmkv(native-lib) FAILED under Poseidon: ${t.javaClass.simpleName}: ${t.message}",
                )
            }
        }
    }
}
