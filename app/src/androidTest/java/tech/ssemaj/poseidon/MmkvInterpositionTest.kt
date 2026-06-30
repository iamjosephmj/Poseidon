package tech.ssemaj.poseidon

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.tencent.mmkv.MMKV
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Verifies that Poseidon's native ELF `DT_NEEDED` interposition does not corrupt a
 * public third-party native library.
 *
 * MMKV (`com.tencent:mmkv`) is backed by `libmmkv.so`, into which the Poseidon plugin
 * injects `libposeidon_shim.so` as the first `DT_NEEDED` at package time.  This test
 * runs on-device against the Poseidon-processed app APK, so it exercises the *rewritten*
 * `.so`.  MMKV uses mmap'd file IO and no sockets, so it is also a zero-egress negative
 * control.
 *
 * Run with: `./gradlew :app:connectedDebugAndroidTest` on a connected arm64 device.
 */
@RunWith(AndroidJUnit4::class)
class MmkvInterpositionTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    /**
     * Initializing MMKV loads `libmmkv.so` via JNI; a corrupt `.so` would surface here
     * as an `UnsatisfiedLinkError`.  A write→read round-trip then proves the native code
     * path actually executes correctly under interposition.
     */
    @Test
    fun mmkvNativeRoundTripSurvivesInterposition() {
        MMKV.initialize(context)
        val kv = MMKV.defaultMMKV()
        val key = "poseidon_test_key"
        val value = "poseidon-mmkv-roundtrip"

        kv.encode(key, value)

        assertEquals(
            "MMKV native round-trip failed under Poseidon DT_NEEDED injection",
            value,
            kv.decodeString(key),
        )
    }
}
