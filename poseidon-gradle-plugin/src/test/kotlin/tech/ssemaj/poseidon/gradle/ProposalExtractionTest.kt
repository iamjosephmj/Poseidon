package tech.ssemaj.poseidon.gradle

import org.junit.Assert.assertEquals
import org.junit.Test

class ProposalExtractionTest {
    @Test fun extractsInlineProposalsFromMergedManifest() {
        val manifest = """
            <manifest package="com.app">
              <application>
                <meta-data android:name="tech.ssemaj.poseidon.proposes"
                           android:value="telemetry.sdk.com,crash.sdk.com"
                           tools:node="com.foo.sdk"/>
              </application>
            </manifest>
        """.trimIndent()
        val props = GeneratePolicyTask.extractProposals(manifest)
        assertEquals(2, props.size)
        assertEquals("telemetry.sdk.com", props[0].host)
        assertEquals("com.foo.sdk", props[0].library)
        assertEquals("crash.sdk.com", props[1].host)
    }

    @Test fun defaultsLibraryToUnknownWhenToolsNodeAbsent() {
        val manifest = """
            <manifest package="com.app">
              <application>
                <meta-data android:name="tech.ssemaj.poseidon.proposes"
                           android:value="solo.sdk.com"/>
              </application>
            </manifest>
        """.trimIndent()
        val props = GeneratePolicyTask.extractProposals(manifest)
        assertEquals(1, props.size)
        assertEquals("solo.sdk.com", props[0].host)
        assertEquals("unknown", props[0].library)
    }
}
