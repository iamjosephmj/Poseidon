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
    }
}
