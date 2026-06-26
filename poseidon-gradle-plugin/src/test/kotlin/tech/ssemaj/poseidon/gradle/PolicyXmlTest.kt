package tech.ssemaj.poseidon.gradle

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import tech.ssemaj.poseidon.gradle.policy.AppPolicyXmlParser
import tech.ssemaj.poseidon.gradle.policy.Proposal

class PolicyXmlTest {
    private val app = """
        <poseidon mode="enforce">
          <allow host="example.com"/>
          <allow host="*.api.foo.com"/>
          <deny-path pattern="/internal/*"/>
          <approve library="com.foo.sdk"/>
        </poseidon>
    """.trimIndent()

    @Test fun parsesAppPolicy() {
        val p = AppPolicyXmlParser.parseAppPolicy(app)
        assertEquals("enforce", p.mode)
        assertTrue(p.allowedHosts.containsAll(listOf("example.com", "*.api.foo.com")))
        assertEquals(listOf("/internal/*"), p.deniedPaths)
        assertEquals(setOf("com.foo.sdk"), p.approvedLibraries)
    }

    @Test fun parsesLibraryProposals() {
        val lib = """<poseidon><allow host="telemetry.sdk.com"/></poseidon>"""
        val props = AppPolicyXmlParser.parseProposals("com.foo.sdk", lib)
        assertEquals(listOf(Proposal("com.foo.sdk", "telemetry.sdk.com")), props)
    }

    @Test fun ignoresNonDirectChildAllow() {
        val xml = """
            <poseidon mode="enforce">
              <allow host="top.com"/>
              <group><allow host="nested.com"/></group>
            </poseidon>
        """.trimIndent()
        val p = AppPolicyXmlParser.parseAppPolicy(xml)
        assertEquals(listOf("top.com"), p.allowedHosts)
    }
}
