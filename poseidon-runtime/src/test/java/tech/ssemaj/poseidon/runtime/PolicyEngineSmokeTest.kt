package tech.ssemaj.poseidon.runtime

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PolicyEngineSmokeTest {
    @Test fun allowListBlocksUnlistedHost() {
        PolicyEngine.configure(allowedHosts = listOf("example.com"), deniedPaths = emptyList())
        assertTrue(PolicyEngine.evaluateHost("evil.test", -1).block)
        assertFalse(PolicyEngine.evaluateHost("example.com", -1).block)
    }
}
