package tech.ssemaj.poseidon.gradle

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PolicyCompilerTest {
    private val app = CompiledPolicy("enforce", listOf("example.com"), listOf("/internal/*"), false, setOf("com.ok.sdk"))

    @Test fun approvedProposalGrantedUnapprovedRecordedOnly() {
        val proposals = listOf(Proposal("com.ok.sdk", "ok.host.com"), Proposal("com.bad.sdk", "bad.host.com"))
        val r = PolicyCompiler.compile(app, proposals, dslHosts = emptyList(), acceptProposals = false)
        assertTrue(r.policyJson.contains("ok.host.com"))      // approved → granted
        assertFalse(r.policyJson.contains("bad.host.com"))    // unapproved → NOT granted
        assertEquals(listOf(Proposal("com.bad.sdk", "bad.host.com")), r.unapprovedProposals)
        assertTrue(r.report.contains("com.bad.sdk"))          // but still reported
    }

    @Test fun acceptProposalsGrantsAll() {
        val proposals = listOf(Proposal("com.bad.sdk", "bad.host.com"))
        val r = PolicyCompiler.compile(app, proposals, emptyList(), acceptProposals = true)
        assertTrue(r.policyJson.contains("bad.host.com"))
        assertTrue(r.unapprovedProposals.isEmpty())
    }
}
