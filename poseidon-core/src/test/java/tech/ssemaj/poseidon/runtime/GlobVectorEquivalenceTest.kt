package tech.ssemaj.poseidon.runtime

import org.junit.Assert.assertEquals
import org.junit.Test

class GlobVectorEquivalenceTest {
    @Test fun jvmGlobMatchesVectors() {
        val vectors = javaClass.classLoader!!.getResourceAsStream("glob_vectors.txt")!!
            .bufferedReader().readLines().filter { it.isNotBlank() && !it.startsWith("#") }
        for (line in vectors) {
            val (pattern, value, expect) = line.split("|")
            val configured = Glob.matches(pattern, value)
            assertEquals("pattern=$pattern value=$value", expect == "1", configured)
        }
    }
}
