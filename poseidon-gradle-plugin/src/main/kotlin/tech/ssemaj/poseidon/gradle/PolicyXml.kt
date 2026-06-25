package tech.ssemaj.poseidon.gradle

import org.w3c.dom.Element
import java.io.ByteArrayInputStream
import javax.xml.parsers.DocumentBuilderFactory

data class Proposal(val library: String, val host: String)

data class CompiledPolicy(
    val mode: String,
    val allowedHosts: List<String>,
    val deniedPaths: List<String>,
    val dnsCorrelation: Boolean,
    val approvedLibraries: Set<String>,
)

/** Parses the spec §7 <poseidon> XML for the app (authoritative) and libraries (proposals). */
object PolicyXml {
    private fun parse(xml: String): Element {
        val doc = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = false }
            .newDocumentBuilder().parse(ByteArrayInputStream(xml.toByteArray()))
        return doc.documentElement
    }

    private fun Element.childElements(tag: String): List<Element> {
        val result = mutableListOf<Element>()
        for (i in 0 until childNodes.length) {
            val node = childNodes.item(i)
            if (node is Element && node.nodeName == tag) result.add(node)
        }
        return result
    }

    fun parseAppPolicy(xml: String): CompiledPolicy {
        val root = parse(xml)
        return CompiledPolicy(
            mode = root.getAttribute("mode").ifEmpty { "monitor" },
            allowedHosts = root.childElements("allow").map { it.getAttribute("host") },
            deniedPaths = root.childElements("deny-path").map { it.getAttribute("pattern") },
            dnsCorrelation = root.getAttribute("nativeDnsCorrelation") == "true",
            approvedLibraries = root.childElements("approve").map { it.getAttribute("library") }.toSet(),
        )
    }

    fun parseProposals(library: String, xml: String): List<Proposal> =
        parse(xml).childElements("allow").map { Proposal(library, it.getAttribute("host")) }
}
