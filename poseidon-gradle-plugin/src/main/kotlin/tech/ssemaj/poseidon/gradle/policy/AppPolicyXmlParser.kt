package tech.ssemaj.poseidon.gradle.policy

import org.w3c.dom.Element
import org.w3c.dom.NodeList
import java.io.ByteArrayInputStream
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Parses the spec §7 <poseidon> XML for the app (authoritative) and libraries (proposals).
 * Also extracts inline Poseidon proposals from a merged AndroidManifest.
 */
object AppPolicyXmlParser {

    private fun parse(xml: String): Element {
        val doc = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = false }
            .newDocumentBuilder().parse(ByteArrayInputStream(xml.toByteArray()))
        return doc.documentElement
    }

    private fun NodeList.elements(): List<Element> =
        (0 until length).mapNotNull { item(it) as? Element }

    private fun Element.childElements(tag: String): List<Element> =
        childNodes.elements().filter { it.nodeName == tag }

    fun parseAppPolicy(xml: String): DeclaredPolicy {
        val root = parse(xml)
        return DeclaredPolicy(
            mode = root.getAttribute("mode").ifEmpty { MODE_MONITOR },
            allowedHosts = root.childElements("allow").map { it.getAttribute("host") },
            deniedPaths = root.childElements("deny-path").map { it.getAttribute("pattern") },
            dnsCorrelation = root.getAttribute("nativeDnsCorrelation") == "true",
            approvedLibraries = root.childElements("approve").map { it.getAttribute("library") }.toSet(),
            allowedCidrs = root.childElements("allow-cidr").map { it.getAttribute("value") },
        )
    }

    fun parseProposals(library: String, xml: String): List<Proposal> =
        parse(xml).childElements("allow").map { Proposal(library, it.getAttribute("host")) }

    /** Reads inline poseidon proposal meta-data from a merged AndroidManifest. */
    fun parseManifestProposals(manifestXml: String): List<Proposal> {
        val doc = DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(ByteArrayInputStream(manifestXml.toByteArray()))
        return doc.getElementsByTagName("meta-data").elements()
            .filter { it.getAttribute("android:name") == "tech.ssemaj.poseidon.proposes" }
            .flatMap { el ->
                val lib = el.getAttribute("tools:node").ifEmpty { "unknown" }
                el.getAttribute("android:value").split(",")
                    .map { it.trim() }
                    .filter { it.isNotEmpty() }
                    .map { Proposal(lib, it) }
            }
    }
}
