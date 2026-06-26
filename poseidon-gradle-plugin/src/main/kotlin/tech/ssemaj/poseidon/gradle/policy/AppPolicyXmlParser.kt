package tech.ssemaj.poseidon.gradle.policy

import org.w3c.dom.Element
import org.w3c.dom.NodeList
import java.io.ByteArrayInputStream
import javax.xml.parsers.DocumentBuilderFactory

// ---------------------------------------------------------------------------
// XML element names in the <poseidon> policy document (spec §7).
// ---------------------------------------------------------------------------
/** Element that grants access to a host. */
private const val XML_ELEM_ALLOW      = "allow"
/** Element that blocks requests whose path matches a pattern. */
private const val XML_ELEM_DENY_PATH  = "deny-path"
/** Element that permits connections to a CIDR range. */
private const val XML_ELEM_ALLOW_CIDR = "allow-cidr"
/** Element that approves a library's network proposals. */
private const val XML_ELEM_APPROVE    = "approve"

// ---------------------------------------------------------------------------
// XML attribute names in the <poseidon> policy document.
// ---------------------------------------------------------------------------
/** Attribute carrying the host name on an <allow> element. */
private const val XML_ATTR_HOST             = "host"
/** Attribute carrying the path-match pattern on a <deny-path> element. */
private const val XML_ATTR_PATTERN          = "pattern"
/** Attribute carrying the CIDR string on an <allow-cidr> element. */
private const val XML_ATTR_VALUE            = "value"
/** Root attribute selecting the enforcement mode (monitor/enforce). */
private const val XML_ATTR_MODE             = "mode"
/** Attribute carrying the library identifier on an <approve> element. */
private const val XML_ATTR_LIBRARY          = "library"
/** Root attribute enabling native-DNS correlation enforcement. */
private const val XML_ATTR_DNS_CORRELATION  = "nativeDnsCorrelation"

// ---------------------------------------------------------------------------
// AndroidManifest meta-data element name, attributes, and value constants
// used for inline library host proposals.
// ---------------------------------------------------------------------------
/** AndroidManifest element name for application metadata entries. */
private const val MANIFEST_ELEM_META_DATA      = "meta-data"
/** Standard Android namespace attribute that identifies a meta-data entry. */
private const val MANIFEST_ATTR_ANDROID_NAME   = "android:name"
/** Standard Android namespace attribute that holds a meta-data value. */
private const val MANIFEST_ATTR_ANDROID_VALUE  = "android:value"
/** Manifest merger attribute recording the library that contributed this node. */
private const val MANIFEST_ATTR_TOOLS_NODE     = "tools:node"
/** The android:name value used by libraries to declare network host proposals. */
private const val META_PROPOSES                = "tech.ssemaj.poseidon.proposes"
/** Fallback library identifier when the tools:node attribute is absent from a proposal. */
private const val UNKNOWN_LIBRARY              = "unknown"

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
            mode = root.getAttribute(XML_ATTR_MODE).ifEmpty { MODE_MONITOR },
            allowedHosts = root.childElements(XML_ELEM_ALLOW).map { it.getAttribute(XML_ATTR_HOST) },
            deniedPaths = root.childElements(XML_ELEM_DENY_PATH).map { it.getAttribute(XML_ATTR_PATTERN) },
            dnsCorrelation = root.getAttribute(XML_ATTR_DNS_CORRELATION) == "true",
            approvedLibraries = root.childElements(XML_ELEM_APPROVE).map { it.getAttribute(XML_ATTR_LIBRARY) }.toSet(),
            allowedCidrs = root.childElements(XML_ELEM_ALLOW_CIDR).map { it.getAttribute(XML_ATTR_VALUE) },
        )
    }

    fun parseProposals(library: String, xml: String): List<Proposal> =
        parse(xml).childElements(XML_ELEM_ALLOW).map { Proposal(library, it.getAttribute(XML_ATTR_HOST)) }

    /** Reads inline poseidon proposal meta-data from a merged AndroidManifest. */
    fun parseManifestProposals(manifestXml: String): List<Proposal> {
        val doc = DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(ByteArrayInputStream(manifestXml.toByteArray()))
        return doc.getElementsByTagName(MANIFEST_ELEM_META_DATA).elements()
            .filter { it.getAttribute(MANIFEST_ATTR_ANDROID_NAME) == META_PROPOSES }
            .flatMap { el ->
                val lib = el.getAttribute(MANIFEST_ATTR_TOOLS_NODE).ifEmpty { UNKNOWN_LIBRARY }
                el.getAttribute(MANIFEST_ATTR_ANDROID_VALUE).split(",")
                    .map { it.trim() }
                    .filter { it.isNotEmpty() }
                    .map { Proposal(lib, it) }
            }
    }
}
