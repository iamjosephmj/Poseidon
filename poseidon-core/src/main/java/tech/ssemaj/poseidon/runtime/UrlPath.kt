package tech.ssemaj.poseidon.runtime

/** Normalizes a URL path: null or empty string → "/". */
internal fun normalizePath(path: String?): String = path?.ifEmpty { "/" } ?: "/"
