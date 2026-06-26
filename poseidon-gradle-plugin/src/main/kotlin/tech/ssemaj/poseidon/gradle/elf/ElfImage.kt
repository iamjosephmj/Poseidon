package tech.ssemaj.poseidon.gradle.elf

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

// ELF constants shared across the injector phases.
internal const val PT_LOAD     = 1
internal const val PT_DYNAMIC  = 2
internal const val PT_PHDR     = 6
internal const val PF_R        = 4
internal const val DT_NULL     = 0L
internal const val DT_NEEDED   = 1L
internal const val DT_STRTAB   = 5L
internal const val DT_STRSZ    = 10L
internal const val SHT_STRTAB  = 3
internal const val SHT_DYNAMIC = 6

/** Reads a 32-bit field at [off] and zero-extends it to Long (unsigned). */
internal fun ByteBuffer.getULong(off: Int): Long = getInt(off).toLong() and 0xffffffffL

/**
 * Parses and holds the structural view of an ELF32/64 little-endian file needed for
 * DT_NEEDED injection. Exposes geometry helpers used by the named injection phases.
 */
internal class ElfImage(val file: File, val b: ByteArray) {

    data class Ph(
        val idx: Int, var type: Int, var flags: Long, var off: Long, var vaddr: Long,
        var paddr: Long, var filesz: Long, var memsz: Long, var align: Long,
    )

    data class Dyn(var tag: Long, var v: Long)

    val bb: ByteBuffer = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
    val is64: Boolean  = b[4].toInt() == 2

    // Header field offsets (vary by ELF class).
    val phentOff: Int = if (is64) 54 else 42
    val phnumOff: Int = if (is64) 56 else 44
    val shentOff: Int = if (is64) 58 else 46
    val shnumOff: Int = if (is64) 60 else 48

    // Header values.
    val ePhoff:    Long = if (is64) bb.getLong(32) else bb.getULong(28)
    val eShoff:    Long = if (is64) bb.getLong(40) else bb.getULong(32)
    val phEntSize: Int  = bb.getShort(phentOff).toInt() and 0xffff
    val phNum:     Int  = bb.getShort(phnumOff).toInt() and 0xffff
    val shEntSize: Int  = bb.getShort(shentOff).toInt() and 0xffff
    val shNum:     Int  = bb.getShort(shnumOff).toInt() and 0xffff

    // Program headers.
    val phs:   List<Ph> = (0 until phNum).map { readPh(it) }
    val dynPh: Ph       = phs.firstOrNull { it.type == PT_DYNAMIC }
        ?: error("no PT_DYNAMIC in ${file.name}")
    val loads: List<Ph> = phs.filter { it.type == PT_LOAD }

    /** Reads an ELF-word at [off]: 64-bit signed on ELF64, 32-bit zero-extended on ELF32. */
    private fun readWord(off: Int): Long = if (is64) bb.getLong(off) else bb.getULong(off)

    // Dynamic section.
    val dynEntSize: Int = if (is64) 16 else 8
    val dyns: List<Dyn>
    val strtabVaddr: Long
    val strsz:  Int
    val strOff: Int
    val oldStrtab: ByteArray

    init {
        require(loads.isNotEmpty()) { "no PT_LOAD in ${file.name}" }

        val dynList = ArrayList<Dyn>()
        var o   = dynPh.off.toInt()
        val end = (dynPh.off + dynPh.filesz).toInt()
        while (o + dynEntSize <= end) {
            val tag = readWord(o)
            val v   = readWord(o + if (is64) 8 else 4)
            dynList.add(Dyn(tag, v))
            if (tag == DT_NULL) break
            o += dynEntSize
        }
        dyns        = dynList
        strtabVaddr = dyns.first { it.tag == DT_STRTAB }.v
        strsz       = dyns.first { it.tag == DT_STRSZ }.v.toInt()
        strOff      = vaddrToOff(strtabVaddr).toInt()
        oldStrtab   = b.copyOfRange(strOff, strOff + strsz)
    }

    fun readPh(i: Int): Ph {
        val o = (ePhoff + i.toLong() * phEntSize).toInt()
        return if (is64) Ph(
            i, bb.getInt(o), bb.getULong(o + 4),
            bb.getLong(o + 8), bb.getLong(o + 16), bb.getLong(o + 24),
            bb.getLong(o + 32), bb.getLong(o + 40), bb.getLong(o + 48),
        ) else Ph(
            i, bb.getInt(o), bb.getULong(o + 24),
            bb.getULong(o + 4), bb.getULong(o + 8),
            bb.getULong(o + 12), bb.getULong(o + 16),
            bb.getULong(o + 20), bb.getULong(o + 28),
        )
    }

    fun vaddrToOff(vaddr: Long): Long {
        val seg = loads.first { vaddr >= it.vaddr && vaddr < it.vaddr + it.filesz }
        return vaddr - (seg.vaddr - seg.off)
    }

    fun cstr(buf: ByteArray, off: Int): String {
        val end = (off until buf.size).firstOrNull { buf[it].toInt() == 0 } ?: buf.size
        return String(buf, off, end - off, Charsets.US_ASCII)
    }
}
