package tech.ssemaj.poseidon.gradle.elf

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

// ---------------------------------------------------------------------------
// ELF program-header type values (ELF spec §Figure 2-2 / p_type).
// ---------------------------------------------------------------------------
internal const val PT_LOAD    = 1  // Loadable segment.
internal const val PT_DYNAMIC = 2  // Dynamic linking information.
internal const val PT_PHDR    = 6  // Program-header table itself.

// ELF program-header flags (ELF spec §Figure 2-3 / p_flags bit-mask).
internal const val PF_R = 4  // Segment is readable.

// ---------------------------------------------------------------------------
// ELF dynamic-section tag values (ELF spec §Figure 2-9 / d_tag).
// ---------------------------------------------------------------------------
internal const val DT_NULL   = 0L   // Marks the end of the dynamic array.
internal const val DT_NEEDED = 1L   // Name offset of a required shared library.
internal const val DT_STRTAB = 5L   // Address of the string table.
internal const val DT_STRSZ  = 10L  // Size (bytes) of the string table.

// ELF section-header type values (ELF spec §Figure 1-19 / sh_type).
internal const val SHT_STRTAB  = 3  // Section holds a string table.
internal const val SHT_DYNAMIC = 6  // Section holds dynamic-linking info.

// ---------------------------------------------------------------------------
// ELF identification (e_ident) indices and canonical values
// (ELF spec §Figure 1-3).
// ---------------------------------------------------------------------------
internal object ElfIdent {
    /** Byte index 0: EI_MAG0 — always 0x7F (DEL character). */
    const val MAG0_OFF = 0;  const val MAG0 = 0x7f
    /** Byte indices 1–3: EI_MAG1/2/3 — ASCII 'E', 'L', 'F'. */
    const val MAG1_OFF = 1;  const val MAG1 = 'E'.code
    const val MAG2_OFF = 2;  const val MAG2 = 'L'.code
    const val MAG3_OFF = 3;  const val MAG3 = 'F'.code
    /** Byte index 4: EI_CLASS — 1 = ELFCLASS32, 2 = ELFCLASS64. */
    const val CLASS_OFF = 4; const val CLASS64 = 2
    /** Byte index 5: EI_DATA — 1 = ELFDATA2LSB (little-endian). */
    const val DATA_OFF  = 5; const val DATA_LSB = 1
    /** Minimum valid ELF file size in bytes (covers the full 64-byte ELF64 header). */
    const val MIN_SIZE  = 64
}

// ---------------------------------------------------------------------------
// ELF main-header field byte offsets, per ELF class
// (ELF spec §Figure 1-2 / Elf32_Ehdr / Elf64_Ehdr).
// ---------------------------------------------------------------------------
internal object ElfHeaderOff {
    /** e_phoff: byte offset of the program-header table within the file. */
    const val E_PHOFF_64 = 32;     const val E_PHOFF_32 = 28
    /** e_shoff: byte offset of the section-header table within the file. */
    const val E_SHOFF_64 = 40;     const val E_SHOFF_32 = 32
    /** e_phentsize: size in bytes of one program-header entry. */
    const val E_PHENTSIZE_64 = 54; const val E_PHENTSIZE_32 = 42
    /** e_phnum: number of entries in the program-header table. */
    const val E_PHNUM_64 = 56;     const val E_PHNUM_32 = 44
    /** e_shentsize: size in bytes of one section-header entry. */
    const val E_SHENTSIZE_64 = 58; const val E_SHENTSIZE_32 = 46
    /** e_shnum: number of entries in the section-header table. */
    const val E_SHNUM_64 = 60;     const val E_SHNUM_32 = 48
}

// ---------------------------------------------------------------------------
// Field byte offsets within Elf32_Phdr / Elf64_Phdr
// (ELF spec §Figure 2-2 / 2-3).
// Note: in ELF64 p_flags moves to offset 4 (before p_offset), whereas in
// ELF32 it lives at the end (offset 24).
// ---------------------------------------------------------------------------
internal object ElfPhdrOff {
    // Elf64_Phdr field offsets.
    const val TYPE_64   = 0;   const val FLAGS_64  =  4
    const val OFFSET_64 = 8;   const val VADDR_64  = 16
    const val PADDR_64  = 24;  const val FILESZ_64 = 32
    const val MEMSZ_64  = 40;  const val ALIGN_64  = 48
    // Elf32_Phdr field offsets.
    const val TYPE_32   = 0;   const val OFFSET_32 =  4
    const val VADDR_32  = 8;   const val PADDR_32  = 12
    const val FILESZ_32 = 16;  const val MEMSZ_32  = 20
    const val FLAGS_32  = 24;  const val ALIGN_32  = 28
}

// ---------------------------------------------------------------------------
// Field byte offsets within Elf32_Shdr / Elf64_Shdr
// (ELF spec §Figure 1-20 / 1-22).
// ---------------------------------------------------------------------------
internal object ElfShdrOff {
    /** sh_type: section type; offset is 4 in both ELF32 and ELF64. */
    const val SH_TYPE = 4
    /** sh_addr: virtual address at which the section appears in memory. */
    const val SH_ADDR_64 = 16;   const val SH_ADDR_32 = 12
    /** sh_offset: byte offset of the section from the start of the file. */
    const val SH_OFFSET_64 = 24; const val SH_OFFSET_32 = 16
    /** sh_size: section size in bytes in the file image. */
    const val SH_SIZE_64 = 32;   const val SH_SIZE_32 = 20
}

// ---------------------------------------------------------------------------
// Elf32_Dyn / Elf64_Dyn sizes and d_un field offset
// (ELF spec §Figure 2-9).
// ---------------------------------------------------------------------------
internal object ElfDynEnt {
    /** Total size of one dynamic entry: 16 bytes (Elf64_Dyn) or 8 bytes (Elf32_Dyn). */
    const val SIZE_64  = 16; const val SIZE_32 = 8
    /** Byte offset of d_un (the value/pointer union) within a dynamic entry. */
    const val D_VAL_64 = 8;  const val D_VAL_32 = 4
}

// ---------------------------------------------------------------------------
// Misc masks and alignment defaults.
// ---------------------------------------------------------------------------

/** Unsigned 16-bit mask: zero-extends a signed Short/Int to its unsigned 16-bit value. */
internal const val MASK_U16 = 0xffff
/** Unsigned 32-bit mask: zero-extends a signed Int to its unsigned 32-bit value as Long. */
internal const val MASK_U32 = 0xffffffffL
/** Default segment-alignment (page size = 4 096 bytes) used when no PT_LOAD has a larger value. */
internal const val DEFAULT_PAGE_ALIGN = 0x1000L

/** Reads a 32-bit field at [off] and zero-extends it to Long (unsigned). */
internal fun ByteBuffer.getULong(off: Int): Long = getInt(off).toLong() and MASK_U32

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
    val is64: Boolean  = b[ElfIdent.CLASS_OFF].toInt() == ElfIdent.CLASS64

    // Header field offsets (vary by ELF class).
    val phentOff: Int = if (is64) ElfHeaderOff.E_PHENTSIZE_64 else ElfHeaderOff.E_PHENTSIZE_32
    val phnumOff: Int = if (is64) ElfHeaderOff.E_PHNUM_64     else ElfHeaderOff.E_PHNUM_32
    val shentOff: Int = if (is64) ElfHeaderOff.E_SHENTSIZE_64 else ElfHeaderOff.E_SHENTSIZE_32
    val shnumOff: Int = if (is64) ElfHeaderOff.E_SHNUM_64     else ElfHeaderOff.E_SHNUM_32

    // Header values.
    val ePhoff:    Long = if (is64) bb.getLong(ElfHeaderOff.E_PHOFF_64) else bb.getULong(ElfHeaderOff.E_PHOFF_32)
    val eShoff:    Long = if (is64) bb.getLong(ElfHeaderOff.E_SHOFF_64) else bb.getULong(ElfHeaderOff.E_SHOFF_32)
    val phEntSize: Int  = bb.getShort(phentOff).toInt() and MASK_U16
    val phNum:     Int  = bb.getShort(phnumOff).toInt() and MASK_U16
    val shEntSize: Int  = bb.getShort(shentOff).toInt() and MASK_U16
    val shNum:     Int  = bb.getShort(shnumOff).toInt() and MASK_U16

    // Program headers.
    val phs:   List<Ph> = (0 until phNum).map { readPh(it) }
    val dynPh: Ph       = phs.firstOrNull { it.type == PT_DYNAMIC }
        ?: error("no PT_DYNAMIC in ${file.name}")
    val loads: List<Ph> = phs.filter { it.type == PT_LOAD }

    /** Reads an ELF-word at [off]: 64-bit signed on ELF64, 32-bit zero-extended on ELF32. */
    private fun readWord(off: Int): Long = if (is64) bb.getLong(off) else bb.getULong(off)

    // Dynamic section.
    val dynEntSize: Int = if (is64) ElfDynEnt.SIZE_64 else ElfDynEnt.SIZE_32
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
        val dValOff = if (is64) ElfDynEnt.D_VAL_64 else ElfDynEnt.D_VAL_32
        while (o + dynEntSize <= end) {
            val tag = readWord(o)
            val v   = readWord(o + dValOff)
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
            i,
            bb.getInt(o + ElfPhdrOff.TYPE_64),
            bb.getULong(o + ElfPhdrOff.FLAGS_64),
            bb.getLong(o + ElfPhdrOff.OFFSET_64),
            bb.getLong(o + ElfPhdrOff.VADDR_64),
            bb.getLong(o + ElfPhdrOff.PADDR_64),
            bb.getLong(o + ElfPhdrOff.FILESZ_64),
            bb.getLong(o + ElfPhdrOff.MEMSZ_64),
            bb.getLong(o + ElfPhdrOff.ALIGN_64),
        ) else Ph(
            i,
            bb.getInt(o + ElfPhdrOff.TYPE_32),
            bb.getULong(o + ElfPhdrOff.FLAGS_32),
            bb.getULong(o + ElfPhdrOff.OFFSET_32),
            bb.getULong(o + ElfPhdrOff.VADDR_32),
            bb.getULong(o + ElfPhdrOff.PADDR_32),
            bb.getULong(o + ElfPhdrOff.FILESZ_32),
            bb.getULong(o + ElfPhdrOff.MEMSZ_32),
            bb.getULong(o + ElfPhdrOff.ALIGN_32),
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
