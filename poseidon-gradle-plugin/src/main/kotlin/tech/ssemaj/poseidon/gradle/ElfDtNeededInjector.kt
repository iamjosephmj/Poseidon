package tech.ssemaj.poseidon.gradle

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Pure-JVM ELF DT_NEEDED injector (ELF32/64, little-endian — all Android ABIs).
 *
 * Adds a DT_NEEDED entry by appending ONE new PT_LOAD segment at end-of-file that
 * holds: a relocated program-header table (old phdrs + the new PT_LOAD, with
 * PT_PHDR/PT_DYNAMIC repointed), a copied+extended .dynstr (old bytes kept so every
 * existing offset stays valid, soname appended), and a relocated .dynamic (old
 * entries + our DT_NEEDED placed FIRST so the shim wins symbol resolution). The ELF
 * header's e_phoff/e_phnum are updated to the relocated phdr table. Section headers
 * for .dynamic/.dynstr are also repointed so tooling agrees with the loader.
 *
 * No external dependencies (replaces the LIEF/python interim).
 */
object ElfDtNeededInjector {
    private const val PT_LOAD = 1
    private const val PT_DYNAMIC = 2
    private const val PT_PHDR = 6
    private const val PF_R = 4
    private const val DT_NULL = 0L
    private const val DT_NEEDED = 1L
    private const val DT_STRTAB = 5L
    private const val DT_STRSZ = 10L
    private const val SHT_STRTAB = 3
    private const val SHT_DYNAMIC = 6

    /** @return true if injected, false if already present. Throws on malformed/unsupported ELF. */
    fun inject(file: File, soname: String): Boolean {
        val b = file.readBytes()
        require(b.size > 64 && b[0] == 0x7f.toByte() && b[1] == 'E'.code.toByte() &&
            b[2] == 'L'.code.toByte() && b[3] == 'F'.code.toByte()) { "not an ELF: ${file.name}" }
        val is64 = b[4].toInt() == 2
        require(b[5].toInt() == 1) { "big-endian ELF unsupported: ${file.name}" }
        val bb = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)

        // ---- ELF header fields ----
        val ePhoff = if (is64) bb.getLong(32) else bb.getInt(28).toLong() and 0xffffffffL
        val eShoff = if (is64) bb.getLong(40) else bb.getInt(32).toLong() and 0xffffffffL
        val phentOff = if (is64) 54 else 42
        val phnumOff = if (is64) 56 else 44
        val phEntSize = bb.getShort(phentOff).toInt() and 0xffff
        val phNum = bb.getShort(phnumOff).toInt() and 0xffff
        val shentOff = if (is64) 58 else 46
        val shnumOff = if (is64) 60 else 48
        val shEntSize = bb.getShort(shentOff).toInt() and 0xffff
        val shNum = bb.getShort(shnumOff).toInt() and 0xffff

        // ---- read program headers ----
        data class Ph(val idx: Int, var type: Int, var flags: Long, var off: Long, var vaddr: Long,
                      var paddr: Long, var filesz: Long, var memsz: Long, var align: Long)
        fun readPh(i: Int): Ph {
            val o = (ePhoff + i.toLong() * phEntSize).toInt()
            return if (is64) Ph(i, bb.getInt(o), bb.getInt(o + 4).toLong() and 0xffffffffL,
                bb.getLong(o + 8), bb.getLong(o + 16), bb.getLong(o + 24),
                bb.getLong(o + 32), bb.getLong(o + 40), bb.getLong(o + 48))
            else Ph(i, bb.getInt(o), bb.getInt(o + 24).toLong() and 0xffffffffL,
                bb.getInt(o + 4).toLong() and 0xffffffffL, bb.getInt(o + 8).toLong() and 0xffffffffL,
                bb.getInt(o + 12).toLong() and 0xffffffffL, bb.getInt(o + 16).toLong() and 0xffffffffL,
                bb.getInt(o + 20).toLong() and 0xffffffffL, bb.getInt(o + 28).toLong() and 0xffffffffL)
        }
        val phs = (0 until phNum).map { readPh(it) }
        val dynPh = phs.firstOrNull { it.type == PT_DYNAMIC } ?: error("no PT_DYNAMIC in ${file.name}")
        val loads = phs.filter { it.type == PT_LOAD }
        require(loads.isNotEmpty()) { "no PT_LOAD in ${file.name}" }

        fun vaddrToOff(vaddr: Long): Long {
            val seg = loads.first { vaddr >= it.vaddr && vaddr < it.vaddr + it.filesz }
            return vaddr - (seg.vaddr - seg.off)
        }

        // ---- read .dynamic entries ----
        val dynEntSize = if (is64) 16 else 8
        data class Dyn(var tag: Long, var v: Long)
        val dyns = ArrayList<Dyn>()
        run {
            var o = dynPh.off.toInt()
            val end = (dynPh.off + dynPh.filesz).toInt()
            while (o + dynEntSize <= end) {
                val tag = if (is64) bb.getLong(o) else (bb.getInt(o).toLong() and 0xffffffffL)
                val v = if (is64) bb.getLong(o + 8) else (bb.getInt(o + 4).toLong() and 0xffffffffL)
                dyns.add(Dyn(tag, v))
                if (tag == DT_NULL) break
                o += dynEntSize
            }
        }
        val strtabVaddr = dyns.first { it.tag == DT_STRTAB }.v
        val strsz = dyns.first { it.tag == DT_STRSZ }.v.toInt()
        val strOff = vaddrToOff(strtabVaddr).toInt()
        val oldStrtab = b.copyOfRange(strOff, strOff + strsz)

        // idempotent: already needed?
        val sonameBytes = soname.toByteArray(Charsets.US_ASCII)
        for (d in dyns) if (d.tag == DT_NEEDED) {
            val s = cstr(oldStrtab, d.v.toInt())
            if (s == soname) return false
        }

        // ---- compute appended region ----
        val align = (loads.maxOf { it.align }.takeIf { it > 1 } ?: 0x1000L)
        fun up(x: Long, a: Long) = (x + a - 1) / a * a
        val regionOff = up(b.size.toLong(), align)
        val maxVEnd = loads.maxOf { it.vaddr + it.memsz }
        val regionVaddr = up(maxVEnd, align)

        val newPhNum = phNum + 1
        val phTableSize = newPhNum.toLong() * phEntSize
        val offPhdr = 0L
        val offDynstr = up(phTableSize, 8)
        val newStrtab = oldStrtab + sonameBytes + byteArrayOf(0)
        val newStrOffset = oldStrtab.size.toLong() // offset of our soname within new strtab
        val offDyn = up(offDynstr + newStrtab.size, 8)

        // new .dynamic: our DT_NEEDED first, then old entries (sans DT_NULL, with strtab updated), then DT_NULL
        val newDyns = ArrayList<Dyn>()
        newDyns.add(Dyn(DT_NEEDED, newStrOffset))
        for (d in dyns) {
            if (d.tag == DT_NULL) continue
            when (d.tag) {
                DT_STRTAB -> newDyns.add(Dyn(DT_STRTAB, regionVaddr + offDynstr))
                DT_STRSZ -> newDyns.add(Dyn(DT_STRSZ, newStrtab.size.toLong()))
                else -> newDyns.add(Dyn(d.tag, d.v))
            }
        }
        newDyns.add(Dyn(DT_NULL, 0))
        val newDynSize = newDyns.size.toLong() * dynEntSize
        val regionSize = offDyn + newDynSize

        // ---- build region bytes ----
        val region = ByteArray(regionSize.toInt())
        val rb = ByteBuffer.wrap(region).order(ByteOrder.LITTLE_ENDIAN)
        // phdr table: copy originals (with PT_PHDR/PT_DYNAMIC updated), then append new PT_LOAD
        val updated = phs.map { p ->
            when (p.type) {
                PT_PHDR -> p.copy(off = regionOff + offPhdr, vaddr = regionVaddr + offPhdr,
                    paddr = regionVaddr + offPhdr, filesz = phTableSize, memsz = phTableSize)
                PT_DYNAMIC -> p.copy(off = regionOff + offDyn, vaddr = regionVaddr + offDyn,
                    paddr = regionVaddr + offDyn, filesz = newDynSize, memsz = newDynSize)
                else -> p
            }
        }.toMutableList()
        updated.add(Ph(newPhNum - 1, PT_LOAD, PF_R.toLong(), regionOff, regionVaddr,
            regionVaddr, regionSize, regionSize, align))
        updated.forEachIndexed { i, p ->
            val o = (offPhdr + i.toLong() * phEntSize).toInt()
            if (is64) {
                rb.putInt(o, p.type); rb.putInt(o + 4, p.flags.toInt())
                rb.putLong(o + 8, p.off); rb.putLong(o + 16, p.vaddr); rb.putLong(o + 24, p.paddr)
                rb.putLong(o + 32, p.filesz); rb.putLong(o + 40, p.memsz); rb.putLong(o + 48, p.align)
            } else {
                rb.putInt(o, p.type); rb.putInt(o + 4, p.off.toInt()); rb.putInt(o + 8, p.vaddr.toInt())
                rb.putInt(o + 12, p.paddr.toInt()); rb.putInt(o + 16, p.filesz.toInt())
                rb.putInt(o + 20, p.memsz.toInt()); rb.putInt(o + 24, p.flags.toInt()); rb.putInt(o + 28, p.align.toInt())
            }
        }
        // dynstr
        System.arraycopy(newStrtab, 0, region, offDynstr.toInt(), newStrtab.size)
        // dynamic
        newDyns.forEachIndexed { i, d ->
            val o = (offDyn + i.toLong() * dynEntSize).toInt()
            if (is64) { rb.putLong(o, d.tag); rb.putLong(o + 8, d.v) }
            else { rb.putInt(o, d.tag.toInt()); rb.putInt(o + 4, d.v.toInt()) }
        }

        // ---- update ELF header (e_phoff, e_phnum) ----
        if (is64) bb.putLong(32, regionOff + offPhdr) else bb.putInt(28, (regionOff + offPhdr).toInt())
        bb.putShort(phnumOff, newPhNum.toShort())

        // ---- repoint .dynamic / .dynstr section headers (tool consistency) ----
        if (eShoff != 0L && shNum > 0) {
            for (i in 0 until shNum) {
                val so = (eShoff + i.toLong() * shEntSize).toInt()
                val shType = bb.getInt(so + 4)
                if (shType == SHT_DYNAMIC) {
                    if (is64) { bb.putLong(so + 16, regionVaddr + offDyn); bb.putLong(so + 24, regionOff + offDyn); bb.putLong(so + 32, newDynSize) }
                    else { bb.putInt(so + 12, (regionVaddr + offDyn).toInt()); bb.putInt(so + 16, (regionOff + offDyn).toInt()); bb.putInt(so + 20, newDynSize.toInt()) }
                } else if (shType == SHT_STRTAB) {
                    val shAddr = if (is64) bb.getLong(so + 16) else bb.getInt(so + 12).toLong() and 0xffffffffL
                    if (shAddr == strtabVaddr) {
                        if (is64) { bb.putLong(so + 16, regionVaddr + offDynstr); bb.putLong(so + 24, regionOff + offDynstr); bb.putLong(so + 32, newStrtab.size.toLong()) }
                        else { bb.putInt(so + 12, (regionVaddr + offDynstr).toInt()); bb.putInt(so + 16, (regionOff + offDynstr).toInt()); bb.putInt(so + 20, newStrtab.size) }
                    }
                }
            }
        }

        // ---- assemble output: original (padded to regionOff) + region ----
        file.outputStream().buffered().use { out ->
            out.write(b)
            repeat((regionOff - b.size).toInt()) { out.write(0) }
            out.write(region)
        }
        return true
    }

    private fun cstr(buf: ByteArray, off: Int): String {
        var e = off
        while (e < buf.size && buf[e].toInt() != 0) e++
        return String(buf, off, e - off, Charsets.US_ASCII)
    }
}
