package tech.ssemaj.poseidon.gradle.elf

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

    /** @return true if injected, false if already present. Throws on malformed/unsupported ELF. */
    fun inject(file: File, soname: String): Boolean {
        val bytes = file.readBytes()
        validateElf(bytes, file)
        val image = readHeaders(file, bytes)
        if (alreadyNeeded(image, soname)) return false
        val regionData = buildAppendedRegion(image, soname)
        patchHeaderAndSections(image, regionData)
        writeOut(file, image.b, regionData)
        return true
    }

    // ---- Phase 1: validate + parse ----

    private fun validateElf(b: ByteArray, file: File) {
        require(
            b.size > 64 && b[0] == 0x7f.toByte() && b[1] == 'E'.code.toByte() &&
                b[2] == 'L'.code.toByte() && b[3] == 'F'.code.toByte()
        ) { "not an ELF: ${file.name}" }
        require(b[5].toInt() == 1) { "big-endian ELF unsupported: ${file.name}" }
    }

    private fun readHeaders(file: File, bytes: ByteArray): ElfImage = ElfImage(file, bytes)

    // ---- Phase 2: idempotency check (part of readDynamic semantics) ----

    private fun alreadyNeeded(image: ElfImage, soname: String): Boolean =
        image.dyns.any { d -> d.tag == DT_NEEDED && image.cstr(image.oldStrtab, d.v.toInt()) == soname }

    // ---- Phase 3: build the appended region (phdr table + dynstr + .dynamic) ----

    private data class RegionData(
        val region: ByteArray,
        val regionOff: Long,
        val regionVaddr: Long,
        val newPhNum: Int,
        val offPhdr: Long,
        val offDyn: Long,
        val offDynstr: Long,
        val newDynSize: Long,
        val newStrtabSize: Int,
        val origStrtabVaddr: Long,
    )

    private fun buildAppendedRegion(image: ElfImage, soname: String): RegionData {
        val align = (image.loads.maxOf { it.align }.takeIf { it > 1 } ?: 0x1000L)
        fun up(x: Long, a: Long) = (x + a - 1) / a * a
        val regionOff   = up(image.b.size.toLong(), align)
        val maxVEnd     = image.loads.maxOf { it.vaddr + it.memsz }
        val regionVaddr = up(maxVEnd, align)

        val newPhNum     = image.phNum + 1
        val phTableSize  = newPhNum.toLong() * image.phEntSize
        val offPhdr      = 0L
        val offDynstr    = up(phTableSize, 8)
        val sonameBytes  = soname.toByteArray(Charsets.US_ASCII)
        val newStrtab    = image.oldStrtab + sonameBytes + byteArrayOf(0)
        val newStrOffset = image.oldStrtab.size.toLong()
        val offDyn       = up(offDynstr + newStrtab.size, 8)

        // new .dynamic: our DT_NEEDED first, old entries (sans DT_NULL, strtab updated), DT_NULL
        val newDyns = ArrayList<ElfImage.Dyn>()
        newDyns.add(ElfImage.Dyn(DT_NEEDED, newStrOffset))
        for (d in image.dyns) {
            if (d.tag == DT_NULL) continue
            when (d.tag) {
                DT_STRTAB -> newDyns.add(ElfImage.Dyn(DT_STRTAB, regionVaddr + offDynstr))
                DT_STRSZ  -> newDyns.add(ElfImage.Dyn(DT_STRSZ, newStrtab.size.toLong()))
                else       -> newDyns.add(ElfImage.Dyn(d.tag, d.v))
            }
        }
        newDyns.add(ElfImage.Dyn(DT_NULL, 0))
        val newDynSize  = newDyns.size.toLong() * image.dynEntSize
        val regionSize  = offDyn + newDynSize

        val region = ByteArray(regionSize.toInt())
        val rb     = ByteBuffer.wrap(region).order(ByteOrder.LITTLE_ENDIAN)

        // phdr table: copy originals (PT_PHDR/PT_DYNAMIC repointed), then new PT_LOAD
        val updatedPhs = image.phs.map { p ->
            when (p.type) {
                PT_PHDR    -> p.copy(
                    off = regionOff + offPhdr, vaddr = regionVaddr + offPhdr,
                    paddr = regionVaddr + offPhdr, filesz = phTableSize, memsz = phTableSize,
                )
                PT_DYNAMIC -> p.copy(
                    off = regionOff + offDyn, vaddr = regionVaddr + offDyn,
                    paddr = regionVaddr + offDyn, filesz = newDynSize, memsz = newDynSize,
                )
                else       -> p
            }
        }.toMutableList()
        updatedPhs.add(
            ElfImage.Ph(
                newPhNum - 1, PT_LOAD, PF_R.toLong(), regionOff, regionVaddr,
                regionVaddr, regionSize, regionSize, align,
            )
        )

        updatedPhs.forEachIndexed { i, p ->
            val o = (offPhdr + i.toLong() * image.phEntSize).toInt()
            if (image.is64) {
                rb.putInt(o, p.type); rb.putInt(o + 4, p.flags.toInt())
                rb.putLong(o + 8, p.off); rb.putLong(o + 16, p.vaddr); rb.putLong(o + 24, p.paddr)
                rb.putLong(o + 32, p.filesz); rb.putLong(o + 40, p.memsz); rb.putLong(o + 48, p.align)
            } else {
                rb.putInt(o, p.type); rb.putInt(o + 4, p.off.toInt()); rb.putInt(o + 8, p.vaddr.toInt())
                rb.putInt(o + 12, p.paddr.toInt()); rb.putInt(o + 16, p.filesz.toInt())
                rb.putInt(o + 20, p.memsz.toInt()); rb.putInt(o + 24, p.flags.toInt())
                rb.putInt(o + 28, p.align.toInt())
            }
        }

        // dynstr
        System.arraycopy(newStrtab, 0, region, offDynstr.toInt(), newStrtab.size)
        // dynamic
        newDyns.forEachIndexed { i, d ->
            val o = (offDyn + i.toLong() * image.dynEntSize).toInt()
            if (image.is64) { rb.putLong(o, d.tag); rb.putLong(o + 8, d.v) }
            else { rb.putInt(o, d.tag.toInt()); rb.putInt(o + 4, d.v.toInt()) }
        }

        return RegionData(
            region = region, regionOff = regionOff, regionVaddr = regionVaddr,
            newPhNum = newPhNum, offPhdr = offPhdr, offDyn = offDyn, offDynstr = offDynstr,
            newDynSize = newDynSize, newStrtabSize = newStrtab.size,
            origStrtabVaddr = image.strtabVaddr,
        )
    }

    // ---- Phase 4: patch ELF header + section headers in the in-memory buffer ----

    private fun patchHeaderAndSections(image: ElfImage, data: RegionData) {
        val bb   = image.bb
        val is64 = image.is64

        // Update e_phoff and e_phnum.
        if (is64) bb.putLong(32, data.regionOff + data.offPhdr)
        else       bb.putInt(28, (data.regionOff + data.offPhdr).toInt())
        bb.putShort(image.phnumOff, data.newPhNum.toShort())

        // Repoint .dynamic / .dynstr section headers so tooling agrees with the loader.
        if (image.eShoff != 0L && image.shNum > 0) {
            for (i in 0 until image.shNum) {
                val so     = (image.eShoff + i.toLong() * image.shEntSize).toInt()
                val shType = bb.getInt(so + 4)
                when (shType) {
                    SHT_DYNAMIC -> if (is64) {
                        bb.putLong(so + 16, data.regionVaddr + data.offDyn)
                        bb.putLong(so + 24, data.regionOff  + data.offDyn)
                        bb.putLong(so + 32, data.newDynSize)
                    } else {
                        bb.putInt(so + 12, (data.regionVaddr + data.offDyn).toInt())
                        bb.putInt(so + 16, (data.regionOff   + data.offDyn).toInt())
                        bb.putInt(so + 20, data.newDynSize.toInt())
                    }
                    SHT_STRTAB -> {
                        val shAddr = if (is64) bb.getLong(so + 16) else bb.getInt(so + 12).toLong() and 0xffffffffL
                        if (shAddr == data.origStrtabVaddr) {
                            if (is64) {
                                bb.putLong(so + 16, data.regionVaddr + data.offDynstr)
                                bb.putLong(so + 24, data.regionOff   + data.offDynstr)
                                bb.putLong(so + 32, data.newStrtabSize.toLong())
                            } else {
                                bb.putInt(so + 12, (data.regionVaddr + data.offDynstr).toInt())
                                bb.putInt(so + 16, (data.regionOff   + data.offDynstr).toInt())
                                bb.putInt(so + 20, data.newStrtabSize)
                            }
                        }
                    }
                }
            }
        }
    }

    // ---- Phase 5: assemble and write: original (padded to regionOff) + appended region ----

    private fun writeOut(file: File, b: ByteArray, data: RegionData) {
        file.outputStream().buffered().use { out ->
            out.write(b)
            repeat((data.regionOff - b.size).toInt()) { out.write(0) }
            out.write(data.region)
        }
    }
}
